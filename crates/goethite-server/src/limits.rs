//! Per-client limits: query rate limiting and TCP connection counts.
//!
//! Rate limiting keeps goethite from being used to flood a third party with
//! answers to queries sent from a spoofed source address, and keeps one
//! client from using up the resolver. One limiter counts a client's queries
//! over UDP, TCP, DNS over TLS, HTTPS and QUIC together. Oblivious DoH is
//! not limited: its peer is a proxy relaying many clients, which the
//! connection limits bound instead.
//!
//! Clients are grouped into networks (by default each IPv4 address and each
//! IPv6 /64) and every network gets a token bucket, implemented as GCRA: one
//! timestamp per network, no timers. The table of networks is bounded; when
//! it is full, networks that are not tracked share one bucket.

use std::collections::HashMap;
use std::fmt;
use std::hash::{BuildHasher, RandomState};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use goethite_resolver::Cidr;

/// Number of independently locked parts of the rate limiter table.
const SHARDS: usize = 16;

/// The most client networks the rate limiter tracks, whatever the setting.
pub const MAX_RATE_LIMITED_CLIENTS: usize = 1_000_000;

/// The most networks [`RateLimitConfig::exempt`] may list.
pub const MAX_RATE_LIMIT_EXEMPTIONS: usize = 256;

/// How often a full shard may be swept for networks that are back to a full
/// bucket, so a flood of new sources cannot make every query scan the table.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Rate limiting settings, for queries over every transport but Oblivious
/// DoH.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateLimitConfig {
    /// Queries per second one client network may send on average; 0 turns
    /// rate limiting off.
    pub queries_per_second: u32,
    /// Queries a client network may send at once after being quiet.
    pub burst: u32,
    /// Every `slip`-th limited query gets an empty, truncated answer instead
    /// of none, so a real client retries over TCP while a spoofed victim
    /// receives nothing bigger than the query. 0 drops every limited query.
    pub slip: u32,
    /// IPv4 clients sharing this many leading address bits share a limit.
    pub ipv4_prefix: u8,
    /// IPv6 clients sharing this many leading address bits share a limit.
    pub ipv6_prefix: u8,
    /// How many client networks are tracked; capped at
    /// [`MAX_RATE_LIMITED_CLIENTS`].
    pub max_clients: usize,
    /// Never limit loopback clients. Their addresses cannot be spoofed from
    /// the network, and they are often a local stub resolver serving every
    /// program on the host.
    pub exempt_loopback: bool,
    /// Networks never limited, such as the local network behind a router
    /// that forwards every household's queries; at most
    /// [`MAX_RATE_LIMIT_EXEMPTIONS`] are used.
    pub exempt: Vec<Cidr>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            queries_per_second: 300,
            burst: 1000,
            slip: 2,
            ipv4_prefix: 32,
            ipv6_prefix: 64,
            max_clients: 65_536,
            exempt_loopback: true,
            exempt: Vec::new(),
        }
    }
}

/// A client network: an address with all but its leading bits cleared.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Network {
    V4(u32),
    V6(u128),
}

impl Network {
    /// The network of `ip` with `ipv4_bits` or `ipv6_bits` leading bits.
    /// IPv4 addresses mapped into IPv6 count as IPv4.
    pub(crate) fn of(ip: IpAddr, ipv4_bits: u8, ipv6_bits: u8) -> Self {
        let v4 = |ip: Ipv4Addr| Self::V4(u32::from(ip) & mask32(ipv4_bits));
        match ip {
            IpAddr::V4(ip) => v4(ip),
            IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
                Some(mapped) => v4(mapped),
                None => Self::V6(u128::from(ip) & mask128(ipv6_bits)),
            },
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::V4(bits) => Ipv4Addr::from(bits).fmt(f),
            Self::V6(bits) => Ipv6Addr::from(bits).fmt(f),
        }
    }
}

fn mask32(bits: u8) -> u32 {
    u32::MAX
        .checked_shl(32_u32.saturating_sub(u32::from(bits)))
        .unwrap_or(0)
}

fn mask128(bits: u8) -> u128 {
    u128::MAX
        .checked_shl(128_u32.saturating_sub(u32::from(bits)))
        .unwrap_or(0)
}

/// What to do with a query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Decision {
    /// Answer it.
    Allow,
    /// Over the limit: send a truncated answer if `slip`, nothing otherwise.
    /// `first` is set on the network's first limited query, for logging.
    Limited { slip: bool, first: bool },
}

/// A GCRA bucket: the theoretical arrival time of the next query.
#[derive(Clone, Copy, Debug)]
struct Bucket {
    next: Instant,
    limited: u32,
}

impl Bucket {
    fn new(now: Instant) -> Self {
        Self {
            next: now,
            limited: 0,
        }
    }

    fn take(&mut self, now: Instant, limiter: &RateLimiter) -> Decision {
        let next = self.next.max(now);
        if next.saturating_duration_since(now) > limiter.tolerance {
            self.limited = self.limited.wrapping_add(1);
            Decision::Limited {
                slip: self.limited.checked_rem(limiter.slip) == Some(0),
                first: self.limited == 1,
            }
        } else {
            self.next = next.checked_add(limiter.interval).unwrap_or(next);
            Decision::Allow
        }
    }
}

#[derive(Debug, Default)]
struct Shard {
    clients: HashMap<Network, Bucket>,
    /// Shared by every network not tracked because the table is full.
    overflow: Option<Bucket>,
    last_sweep: Option<Instant>,
}

impl Shard {
    /// Forgets networks whose bucket is full again: for them, a fresh bucket
    /// is the same.
    fn sweep(&mut self, now: Instant) {
        if self
            .last_sweep
            .is_some_and(|last| now.saturating_duration_since(last) < SWEEP_INTERVAL)
        {
            return;
        }
        self.last_sweep = Some(now);
        self.clients.retain(|_, bucket| bucket.next > now);
    }
}

/// Limits the rate of queries per client network.
#[derive(Debug)]
pub(crate) struct RateLimiter {
    interval: Duration,
    tolerance: Duration,
    slip: u32,
    ipv4_prefix: u8,
    ipv6_prefix: u8,
    exempt_loopback: bool,
    exempt: Vec<Cidr>,
    per_shard: usize,
    shards: Box<[Mutex<Shard>]>,
    hasher: RandomState,
}

impl RateLimiter {
    /// A limiter for `config`, or `None` if rate limiting is off.
    pub(crate) fn new(config: &RateLimitConfig) -> Option<Self> {
        let interval = Duration::from_secs(1).checked_div(config.queries_per_second)?;
        let max_clients = config.max_clients.clamp(SHARDS, MAX_RATE_LIMITED_CLIENTS);
        Some(Self {
            interval,
            // `burst` queries fit: the first one at a full bucket, then
            // `burst - 1` more within the tolerance.
            tolerance: interval.saturating_mul(config.burst.saturating_sub(1)),
            slip: config.slip,
            ipv4_prefix: config.ipv4_prefix,
            ipv6_prefix: config.ipv6_prefix,
            exempt_loopback: config.exempt_loopback,
            exempt: config
                .exempt
                .iter()
                .take(MAX_RATE_LIMIT_EXEMPTIONS)
                .copied()
                .collect(),
            per_shard: max_clients.div_ceil(SHARDS),
            shards: (0..SHARDS).map(|_| Mutex::default()).collect(),
            hasher: RandomState::new(),
        })
    }

    /// Accounts for a query from `ip` arriving at `now`.
    pub(crate) fn check(&self, ip: IpAddr, now: Instant) -> (Decision, Network) {
        let network = Network::of(ip, self.ipv4_prefix, self.ipv6_prefix);
        if (self.exempt_loopback && is_loopback(ip))
            || self.exempt.iter().any(|exempt| exempt.contains(ip))
        {
            return (Decision::Allow, network);
        }
        let index = usize::try_from(self.hasher.hash_one(network))
            .unwrap_or_default()
            .checked_rem(SHARDS)
            .unwrap_or_default();
        let Some(shard) = self.shards.get(index) else {
            return (Decision::Allow, network);
        };
        let mut shard = shard.lock().unwrap_or_else(PoisonError::into_inner);
        if !shard.clients.contains_key(&network) && shard.clients.len() >= self.per_shard {
            shard.sweep(now);
        }
        let tracked = shard.clients.len() < self.per_shard || shard.clients.contains_key(&network);
        let bucket = if tracked {
            shard
                .clients
                .entry(network)
                .or_insert_with(|| Bucket::new(now))
        } else {
            shard.overflow.get_or_insert_with(|| Bucket::new(now))
        };
        (bucket.take(now, self), network)
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| shard.lock().map_or(0, |shard| shard.clients.len()))
            .sum()
    }
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => {
            ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// Counts open TCP connections per client (each IPv4 address, each IPv6
/// /64), so one host cannot take every connection slot.
#[derive(Debug)]
pub(crate) struct ClientConnections {
    max_per_client: usize,
    counts: Mutex<HashMap<Network, usize>>,
}

impl ClientConnections {
    pub(crate) fn new(max_per_client: usize) -> Arc<Self> {
        Arc::new(Self {
            max_per_client,
            counts: Mutex::default(),
        })
    }

    /// Takes a connection slot for `ip`, or `None` if it has too many open.
    /// The table only holds clients with open connections, so it is bounded
    /// by the total connection limit.
    pub(crate) fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<ClientSlot> {
        let network = Network::of(ip, 32, 64);
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let count = counts.get(&network).copied().unwrap_or(0);
        if count >= self.max_per_client {
            return None;
        }
        counts.insert(network, count.saturating_add(1));
        Some(ClientSlot {
            owner: Arc::clone(self),
            network,
        })
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.counts.lock().map_or(0, |counts| counts.len())
    }
}

/// An open connection's share of its client's limit, released on drop.
#[derive(Debug)]
pub(crate) struct ClientSlot {
    owner: Arc<ClientConnections>,
    network: Network,
}

impl Drop for ClientSlot {
    fn drop(&mut self) {
        let mut counts = self
            .owner
            .counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = counts.get_mut(&self.network) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.network);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, reason = "test arithmetic")]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn limiter(queries_per_second: u32, burst: u32, slip: u32) -> RateLimiter {
        RateLimiter::new(&RateLimitConfig {
            queries_per_second,
            burst,
            slip,
            ..RateLimitConfig::default()
        })
        .unwrap()
    }

    #[test]
    fn networks() {
        assert_eq!(
            Network::of(ip("192.0.2.77"), 24, 64),
            Network::of(ip("192.0.2.1"), 24, 64)
        );
        assert_ne!(
            Network::of(ip("192.0.2.77"), 32, 64),
            Network::of(ip("192.0.2.1"), 32, 64)
        );
        assert_eq!(
            Network::of(ip("2001:db8:1:2:aaaa::1"), 32, 64),
            Network::of(ip("2001:db8:1:2:bbbb::2"), 32, 64)
        );
        assert_ne!(
            Network::of(ip("2001:db8:1:2::1"), 32, 64),
            Network::of(ip("2001:db8:1:3::1"), 32, 64)
        );
        assert_eq!(
            Network::of(ip("::ffff:192.0.2.1"), 32, 64),
            Network::of(ip("192.0.2.1"), 32, 64)
        );
        assert_eq!(Network::of(ip("192.0.2.1"), 0, 0).to_string(), "0.0.0.0");
        assert_eq!(
            Network::of(ip("192.0.2.1"), 200, 0).to_string(),
            "192.0.2.1"
        );
        assert_eq!(
            Network::of(ip("2001:db8::1"), 0, 32).to_string(),
            "2001:db8::"
        );
    }

    #[test]
    fn off_when_the_rate_is_zero() {
        assert!(
            RateLimiter::new(&RateLimitConfig {
                queries_per_second: 0,
                ..RateLimitConfig::default()
            })
            .is_none()
        );
    }

    #[test]
    fn allows_a_burst_then_the_rate() {
        let limiter = limiter(10, 5, 0);
        let client = ip("192.0.2.1");
        let now = Instant::now();
        for _ in 0..5 {
            assert_eq!(limiter.check(client, now).0, Decision::Allow);
        }
        assert_eq!(
            limiter.check(client, now).0,
            Decision::Limited {
                slip: false,
                first: true
            }
        );
        // Another client is not affected.
        assert_eq!(limiter.check(ip("192.0.2.2"), now).0, Decision::Allow);
        // One token comes back every 100 ms.
        let later = now + Duration::from_millis(100);
        assert_eq!(limiter.check(client, later).0, Decision::Allow);
        assert!(matches!(
            limiter.check(client, later).0,
            Decision::Limited { first: false, .. }
        ));
        // After a quiet second the whole burst is available again.
        let much_later = later + Duration::from_secs(1);
        for _ in 0..5 {
            assert_eq!(limiter.check(client, much_later).0, Decision::Allow);
        }
    }

    #[test]
    fn slips_every_nth_limited_query() {
        let limiter = limiter(1, 1, 2);
        let client = ip("2001:db8::1");
        let now = Instant::now();
        assert_eq!(limiter.check(client, now).0, Decision::Allow);
        let slips: Vec<bool> = (0..6)
            .map(|_| match limiter.check(client, now).0 {
                Decision::Limited { slip, .. } => slip,
                Decision::Allow => panic!("allowed"),
            })
            .collect();
        assert_eq!(slips, [false, true, false, true, false, true]);
    }

    #[test]
    fn loopback_is_exempt_unless_configured() {
        let limiter = limiter(1, 1, 0);
        let now = Instant::now();
        for _ in 0..10 {
            assert_eq!(limiter.check(ip("127.0.0.1"), now).0, Decision::Allow);
            assert_eq!(limiter.check(ip("::1"), now).0, Decision::Allow);
        }
        let strict = RateLimiter::new(&RateLimitConfig {
            queries_per_second: 1,
            burst: 1,
            exempt_loopback: false,
            ..RateLimitConfig::default()
        })
        .unwrap();
        assert_eq!(strict.check(ip("127.0.0.1"), now).0, Decision::Allow);
        assert!(matches!(
            strict.check(ip("127.0.0.1"), now).0,
            Decision::Limited { .. }
        ));
    }

    #[test]
    fn exempt_networks_are_never_limited() {
        let limiter = RateLimiter::new(&RateLimitConfig {
            queries_per_second: 1,
            burst: 1,
            exempt: vec![
                "192.168.0.0/16".parse().unwrap(),
                "2001:db8::/32".parse().unwrap(),
            ],
            ..RateLimitConfig::default()
        })
        .unwrap();
        let now = Instant::now();
        for _ in 0..10 {
            for exempt in ["192.168.7.8", "::ffff:192.168.7.8", "2001:db8::53"] {
                assert_eq!(
                    limiter.check(ip(exempt), now).0,
                    Decision::Allow,
                    "{exempt}"
                );
            }
        }
        assert_eq!(limiter.check(ip("10.0.0.1"), now).0, Decision::Allow);
        assert!(matches!(
            limiter.check(ip("10.0.0.1"), now).0,
            Decision::Limited { .. }
        ));
    }

    #[test]
    fn the_table_is_bounded() {
        let limiter = RateLimiter::new(&RateLimitConfig {
            queries_per_second: 1,
            burst: 1,
            slip: 0,
            max_clients: 64,
            ..RateLimitConfig::default()
        })
        .unwrap();
        let now = Instant::now();
        for i in 0..10_000_u32 {
            limiter.check(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i)), now);
        }
        assert!(limiter.tracked() <= 64, "{}", limiter.tracked());
        // Untracked networks share a bucket, which is now empty.
        let newcomer = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        assert!(matches!(
            limiter.check(newcomer, now).0,
            Decision::Limited { .. }
        ));
        // Once buckets refill, a sweep makes room again.
        let later = now + Duration::from_secs(5);
        assert_eq!(limiter.check(newcomer, later).0, Decision::Allow);
        assert!(limiter.tracked() <= 64);
    }

    #[test]
    fn connection_slots_per_client() {
        let connections = ClientConnections::new(2);
        let a = connections.try_acquire(ip("192.0.2.1")).unwrap();
        let b = connections.try_acquire(ip("::ffff:192.0.2.1")).unwrap();
        assert!(connections.try_acquire(ip("192.0.2.1")).is_none());
        let other = connections.try_acquire(ip("192.0.2.2")).unwrap();
        // The same IPv6 /64 is one client.
        let v6 = connections.try_acquire(ip("2001:db8::1")).unwrap();
        let v6_too = connections.try_acquire(ip("2001:db8::2")).unwrap();
        assert!(connections.try_acquire(ip("2001:db8::3")).is_none());
        drop(a);
        let again = connections.try_acquire(ip("192.0.2.1")).unwrap();
        drop((b, again, other, v6, v6_too));
        assert_eq!(connections.tracked(), 0);
    }
}
