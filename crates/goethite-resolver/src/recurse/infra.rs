//! What a recursive resolver learns about the DNS's infrastructure: zone
//! cuts and their name servers, the servers' addresses, and how each server
//! is doing. Every table is bounded and evicts its oldest entries; locks
//! are held only for map operations, never across an `.await`.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use goethite_proto::Name;
use tokio::time::Instant;

/// The shortest time infrastructure records are kept, so a zone with tiny
/// TTLs does not cost a referral chain for every query.
const MIN_TTL: u32 = 30;
/// The longest.
const MAX_TTL: u32 = 86_400;

/// A server's round-trip time until one is measured.
const UNKNOWN_RTT: Duration = Duration::from_millis(300);
/// The longest an attempt may wait for one server.
const MAX_ATTEMPT: Duration = Duration::from_millis(2_000);
/// The shortest.
const MIN_ATTEMPT: Duration = Duration::from_millis(250);
/// Failures in a row before a server is tried last for a while.
const FAILURES_BEFORE_DOWN: u32 = 3;
/// How long.
const DOWN_FOR: Duration = Duration::from_secs(60);

/// The time to keep something with `ttl`.
fn keep_for(ttl: u32) -> Duration {
    Duration::from_secs(u64::from(ttl.clamp(MIN_TTL, MAX_TTL)))
}

/// A map of at most `capacity` entries that forgets the oldest first.
struct Bounded<K, V> {
    map: HashMap<K, (V, u64)>,
    order: VecDeque<(K, u64)>,
    next: u64,
    capacity: usize,
}

impl<K: Clone + Eq + Hash, V> Bounded<K, V> {
    fn new(capacity: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            next: 0,
            capacity: capacity.max(1),
        }
    }

    fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key).map(|(value, _)| value)
    }

    fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.map.get_mut(key).map(|(value, _)| value)
    }

    fn insert(&mut self, key: K, value: V) {
        let seq = self.next;
        self.next = self.next.wrapping_add(1);
        self.map.insert(key.clone(), (value, seq));
        self.order.push_back((key, seq));
        while self.map.len() > self.capacity {
            let Some((old, old_seq)) = self.order.pop_front() else {
                break;
            };
            // Entries replaced since are still in `order`, under an older
            // sequence number.
            if self.map.get(&old).is_some_and(|(_, seq)| *seq == old_seq) {
                self.map.remove(&old);
            }
        }
        // Keep `order` from growing without bound through replacements.
        if self.order.len() > self.capacity.saturating_mul(4) {
            let map = &self.map;
            self.order
                .retain(|(key, seq)| map.get(key).is_some_and(|(_, current)| current == seq));
        }
    }

    fn len(&self) -> usize {
        self.map.len()
    }
}

/// A zone's name servers, as its parent delegates it.
#[derive(Clone, Debug)]
pub(super) struct Delegation {
    pub(super) servers: Arc<[Name]>,
    expires: Instant,
}

#[derive(Clone)]
struct Addresses {
    ips: Arc<[IpAddr]>,
    expires: Instant,
}

/// How a server has been doing.
#[derive(Clone, Copy)]
struct Server {
    /// Smoothed round-trip time.
    srtt: Duration,
    /// Whether `srtt` was measured rather than assumed.
    measured: bool,
    failures: u32,
    down_until: Option<Instant>,
    /// False once it answered with the case of the name changed: no 0x20
    /// for it.
    keeps_case: bool,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            srtt: UNKNOWN_RTT,
            measured: false,
            failures: 0,
            down_until: None,
            keeps_case: true,
        }
    }
}

/// The infrastructure tables.
pub(super) struct Infra {
    delegations: Mutex<Bounded<Name, Delegation>>,
    addresses: Mutex<Bounded<Name, Addresses>>,
    servers: Mutex<Bounded<IpAddr, Server>>,
}

impl Infra {
    /// Tables of at most `entries` entries each.
    pub(super) fn new(entries: usize) -> Self {
        Self {
            delegations: Mutex::new(Bounded::new(entries)),
            addresses: Mutex::new(Bounded::new(entries)),
            servers: Mutex::new(Bounded::new(entries)),
        }
    }

    /// The known zone cut closest to `name` (`name` itself or an
    /// ancestor) that has not expired, with its delegation.
    pub(super) fn closest(&self, name: &Name, now: Instant) -> Option<(Name, Delegation)> {
        let delegations = self
            .delegations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        (0..=name.label_count()).rev().find_map(|labels| {
            let zone = name.suffix(labels)?;
            let delegation = delegations.get(&zone)?;
            (delegation.expires > now).then(|| (zone, delegation.clone()))
        })
    }

    /// Remembers that `zone` is served by `servers` for `ttl` seconds.
    pub(super) fn delegate(&self, zone: Name, servers: Vec<Name>, ttl: u32, now: Instant) {
        let delegation = Delegation {
            servers: servers.into(),
            expires: now.checked_add(keep_for(ttl)).unwrap_or(now),
        };
        self.delegations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(zone, delegation);
    }

    /// The addresses of name server `name`, if known and not expired.
    pub(super) fn addresses(&self, name: &Name, now: Instant) -> Option<Arc<[IpAddr]>> {
        let addresses = self
            .addresses
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        addresses
            .get(name)
            .filter(|entry| entry.expires > now)
            .map(|entry| Arc::clone(&entry.ips))
    }

    /// Remembers name server `name`'s addresses for `ttl` seconds; an empty
    /// list too, so a name without addresses is not looked up again soon.
    pub(super) fn set_addresses(&self, name: Name, ips: Vec<IpAddr>, ttl: u32, now: Instant) {
        let entry = Addresses {
            ips: ips.into(),
            expires: now.checked_add(keep_for(ttl)).unwrap_or(now),
        };
        self.addresses
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(name, entry);
    }

    /// `ips` in the order to try them: servers not failing first, then by
    /// round-trip time.
    pub(super) fn ranked(&self, ips: &mut [IpAddr], now: Instant) {
        let servers = self.servers.lock().unwrap_or_else(PoisonError::into_inner);
        ips.sort_by_cached_key(|ip| {
            let server = servers.get(ip).copied().unwrap_or_default();
            let down = server.down_until.is_some_and(|until| until > now);
            (down, server.srtt)
        });
    }

    /// How long to wait for `ip`: a few round-trip times, within bounds.
    pub(super) fn attempt_timeout(&self, ip: IpAddr) -> Duration {
        let srtt = self
            .servers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&ip)
            .map_or(UNKNOWN_RTT, |server| server.srtt);
        srtt.saturating_mul(4).clamp(MIN_ATTEMPT, MAX_ATTEMPT)
    }

    /// Whether `ip` keeps the case of names, as far as is known.
    pub(super) fn keeps_case(&self, ip: IpAddr) -> bool {
        self.servers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&ip)
            .is_none_or(|server| server.keeps_case)
    }

    fn update(&self, ip: IpAddr, change: impl FnOnce(&mut Server)) {
        let mut servers = self.servers.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(server) = servers.get_mut(&ip) {
            change(server);
        } else {
            let mut server = Server::default();
            change(&mut server);
            servers.insert(ip, server);
        }
    }

    /// `ip` answered in `rtt`.
    pub(super) fn answered(&self, ip: IpAddr, rtt: Duration) {
        self.update(ip, |server| {
            // srtt += (rtt - srtt) / 8, as TCP does, from the first sample.
            server.srtt = if server.measured {
                server
                    .srtt
                    .saturating_mul(7)
                    .saturating_add(rtt)
                    .checked_div(8)
                    .unwrap_or(rtt)
            } else {
                rtt
            };
            server.measured = true;
            server.failures = 0;
            server.down_until = None;
        });
    }

    /// `ip` did not answer, or not usefully.
    pub(super) fn failed(&self, ip: IpAddr, now: Instant) {
        self.update(ip, |server| {
            server.srtt = server.srtt.saturating_mul(2).min(MAX_ATTEMPT);
            server.failures = server.failures.saturating_add(1);
            if server.failures >= FAILURES_BEFORE_DOWN {
                server.down_until = now.checked_add(DOWN_FOR);
            }
        });
    }

    /// `ip` changed the case of a name: ask it without 0x20 from now on.
    pub(super) fn ignores_case(&self, ip: IpAddr) {
        self.update(ip, |server| server.keeps_case = false);
    }

    /// How many zone cuts and servers are known.
    pub(super) fn sizes(&self) -> (usize, usize) {
        (
            self.delegations
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .len(),
            self.servers
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn name(text: &str) -> Name {
        text.parse().unwrap()
    }

    #[test]
    fn the_closest_live_cut_wins() {
        let infra = Infra::new(100);
        let now = Instant::now();
        infra.delegate(
            name("com."),
            vec![name("a.gtld-servers.net.")],
            172_800,
            now,
        );
        infra.delegate(
            name("example.com."),
            vec![name("ns1.example.com.")],
            60,
            now,
        );
        let (zone, _) = infra.closest(&name("www.example.com."), now).unwrap();
        assert_eq!(zone, name("example.com."));
        assert!(
            infra.closest(&name("example.org."), now).is_none(),
            "nothing for org"
        );
        // Expired: the next one up.
        let later = now + Duration::from_secs(120);
        let (zone, _) = infra.closest(&name("www.example.com."), later).unwrap();
        assert_eq!(zone, name("com."));
    }

    #[test]
    fn tables_stay_bounded() {
        let infra = Infra::new(3);
        let now = Instant::now();
        for i in 0..10 {
            infra.set_addresses(
                name(&format!("ns{i}.example.")),
                vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, i))],
                300,
                now,
            );
        }
        assert!(infra.addresses(&name("ns0.example."), now).is_none());
        assert!(infra.addresses(&name("ns9.example."), now).is_some());
        let mut bounded = Bounded::new(2);
        for _ in 0..100 {
            bounded.insert(1, ());
        }
        assert!(bounded.order.len() <= 8, "replacements do not pile up");
    }

    #[test]
    fn fast_and_healthy_servers_first() {
        let infra = Infra::new(100);
        let now = Instant::now();
        let [slow, fast, broken, unknown] =
            [1, 2, 3, 4].map(|i| IpAddr::V4(Ipv4Addr::new(192, 0, 2, i)));
        infra.answered(slow, Duration::from_millis(900));
        infra.answered(fast, Duration::from_millis(20));
        for _ in 0..3 {
            infra.failed(broken, now);
        }
        let mut ips = vec![broken, slow, unknown, fast];
        infra.ranked(&mut ips, now);
        assert_eq!(ips, [fast, unknown, slow, broken]);
        assert_eq!(infra.attempt_timeout(fast), MIN_ATTEMPT);
        assert!(infra.keeps_case(fast));
        infra.ignores_case(fast);
        assert!(!infra.keeps_case(fast));
    }
}
