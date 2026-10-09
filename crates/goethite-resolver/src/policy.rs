//! Who is asking, and what applies to them.
//!
//! A [`Policy`] is compiled by the control plane from the configuration: the
//! filter, the groups with the filter sources each one uses, and the clients
//! with the addresses that identify them. It is immutable; [`PolicyState`]
//! holds the current one behind an [`ArcSwap`] together with the two things
//! that change without a recompile: which schedules are active right now,
//! and whether filtering is paused.
//!
//! A client is identified by its client ID, when the query came over an
//! encrypted transport that carries one and the ID is known; otherwise by
//! the longest network among all clients' addresses that contains the
//! query's source address. Unknown clients belong to the default group.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use goethite_filter::{Filter, Source, Sources};

use crate::blocking::BlockResponse;
use crate::cidr::{Cidr, canonical, mask};
use crate::services::{ServiceFilter, ServiceMask};

/// The most schedules a policy tells apart.
pub const MAX_SCHEDULES: usize = 64;

/// The longest client ID: one DNS label, so it fits in a TLS server name.
pub const MAX_CLIENT_ID_LEN: usize = 63;

/// Whether `text` is a valid client ID: 1 to [`MAX_CLIENT_ID_LEN`]
/// lowercase letters, digits and hyphens, not starting or ending with a
/// hyphen. Such an ID is a DNS label and a URL path segment as it is.
pub fn is_client_id(text: &str) -> bool {
    let bytes = text.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_CLIENT_ID_LEN
        && bytes
            .iter()
            .all(|&byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && bytes.first() != Some(&b'-')
        && bytes.last() != Some(&b'-')
}

/// Sources a group uses while a schedule is active.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduledSources {
    /// The schedule's index, below [`MAX_SCHEDULES`].
    pub schedule: u8,
    /// The extra sources.
    pub sources: Sources,
}

/// Services a group blocks while a schedule is active.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduledServices {
    /// The schedule's index, below [`MAX_SCHEDULES`].
    pub schedule: u8,
    /// The services, by index in the policy's [`ServiceFilter`].
    pub services: ServiceMask,
}

/// What applies to the clients of one group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupPolicy {
    /// The group's ID, for the query log.
    pub id: Arc<str>,
    /// Whether names are filtered at all.
    pub filtering: bool,
    /// Whether search engines are sent to their safe endpoints.
    pub safe_search: bool,
    /// Sources that always apply.
    pub sources: Sources,
    /// Sources that apply while a schedule is active.
    pub scheduled: Vec<ScheduledSources>,
    /// Services it always blocks.
    pub services: ServiceMask,
    /// Services it blocks while a schedule is active.
    pub scheduled_services: Vec<ScheduledServices>,
}

impl GroupPolicy {
    /// A group that filters with `sources` and nothing else.
    pub fn new(id: impl Into<Arc<str>>, sources: Sources) -> Self {
        Self {
            id: id.into(),
            filtering: true,
            safe_search: false,
            sources,
            scheduled: Vec::new(),
            services: ServiceMask::NONE,
            scheduled_services: Vec::new(),
        }
    }

    /// The sources that apply while the schedules in `active` are on.
    pub fn sources_now(&self, active: u64) -> Sources {
        self.scheduled
            .iter()
            .filter(|entry| {
                1_u64
                    .checked_shl(u32::from(entry.schedule))
                    .is_some_and(|bit| active & bit != 0)
            })
            .fold(self.sources, |all, entry| all.union(entry.sources))
    }

    /// The services blocked while the schedules in `active` are on.
    pub fn services_now(&self, active: u64) -> ServiceMask {
        self.scheduled_services
            .iter()
            .filter(|entry| {
                1_u64
                    .checked_shl(u32::from(entry.schedule))
                    .is_some_and(|bit| active & bit != 0)
            })
            .fold(self.services, |all, entry| all.union(entry.services))
    }
}

/// A known client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientPolicy {
    /// The client's ID, for the query log.
    pub id: Arc<str>,
    /// The networks or addresses it uses.
    pub addresses: Vec<Cidr>,
    /// The client IDs it uses over encrypted transports (see
    /// [`is_client_id`]).
    pub ids: Vec<Arc<str>>,
    /// Its group: an index into [`PolicyParts::groups`].
    pub group: usize,
}

/// Everything a [`Policy`] is made of.
pub struct PolicyParts {
    /// The compiled filter.
    pub filter: Arc<Filter>,
    /// The ID of each source in the filter (a list ID, for example), by
    /// source index, for the query log.
    pub source_ids: Vec<Arc<str>>,
    /// The groups; the first one is the default group, for clients that are
    /// not known. Must not be empty.
    pub groups: Vec<GroupPolicy>,
    /// The known clients.
    pub clients: Vec<ClientPolicy>,
    /// How blocked names are answered.
    pub block_response: BlockResponse,
    /// Time to live of null-IP answers.
    pub blocked_ttl: u32,
    /// The master switch: when off, nothing is filtered for anyone.
    pub protection: bool,
    /// The blocked services catalog, compiled: the groups' service masks
    /// index into it.
    pub services: Arc<ServiceFilter>,
}

/// Why a policy could not be built.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// There is no default group.
    #[error("a policy needs at least the default group")]
    NoGroups,
    /// A client refers to a group that does not exist.
    #[error("client {client} refers to group number {group}, which does not exist")]
    UnknownGroup {
        /// The client.
        client: String,
        /// The group index.
        group: usize,
    },
    /// Two clients claim the same network.
    #[error("clients {first} and {second} both use {network}")]
    DuplicateAddress {
        /// The network.
        network: Cidr,
        /// One client.
        first: String,
        /// The other.
        second: String,
    },
    /// Two clients claim the same client ID.
    #[error("clients {first} and {second} both use the client ID {id}")]
    DuplicateId {
        /// The client ID.
        id: String,
        /// One client.
        first: String,
        /// The other.
        second: String,
    },
    /// A client ID is not valid (see [`is_client_id`]).
    #[error("client {client} has the invalid client ID {id:?}")]
    InvalidId {
        /// The client.
        client: String,
        /// The ID.
        id: String,
    },
    /// A group refers to a schedule index beyond [`MAX_SCHEDULES`].
    #[error("group {0} refers to a schedule beyond the {MAX_SCHEDULES} supported")]
    ScheduleOutOfRange(String),
}

/// Exact-network lookup tables, longest prefix first, and client IDs.
#[derive(Debug, Default)]
struct ClientTable {
    v4: Vec<(u8, HashMap<IpAddr, usize>)>,
    v6: Vec<(u8, HashMap<IpAddr, usize>)>,
    ids: HashMap<Arc<str>, usize>,
}

impl ClientTable {
    fn build(clients: &[ClientPolicy]) -> Result<Self, PolicyError> {
        let name = |i: usize| clients.get(i).map(|c| c.id.to_string()).unwrap_or_default();
        let mut by_prefix: HashMap<(bool, u8), HashMap<IpAddr, usize>> = HashMap::new();
        let mut ids = HashMap::new();
        for (index, client) in clients.iter().enumerate() {
            for id in &client.ids {
                if !is_client_id(id) {
                    return Err(PolicyError::InvalidId {
                        client: name(index),
                        id: id.to_string(),
                    });
                }
                if let Some(other) = ids.insert(Arc::clone(id), index) {
                    return Err(PolicyError::DuplicateId {
                        id: id.to_string(),
                        first: name(other),
                        second: name(index),
                    });
                }
            }
            for network in &client.addresses {
                let table = by_prefix
                    .entry((network.addr().is_ipv4(), network.prefix()))
                    .or_default();
                if let Some(&other) = table.get(&network.addr()) {
                    return Err(PolicyError::DuplicateAddress {
                        network: *network,
                        first: name(other),
                        second: name(index),
                    });
                }
                table.insert(network.addr(), index);
            }
        }
        let mut table = Self {
            ids,
            ..Self::default()
        };
        for ((v4, prefix), entries) in by_prefix {
            if v4 {
                table.v4.push((prefix, entries));
            } else {
                table.v6.push((prefix, entries));
            }
        }
        table
            .v4
            .sort_unstable_by_key(|entry| std::cmp::Reverse(entry.0));
        table
            .v6
            .sort_unstable_by_key(|entry| std::cmp::Reverse(entry.0));
        Ok(table)
    }

    fn lookup(&self, ip: IpAddr, id: Option<&str>) -> Option<usize> {
        if let Some(&index) = id.and_then(|id| self.ids.get(id)) {
            return Some(index);
        }
        let ip = canonical(ip);
        let tables = if ip.is_ipv4() { &self.v4 } else { &self.v6 };
        tables
            .iter()
            .find_map(|(prefix, entries)| entries.get(&mask(ip, *prefix)).copied())
    }
}

/// A compiled, immutable policy.
pub struct Policy {
    filter: Arc<Filter>,
    source_ids: Vec<Arc<str>>,
    groups: Vec<GroupPolicy>,
    default_group: GroupPolicy,
    clients: Vec<ClientPolicy>,
    table: ClientTable,
    block_response: BlockResponse,
    blocked_ttl: u32,
    protection: bool,
    services: Arc<ServiceFilter>,
}

impl Policy {
    /// Checks `parts` and compiles them.
    ///
    /// # Errors
    ///
    /// [`PolicyError`] if there is no group, a client refers to a missing
    /// group, two clients use the same network, or a schedule index is out
    /// of range.
    pub fn new(parts: PolicyParts) -> Result<Self, PolicyError> {
        let default_group = parts.groups.first().cloned().ok_or(PolicyError::NoGroups)?;
        for client in &parts.clients {
            if client.group >= parts.groups.len() {
                return Err(PolicyError::UnknownGroup {
                    client: client.id.to_string(),
                    group: client.group,
                });
            }
        }
        for group in &parts.groups {
            if group
                .scheduled
                .iter()
                .map(|entry| entry.schedule)
                .chain(group.scheduled_services.iter().map(|entry| entry.schedule))
                .any(|schedule| usize::from(schedule) >= MAX_SCHEDULES)
            {
                return Err(PolicyError::ScheduleOutOfRange(group.id.to_string()));
            }
        }
        let table = ClientTable::build(&parts.clients)?;
        Ok(Self {
            filter: parts.filter,
            source_ids: parts.source_ids,
            groups: parts.groups,
            default_group,
            clients: parts.clients,
            table,
            block_response: parts.block_response,
            blocked_ttl: parts.blocked_ttl,
            protection: parts.protection,
            services: parts.services,
        })
    }

    /// One default group that uses every source and has no clients: what a
    /// node without groups does.
    pub fn simple(
        filter: Arc<Filter>,
        source_ids: Vec<Arc<str>>,
        block_response: BlockResponse,
        blocked_ttl: u32,
        protection: bool,
    ) -> Self {
        let group = GroupPolicy::new("default", Sources::ALL);
        Self {
            filter,
            source_ids,
            groups: vec![group.clone()],
            default_group: group,
            clients: Vec::new(),
            table: ClientTable::default(),
            block_response,
            blocked_ttl,
            protection,
            services: Arc::new(ServiceFilter::empty()),
        }
    }

    /// A policy that filters nothing.
    pub fn none() -> Self {
        Self::simple(
            Arc::new(Filter::empty()),
            Vec::new(),
            BlockResponse::default(),
            10,
            false,
        )
    }

    /// The compiled filter.
    pub fn filter(&self) -> &Arc<Filter> {
        &self.filter
    }

    /// The ID of `source`, if it has one.
    pub fn source_id(&self, source: Source) -> Option<&Arc<str>> {
        self.source_ids.get(source.index())
    }

    /// The client using the client ID `id`, if it is known, or else the one
    /// using `ip`, if that is known; and its group.
    pub fn identify(&self, ip: IpAddr, id: Option<&str>) -> (Option<&ClientPolicy>, &GroupPolicy) {
        let client = self
            .table
            .lookup(ip, id)
            .and_then(|index| self.clients.get(index));
        let group = client
            .and_then(|client| self.groups.get(client.group))
            .unwrap_or(&self.default_group);
        (client, group)
    }

    /// The client using the client ID `id`, if there is one.
    pub fn client_with_id(&self, id: &str) -> Option<&ClientPolicy> {
        self.table
            .ids
            .get(id)
            .and_then(|&index| self.clients.get(index))
    }

    /// How blocked names are answered.
    pub fn block_response(&self) -> BlockResponse {
        self.block_response
    }

    /// Time to live of null-IP answers.
    pub fn blocked_ttl(&self) -> u32 {
        self.blocked_ttl
    }

    /// Whether filtering is on at all.
    pub fn protection(&self) -> bool {
        self.protection
    }

    /// The blocked services catalog, compiled.
    pub fn services(&self) -> &ServiceFilter {
        &self.services
    }
}

/// The current policy and the state that changes between recompiles.
pub struct PolicyState {
    policy: ArcSwap<Policy>,
    active_schedules: AtomicU64,
    /// Seconds since the Unix epoch until which filtering is paused; 0 when
    /// it is not.
    paused_until: AtomicU64,
}

impl PolicyState {
    /// State starting with `policy`, no schedule active and nothing paused.
    pub fn new(policy: Policy) -> Self {
        Self {
            policy: ArcSwap::from_pointee(policy),
            active_schedules: AtomicU64::new(0),
            paused_until: AtomicU64::new(0),
        }
    }

    /// The current policy.
    pub fn policy(&self) -> Arc<Policy> {
        self.policy.load_full()
    }

    /// Swaps in `policy`; queries in progress finish with the old one.
    pub fn replace(&self, policy: Policy) {
        self.policy.store(Arc::new(policy));
    }

    /// Sets which schedules are active: bit `i` for schedule index `i`.
    pub fn set_active_schedules(&self, active: u64) {
        self.active_schedules.store(active, Ordering::Relaxed);
    }

    /// Which schedules are active.
    pub fn active_schedules(&self) -> u64 {
        self.active_schedules.load(Ordering::Relaxed)
    }

    /// Pauses filtering until `until`, or resumes it with `None`.
    pub fn pause(&self, until: Option<SystemTime>) {
        let seconds = until.map_or(0, |until| {
            until
                .duration_since(UNIX_EPOCH)
                .map_or(1, |since| since.as_secs().max(1))
        });
        self.paused_until.store(seconds, Ordering::Relaxed);
    }

    /// Until when filtering is paused, if it is.
    pub fn paused_until(&self) -> Option<SystemTime> {
        let seconds = self.paused_until.load(Ordering::Relaxed);
        if seconds == 0 {
            return None;
        }
        let until = UNIX_EPOCH.checked_add(Duration::from_secs(seconds))?;
        (until > SystemTime::now()).then_some(until)
    }

    pub(crate) fn is_paused(&self) -> bool {
        self.paused_until.load(Ordering::Relaxed) != 0 && self.paused_until().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(text: &str) -> Cidr {
        text.parse().unwrap()
    }

    fn source(index: usize) -> Source {
        Source::new(index).unwrap()
    }

    fn parts(clients: Vec<ClientPolicy>) -> PolicyParts {
        let mut kids = GroupPolicy::new("kids", Sources::NONE.with(source(0)));
        kids.scheduled.push(ScheduledSources {
            schedule: 3,
            sources: Sources::NONE.with(source(1)),
        });
        kids.safe_search = true;
        PolicyParts {
            filter: Arc::new(Filter::empty()),
            source_ids: vec!["ads".into(), "social".into()],
            groups: vec![GroupPolicy::new("default", Sources::ALL), kids],
            clients,
            block_response: BlockResponse::NullIp,
            blocked_ttl: 10,
            protection: true,
            services: Arc::new(ServiceFilter::empty()),
        }
    }

    fn client(id: &str, addresses: &[&str], group: usize) -> ClientPolicy {
        ClientPolicy {
            id: id.into(),
            addresses: addresses.iter().map(|a| cidr(a)).collect(),
            ids: Vec::new(),
            group,
        }
    }

    #[test]
    fn identifies_clients_by_the_longest_network() {
        let policy = Policy::new(parts(vec![
            client("lan", &["192.168.1.0/24"], 0),
            client("tablet", &["192.168.1.23", "2001:db8:1:2::/64"], 1),
            client("everyone-v6", &["::/0"], 0),
        ]))
        .unwrap();
        let who = |ip: &str| {
            let (client, group) = policy.identify(ip.parse().unwrap(), None);
            (client.map(|c| c.id.to_string()), group.id.to_string())
        };
        assert_eq!(who("192.168.1.23"), (Some("tablet".into()), "kids".into()));
        assert_eq!(
            who("::ffff:192.168.1.23"),
            (Some("tablet".into()), "kids".into())
        );
        assert_eq!(who("192.168.1.24"), (Some("lan".into()), "default".into()));
        assert_eq!(who("10.0.0.1"), (None, "default".into()));
        assert_eq!(
            who("2001:db8:1:2::99"),
            (Some("tablet".into()), "kids".into())
        );
        assert_eq!(
            who("2001:db8::1"),
            (Some("everyone-v6".into()), "default".into())
        );
        assert_eq!(policy.source_id(source(1)).map(|id| &**id), Some("social"));
    }

    #[test]
    fn identifies_clients_by_id_first() {
        let mut phone = client("phone", &[], 1);
        phone.ids = vec!["anna-phone".into(), "p2".into()];
        let policy =
            Policy::new(parts(vec![client("lan", &["192.168.1.0/24"], 0), phone])).unwrap();
        let who = |ip: &str, id: Option<&str>| {
            let (client, group) = policy.identify(ip.parse().unwrap(), id);
            (client.map(|c| c.id.to_string()), group.id.to_string())
        };
        assert_eq!(
            who("192.168.1.5", Some("anna-phone")),
            (Some("phone".into()), "kids".into())
        );
        assert_eq!(
            who("203.0.113.9", Some("p2")),
            (Some("phone".into()), "kids".into())
        );
        // An unknown ID falls back to the address.
        assert_eq!(
            who("192.168.1.5", Some("unknown")),
            (Some("lan".into()), "default".into())
        );
        assert_eq!(
            who("203.0.113.9", Some("unknown")),
            (None, "default".into())
        );
    }

    #[test]
    fn client_ids() {
        for valid in ["a", "anna-phone", "0", "x1-2-3", &"a".repeat(63)] {
            assert!(is_client_id(valid), "{valid}");
        }
        for invalid in [
            "",
            "-a",
            "a-",
            "Anna",
            "a.b",
            "a_b",
            "ä",
            "a b",
            &"a".repeat(64),
        ] {
            assert!(!is_client_id(invalid), "{invalid}");
        }
    }

    #[test]
    fn rejects_inconsistent_parts() {
        let mut a = client("a", &[], 0);
        a.ids = vec!["same".into()];
        let mut b = client("b", &[], 1);
        b.ids = vec!["same".into()];
        assert!(matches!(
            Policy::new(parts(vec![a, b])),
            Err(PolicyError::DuplicateId { .. })
        ));
        let mut c = client("c", &[], 0);
        c.ids = vec!["Not valid".into()];
        assert!(matches!(
            Policy::new(parts(vec![c])),
            Err(PolicyError::InvalidId { .. })
        ));
        let duplicate = Policy::new(parts(vec![
            client("a", &["10.0.0.0/8"], 0),
            client("b", &["10.0.0.0/8"], 1),
        ]));
        assert!(matches!(
            duplicate,
            Err(PolicyError::DuplicateAddress { .. })
        ));
        let missing = Policy::new(parts(vec![client("a", &["10.0.0.1"], 7)]));
        assert!(matches!(
            missing,
            Err(PolicyError::UnknownGroup { group: 7, .. })
        ));
        let mut empty = parts(Vec::new());
        empty.groups.clear();
        assert!(matches!(Policy::new(empty), Err(PolicyError::NoGroups)));
        let mut far = parts(Vec::new());
        far.groups[1].scheduled[0].schedule = 64;
        assert!(matches!(
            Policy::new(far),
            Err(PolicyError::ScheduleOutOfRange(_))
        ));
    }

    #[test]
    fn scheduled_sources_apply_while_active() {
        let policy = Policy::new(parts(vec![client("tablet", &["10.0.0.2"], 1)])).unwrap();
        let (_, kids) = policy.identify("10.0.0.2".parse().unwrap(), None);
        assert_eq!(kids.sources_now(0), Sources::NONE.with(source(0)));
        assert_eq!(kids.sources_now(1 << 2), Sources::NONE.with(source(0)));
        assert_eq!(
            kids.sources_now(1 << 3),
            Sources::NONE.with(source(0)).with(source(1))
        );
    }

    #[test]
    fn pausing() {
        let state = PolicyState::new(Policy::none());
        assert!(!state.is_paused());
        let until = SystemTime::now() + Duration::from_secs(600);
        state.pause(Some(until));
        assert!(state.is_paused());
        assert!(state.paused_until().is_some());
        state.pause(None);
        assert!(!state.is_paused());
        // A pause in the past is over.
        state.pause(Some(UNIX_EPOCH + Duration::from_secs(5)));
        assert!(!state.is_paused());
        assert_eq!(state.paused_until(), None);
    }
}
