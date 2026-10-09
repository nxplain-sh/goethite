//! Which clients goethite answers: allowed and blocked networks and client
//! IDs, checked for every query on every transport.
//!
//! A query is answered when its client is on the allowed list, or that list
//! is empty, and is not on the blocked list; a client is on a list by its
//! address or by its client ID. Loopback addresses always pass, so local
//! tools and the floating IP's health check keep working whatever the lists
//! say; only a blocked client ID is refused even there.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use crate::cidr::{Cidr, canonical, mask};

/// The most entries one access list may hold.
pub const MAX_ACCESS_ENTRIES: usize = 10_000;

/// The entries of one list: networks (single addresses are /32 or /128)
/// and client IDs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccessList {
    /// Networks and addresses.
    pub networks: Vec<Cidr>,
    /// Client IDs, as clients name themselves over DNS over TLS, HTTPS or
    /// QUIC.
    pub ids: Vec<Arc<str>>,
}

/// A list compiled for lookups: one set of networks per prefix length,
/// longest first, and the client IDs.
#[derive(Debug, Default)]
struct Matcher {
    v4: Vec<(u8, HashSet<IpAddr>)>,
    v6: Vec<(u8, HashSet<IpAddr>)>,
    ids: HashSet<Arc<str>>,
}

impl Matcher {
    fn new(list: &AccessList) -> Self {
        let mut v4: Vec<(u8, HashSet<IpAddr>)> = Vec::new();
        let mut v6: Vec<(u8, HashSet<IpAddr>)> = Vec::new();
        for network in &list.networks {
            let tables = if network.addr().is_ipv4() {
                &mut v4
            } else {
                &mut v6
            };
            match tables
                .iter_mut()
                .find(|(prefix, _)| *prefix == network.prefix())
            {
                Some((_, set)) => {
                    set.insert(network.addr());
                }
                None => tables.push((network.prefix(), HashSet::from([network.addr()]))),
            }
        }
        v4.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.0));
        v6.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.0));
        Self {
            v4,
            v6,
            ids: list.ids.iter().cloned().collect(),
        }
    }

    fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty() && self.ids.is_empty()
    }

    /// Whether `ip`, already canonical, is in one of the networks.
    fn has_address(&self, ip: IpAddr) -> bool {
        let tables = if ip.is_ipv4() { &self.v4 } else { &self.v6 };
        tables
            .iter()
            .any(|(prefix, set)| set.contains(&mask(ip, *prefix)))
    }

    fn has_id(&self, id: Option<&str>) -> bool {
        id.is_some_and(|id| self.ids.contains(id))
    }
}

/// The allowed and blocked lists, compiled. The default answers everyone.
#[derive(Debug, Default)]
pub struct Access {
    allowed: Matcher,
    blocked: Matcher,
}

impl Access {
    /// Compiles `allowed` and `blocked`.
    pub fn new(allowed: &AccessList, blocked: &AccessList) -> Self {
        Self {
            allowed: Matcher::new(allowed),
            blocked: Matcher::new(blocked),
        }
    }

    /// Whether both lists are empty, so everyone is answered.
    pub fn is_open(&self) -> bool {
        self.allowed.is_empty() && self.blocked.is_empty()
    }

    /// Whether a query from `ip`, which named itself `id` (if it did), is
    /// answered.
    pub fn admits(&self, ip: IpAddr, id: Option<&str>) -> bool {
        if self.is_open() {
            return true;
        }
        if self.blocked.has_id(id) {
            return false;
        }
        let ip = canonical(ip);
        if ip.is_loopback() {
            return true;
        }
        if self.blocked.has_address(ip) {
            return false;
        }
        self.allowed.is_empty() || self.allowed.has_address(ip) || self.allowed.has_id(id)
    }

    /// Whether a client at `ip` could be answered once it names its client
    /// ID, for deciding before a TLS handshake: not if its address is
    /// blocked, nor if only listed addresses are allowed and `ip` is not one
    /// of them and no client ID is allowed either.
    pub fn may_admit(&self, ip: IpAddr) -> bool {
        if self.is_open() {
            return true;
        }
        let ip = canonical(ip);
        if ip.is_loopback() {
            return true;
        }
        if self.blocked.has_address(ip) {
            return false;
        }
        self.allowed.is_empty() || self.allowed.has_address(ip) || !self.allowed.ids.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(networks: &[&str], ids: &[&str]) -> AccessList {
        AccessList {
            networks: networks.iter().map(|text| text.parse().unwrap()).collect(),
            ids: ids.iter().map(|id| Arc::from(*id)).collect(),
        }
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn empty_lists_answer_everyone() {
        let access = Access::default();
        assert!(access.is_open());
        assert!(access.admits(ip("203.0.113.9"), None));
        assert!(access.may_admit(ip("2001:db8::1")));
    }

    #[test]
    fn blocked_addresses_and_ids_are_refused() {
        let access = Access::new(
            &AccessList::default(),
            &list(&["203.0.113.0/24", "2001:db8::/32"], &["guest"]),
        );
        assert!(!access.admits(ip("203.0.113.9"), None));
        assert!(
            !access.admits(ip("::ffff:203.0.113.9"), None),
            "mapped IPv4 is IPv4"
        );
        assert!(!access.admits(ip("2001:db8::1"), Some("anna")));
        assert!(!access.admits(ip("198.51.100.1"), Some("guest")));
        assert!(access.admits(ip("198.51.100.1"), Some("anna")));
        assert!(access.admits(ip("198.51.100.1"), None));
        assert!(!access.may_admit(ip("203.0.113.9")));
        assert!(
            access.may_admit(ip("198.51.100.1")),
            "its ID may still be blocked later"
        );
    }

    #[test]
    fn an_allowed_list_answers_only_its_entries() {
        let access = Access::new(&list(&["192.168.1.0/24"], &[]), &AccessList::default());
        assert!(access.admits(ip("192.168.1.20"), None));
        assert!(!access.admits(ip("192.168.2.20"), None));
        assert!(!access.may_admit(ip("192.168.2.20")));
    }

    #[test]
    fn allowed_ids_admit_any_address() {
        let access = Access::new(&list(&[], &["anna"]), &AccessList::default());
        assert!(access.admits(ip("203.0.113.9"), Some("anna")));
        assert!(!access.admits(ip("203.0.113.9"), Some("bob")));
        assert!(!access.admits(ip("203.0.113.9"), None));
        assert!(
            access.may_admit(ip("203.0.113.9")),
            "the ID comes with the handshake"
        );
    }

    #[test]
    fn both_lists_apply() {
        let access = Access::new(
            &list(&["192.168.1.0/24"], &[]),
            &list(&["192.168.1.66"], &[]),
        );
        assert!(access.admits(ip("192.168.1.20"), None));
        assert!(!access.admits(ip("192.168.1.66"), None));
    }

    #[test]
    fn loopback_addresses_always_pass() {
        let access = Access::new(
            &list(&["192.168.1.0/24"], &[]),
            &list(&["0.0.0.0/0", "::/0"], &["guest"]),
        );
        for loopback in ["127.0.0.1", "127.8.9.10", "::1", "::ffff:127.0.0.1"] {
            assert!(access.admits(ip(loopback), None), "{loopback}");
            assert!(access.may_admit(ip(loopback)), "{loopback}");
        }
        assert!(
            !access.admits(ip("192.168.1.20"), None),
            "blocked by 0.0.0.0/0"
        );
        assert!(
            !access.admits(ip("127.0.0.1"), Some("guest")),
            "a blocked client ID is refused even on loopback"
        );
    }
}
