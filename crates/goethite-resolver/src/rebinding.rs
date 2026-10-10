//! DNS rebinding protection.
//!
//! A DNS rebinding attack makes a public name, which the attacker controls,
//! resolve to an address inside the local network, so that a web page from
//! that name can reach devices on the LAN. goethite removes private,
//! loopback and link-local addresses from forwarded answers, unless the
//! question is for a name below one of the allowed private domains (such as
//! `lan` or `home.arpa`), where such answers are expected.
//!
//! The question name decides, not the owner of each record: a public answer
//! cannot vouch for a private name, but an attacker can easily point a public
//! name at a private address.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use goethite_proto::{Name, Response};

/// Private domains whose names may resolve to private addresses by default.
pub const DEFAULT_PRIVATE_DOMAINS: &[&str] = &["lan", "home.arpa", "internal", "local"];

/// Removes private addresses from answers for public names.
#[derive(Clone, Debug)]
pub struct RebindingProtection {
    private_domains: Vec<Name>,
}

impl RebindingProtection {
    /// Protection that allows private answers only below `private_domains`.
    pub fn new(private_domains: Vec<Name>) -> Self {
        Self { private_domains }
    }

    /// Removes the private addresses from `response` unless `question` is
    /// below a private domain: the A and AAAA records with private
    /// addresses, and the `ipv4hint` and `ipv6hint` addresses of SVCB and
    /// HTTPS records (RFC 9460 7.3). Returns how many addresses were
    /// removed.
    pub fn apply(&self, question: &Name, response: &mut Response) -> usize {
        if self
            .private_domains
            .iter()
            .any(|domain| question.is_within(domain))
        {
            return 0;
        }
        let before = response.answers.len();
        response
            .answers
            .retain(|record| !record.ip().is_some_and(is_private));
        response
            .additional
            .retain(|record| !record.ip().is_some_and(is_private));
        let mut removed = before.saturating_sub(response.answers.len());
        for record in response.answers.iter_mut().chain(response.additional.iter_mut()) {
            removed = removed.saturating_add(record.prune_svc_hints(is_private));
        }
        removed
    }
}

/// Addresses that only make sense inside a network or host: RFC 1918, carrier
/// NAT, loopback, link-local, unspecified, unique-local IPv6, and IPv4 mapped
/// into IPv6.
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_private_v4(ip),
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(v4) => is_private_v4(v4),
            None => is_private_v6(ip),
        },
    }
}

fn is_private_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || a == 0
        // 100.64.0.0/10, carrier-grade NAT (RFC 6598).
        || (a == 100 && (64..=127).contains(&b))
}

fn is_private_v6(ip: Ipv6Addr) -> bool {
    let [first, second, third, ..] = ip.segments();
    ip.is_loopback()
        || ip.is_unspecified()
        // fc00::/7, unique local (RFC 4193).
        || first & 0xfe00 == 0xfc00
        // fe80::/10, link-local.
        || first & 0xffc0 == 0xfe80
        // 64:ff9b:1::/48, local-use NAT64 (RFC 8215).
        || (first == 0x0064 && second == 0xff9b && third == 0x0001)
}

#[cfg(test)]
mod tests {
    use goethite_proto::{Edns, Query, Question, Record, RecordClass, RecordType, ResponseCode};

    use super::*;

    fn name(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn private_ranges() {
        for private in [
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "0.1.2.3",
            "100.64.0.1",
            "100.127.255.255",
            "::1",
            "::",
            "fd00::1",
            "fc00::1",
            "fe80::1",
            "::ffff:192.168.1.1",
        ] {
            assert!(is_private(private.parse().unwrap()), "{private}");
        }
        for public in [
            "8.8.8.8",
            "172.32.0.1",
            "100.128.0.1",
            "192.0.2.1",
            "2620:fe::fe",
            "::ffff:8.8.8.8",
        ] {
            assert!(!is_private(public.parse().unwrap()), "{public}");
        }
    }

    fn response(owner: &str, addresses: &[&str]) -> Response {
        let query = Query {
            id: 1,
            recursion_desired: true,
            checking_disabled: false,
            authentic_data: false,
            question: Question {
                name: name(owner),
                qtype: RecordType::A,
                qclass: RecordClass::IN,
            },
            edns: Some(Edns::ours()),
        };
        let mut response = Response::for_query(&query, ResponseCode::NO_ERROR);
        for address in addresses {
            let ip: IpAddr = address.parse().unwrap();
            response.answers.push(match ip {
                IpAddr::V4(ip) => Record::a(name(owner), 60, ip),
                IpAddr::V6(ip) => Record::aaaa(name(owner), 60, ip),
            });
        }
        response
    }

    #[test]
    fn strips_private_answers_for_public_names() {
        let protection = RebindingProtection::new(vec![name("lan")]);
        let mut attack = response("evil.example", &["192.168.1.1", "203.0.113.5", "fd00::1"]);
        assert_eq!(protection.apply(&name("evil.example"), &mut attack), 2);
        assert_eq!(attack.answers.len(), 1);
        assert_eq!(attack.answers[0].ip(), Some("203.0.113.5".parse().unwrap()));

        let mut local = response("printer.lan", &["192.168.1.5"]);
        assert_eq!(protection.apply(&name("printer.LAN"), &mut local), 0);
        assert_eq!(local.answers.len(), 1);
    }
}
