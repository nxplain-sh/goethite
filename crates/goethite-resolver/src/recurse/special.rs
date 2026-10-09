//! Names a recursive resolver answers itself, without asking the root:
//! special-use names (RFC 6761, RFC 7686, RFC 8375) and the reverse zones
//! of private and special addresses (RFC 6303, RFC 7793). Asking the
//! internet about them would only leak what the network is up to.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

use goethite_proto::{Name, Query, Record, RecordType, Response, ResponseCode};

/// How long these answers may be cached.
const TTL: u32 = 3_600;

/// Zones that do not exist, as far as anyone asking goethite is concerned.
const EMPTY_ZONES: &[&str] = &[
    // RFC 6761, RFC 7686, RFC 8375, and the private-use `internal`.
    "invalid.",
    "test.",
    "onion.",
    "local.",
    "home.arpa.",
    "internal.",
    // RFC 6303: private, loopback, link-local and documentation addresses.
    "10.in-addr.arpa.",
    "16.172.in-addr.arpa.",
    "17.172.in-addr.arpa.",
    "18.172.in-addr.arpa.",
    "19.172.in-addr.arpa.",
    "20.172.in-addr.arpa.",
    "21.172.in-addr.arpa.",
    "22.172.in-addr.arpa.",
    "23.172.in-addr.arpa.",
    "24.172.in-addr.arpa.",
    "25.172.in-addr.arpa.",
    "26.172.in-addr.arpa.",
    "27.172.in-addr.arpa.",
    "28.172.in-addr.arpa.",
    "29.172.in-addr.arpa.",
    "30.172.in-addr.arpa.",
    "31.172.in-addr.arpa.",
    "168.192.in-addr.arpa.",
    "0.in-addr.arpa.",
    "127.in-addr.arpa.",
    "254.169.in-addr.arpa.",
    "2.0.192.in-addr.arpa.",
    "100.51.198.in-addr.arpa.",
    "113.0.203.in-addr.arpa.",
    "255.255.255.255.in-addr.arpa.",
    "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
    "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
    "d.f.ip6.arpa.",
    "8.e.f.ip6.arpa.",
    "9.e.f.ip6.arpa.",
    "a.e.f.ip6.arpa.",
    "b.e.f.ip6.arpa.",
    "8.b.d.0.1.0.0.2.ip6.arpa.",
];

/// `localhost` and every name below it: the loopback addresses (RFC 6761,
/// section 6.3).
const LOCALHOST: &str = "localhost.";

/// RFC 7793: the shared address space 100.64.0.0/10.
const SHARED_ADDRESS_SPACE: std::ops::RangeInclusive<u8> = 64..=127;

static ZONES: LazyLock<Vec<Name>> = LazyLock::new(|| {
    let shared = SHARED_ADDRESS_SPACE.map(|octet| format!("{octet}.100.in-addr.arpa."));
    EMPTY_ZONES
        .iter()
        .map(|zone| (*zone).to_owned())
        .chain(shared)
        .filter_map(|zone| zone.parse().ok())
        .collect()
});

static LOCALHOST_ZONE: LazyLock<Option<Name>> = LazyLock::new(|| LOCALHOST.parse().ok());

/// goethite's own answer to `query` if it is for such a name.
pub(super) fn answer(query: &Query) -> Option<Response> {
    let name = &query.question.name;
    if let Some(localhost) = LOCALHOST_ZONE.as_ref()
        && name.is_within(localhost)
    {
        let mut response = Response::for_query(query, ResponseCode::NO_ERROR);
        response.recursion_available = true;
        match query.question.qtype {
            RecordType::A => {
                response
                    .answers
                    .push(Record::a(name.clone(), TTL, Ipv4Addr::LOCALHOST));
            }
            RecordType::AAAA => {
                response
                    .answers
                    .push(Record::aaaa(name.clone(), TTL, Ipv6Addr::LOCALHOST));
            }
            _ => response.authority.push(soa(localhost)),
        }
        return Some(response);
    }
    let zone = ZONES.iter().find(|zone| name.is_within(zone))?;
    let mut response = Response::for_query(query, ResponseCode::NX_DOMAIN);
    response.recursion_available = true;
    response.authority.push(soa(zone));
    Some(response)
}

/// An SOA record for `zone`, so the answer can be cached.
fn soa(zone: &Name) -> Record {
    Record::soa(zone.clone(), TTL, zone.clone(), TTL)
}

#[cfg(test)]
mod tests {
    use goethite_proto::{Edns, Question, RecordClass};

    use super::*;

    fn query(name: &str, qtype: RecordType) -> Query {
        Query {
            id: 1,
            recursion_desired: true,
            checking_disabled: false,
            authentic_data: false,
            question: Question {
                name: name.parse().unwrap(),
                qtype,
                qclass: RecordClass::IN,
            },
            edns: Some(Edns::ours()),
        }
    }

    #[test]
    fn special_names_stay_home() {
        let localhost = answer(&query("db.localhost.", RecordType::A)).unwrap();
        assert_eq!(localhost.answers[0].ip(), Some(Ipv4Addr::LOCALHOST.into()));
        let v6 = answer(&query("localhost.", RecordType::AAAA)).unwrap();
        assert_eq!(v6.answers[0].ip(), Some(Ipv6Addr::LOCALHOST.into()));
        let mx = answer(&query("localhost.", RecordType::MX)).unwrap();
        assert_eq!(mx.rcode, ResponseCode::NO_ERROR);
        assert!(mx.answers.is_empty() && mx.authority.len() == 1);

        for name in [
            "printer.home.arpa.",
            "x.onion.",
            "nas.local.",
            "1.1.168.192.in-addr.arpa.",
            "4.3.2.10.in-addr.arpa.",
            "9.9.31.172.in-addr.arpa.",
            "1.0.64.100.in-addr.arpa.",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
        ] {
            let response = answer(&query(name, RecordType::PTR)).unwrap();
            assert_eq!(response.rcode, ResponseCode::NX_DOMAIN, "{name}");
            assert_eq!(response.authority[0].record_type(), RecordType::SOA);
        }
        for name in [
            "example.com.",
            "1.1.1.1.in-addr.arpa.",
            "1.0.32.172.in-addr.arpa.",
            "1.0.128.100.in-addr.arpa.",
            "localhost.example.",
        ] {
            assert!(answer(&query(name, RecordType::A)).is_none(), "{name}");
        }
    }
}
