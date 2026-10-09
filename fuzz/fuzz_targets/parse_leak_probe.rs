//! Fuzz target: reading a DNS leak test's names out of queries
//! (`goethite_api::leak::parse_probe` and `LeakTests::observe`), which every
//! query's name passes through.
//!
//! Invariants checked on every input that decodes as a query:
//! - nothing panics;
//! - a name read as a test name is exactly `<id>-<n>.leak.goethite.test.`,
//!   with 32 lowercase hex digits and `n` from 1 to `PROBES`, in any case;
//! - only names of a test this node made are recorded, at most
//!   `MAX_LOOKUPS` of them.

#![no_main]

use std::net::{IpAddr, Ipv4Addr};

use goethite_api::leak::{Arrival, LeakTests, MAX_LOOKUPS, PROBES, ZONE, parse_probe};
use goethite_proto::{DnsCodec, HickoryCodec, Name};
use goethite_store::Protocol;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(query) = HickoryCodec.decode_query(data) else {
        return;
    };
    let name = &query.question.name;
    if let Some((id, n)) = parse_probe(name) {
        assert_eq!(id.len(), 32);
        assert!(id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        assert!((1..=PROBES).contains(&n));
        let expected: Name = format!("{id}-{n}.{ZONE}").parse().unwrap();
        assert_eq!(&expected, name);
    }
    let tests = LeakTests::new();
    let test = tests.create(None);
    for _ in 0..2 {
        tests.observe(name, || Arrival {
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            protocol: Protocol::Udp,
            qtype: query.question.qtype,
            client: None,
            group: None,
            filtering: false,
        });
    }
    let seen = tests.get(&test.id).unwrap();
    assert!(seen.lookups.len() <= MAX_LOOKUPS);
    // A random name is never one of a fresh test's.
    assert!(seen.lookups.is_empty() || parse_probe(name).is_some_and(|(id, _)| id == test.id));
});
