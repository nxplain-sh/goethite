//! Proptest strategies shared by the integration tests.

#![allow(dead_code, reason = "each test crate uses a different subset")]

use std::net::{Ipv4Addr, Ipv6Addr};

use goethite_proto::{Edns, Name, Query, Question, Record, RecordClass, RecordType};
use proptest::prelude::*;

/// Any valid name, with arbitrary label bytes and mixed case.
pub fn name() -> impl Strategy<Value = Name> {
    prop::collection::vec(prop::collection::vec(any::<u8>(), 1..=63), 0..=8)
        .prop_filter_map("name longer than 255 bytes", |labels| {
            Name::from_labels(labels.iter().map(Vec::as_slice)).ok()
        })
}

/// Names made only of what `Name::from_str` accepts: letters, digits, `-`, `_`.
pub fn host_name() -> impl Strategy<Value = Name> {
    prop::collection::vec("[A-Za-z0-9_-]{1,63}", 0..=4)
        .prop_filter_map("name longer than 255 bytes", |labels| {
            Name::from_labels(labels.iter().map(String::as_bytes)).ok()
        })
}

/// Any query goethite can represent. EDNS payload sizes start at 512 because
/// smaller values mean 512 on the wire (RFC 6891).
pub fn query() -> impl Strategy<Value = Query> {
    (
        any::<u16>(),
        any::<(bool, bool, bool)>(),
        name(),
        any::<u16>(),
        any::<u16>(),
        prop::option::of((512..=u16::MAX, any::<bool>())),
    )
        .prop_map(|(id, (rd, cd, ad), name, qtype, qclass, edns)| Query {
            id,
            recursion_desired: rd,
            checking_disabled: cd,
            authentic_data: ad,
            question: Question {
                name,
                qtype: RecordType(qtype),
                qclass: RecordClass(qclass),
            },
            edns: edns.map(|(udp_payload_size, dnssec_ok)| Edns {
                udp_payload_size,
                dnssec_ok,
            }),
        })
}

/// A, AAAA or CNAME records with arbitrary names and TTLs.
pub fn record() -> impl Strategy<Value = Record> {
    (name(), any::<u32>(), 0..3_u8, any::<[u8; 16]>(), name()).prop_map(
        |(owner, ttl, kind, bytes, target)| match kind {
            0 => Record::a(
                owner,
                ttl,
                Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]),
            ),
            1 => Record::aaaa(owner, ttl, Ipv6Addr::from(bytes)),
            _ => Record::cname(owner, ttl, target),
        },
    )
}
