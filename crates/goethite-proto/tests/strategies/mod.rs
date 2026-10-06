//! Proptest strategies shared by the integration tests.

use goethite_proto::{Edns, Name, Query, Question, RecordClass, RecordType};
use proptest::prelude::*;

/// Any valid name, with arbitrary label bytes and mixed case.
pub fn name() -> impl Strategy<Value = Name> {
    prop::collection::vec(prop::collection::vec(any::<u8>(), 1..=63), 0..=8)
        .prop_filter_map("name longer than 255 bytes", |labels| {
            Name::from_labels(labels.iter().map(Vec::as_slice)).ok()
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
