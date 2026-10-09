//! Fuzz target: DNSSEC validation's checks on an authoritative server's
//! response (`goethite_resolver::recurse::check_dnssec`): RRSIG, DNSKEY,
//! DS, NSEC and NSEC3 records read from the wire, signatures verified,
//! and the proofs of denial, NSEC3 hashing included.
//!
//! Invariants checked on every input that decodes as a response:
//! - nothing panics;
//! - at most `MAX_EVIDENCE` records are kept, and at most `MAX_CHECKS`
//!   signature checks are spent, whatever the response holds.

#![no_main]

use goethite_proto::{DnsCodec, HickoryCodec, Name, RecordType};
use goethite_resolver::recurse::check_dnssec;
use libfuzzer_sys::fuzz_target;

/// `MAX_EVIDENCE` and `MAX_CHECKS` in the validator.
const MAX_EVIDENCE: usize = 128;
const MAX_CHECKS: u32 = 64;

fuzz_target!(|data: &[u8]| {
    let Ok(response) = HickoryCodec.decode_response(data) else {
        return;
    };
    let asked = response
        .question
        .as_ref()
        .map_or_else(Name::root, |question| question.name.clone());
    // As a server of the name's zone and of its parent.
    for labels in [asked.label_count(), asked.label_count().saturating_sub(1)] {
        let Some(zone) = asked.suffix(labels) else {
            continue;
        };
        for qtype in [RecordType::A, RecordType::DS] {
            let (evidence, checks) = check_dnssec(&response, &zone, &asked, qtype);
            assert!(evidence <= MAX_EVIDENCE);
            assert!(checks <= MAX_CHECKS);
        }
    }
});
