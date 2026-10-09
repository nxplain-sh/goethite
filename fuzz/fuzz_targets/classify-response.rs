//! Fuzz target: what an iterating resolver makes of an authoritative
//! server's response (`goethite_resolver::recurse::classify`), which
//! decides what is believed and what is cached.
//!
//! Invariants checked on every input that decodes as a response:
//! - nothing panics;
//! - a referral is to a zone strictly below the zone asked and containing
//!   the name, with at most `MAX_NAME_SERVERS` servers and glue only for
//!   them, within the zone asked;
//! - answer records are owned by names within the zone asked;
//! - a negative answer's SOA is for a zone within the zone asked that
//!   contains the name.

#![no_main]

use goethite_proto::{DnsCodec, HickoryCodec, Name, RecordType};
use goethite_resolver::recurse::{Kind, MAX_NAME_SERVERS, classify};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(response) = HickoryCodec.decode_response(data) else {
        return;
    };
    let asked = response
        .question
        .as_ref()
        .map_or_else(Name::root, |question| question.name.clone());
    // As a server of each zone from the root down to the name.
    for labels in 0..=asked.label_count() {
        let Some(zone) = asked.suffix(labels) else {
            continue;
        };
        for qtype in [RecordType::A, RecordType::DS, RecordType::ANY] {
            match classify(&response, &zone, &asked, qtype) {
                Kind::Referral {
                    zone: cut,
                    servers,
                    glue,
                    ..
                } => {
                    assert!(cut.is_within(&zone) && cut != zone && asked.is_within(&cut));
                    assert!(!servers.is_empty() && servers.len() <= MAX_NAME_SERVERS);
                    for (server, _, _) in &glue {
                        assert!(servers.contains(server) && server.is_within(&zone));
                    }
                }
                Kind::Answer { records, .. } => {
                    assert!(!records.is_empty());
                    assert!(records.iter().all(|record| record.name().is_within(&zone)));
                }
                Kind::NoData { soa } | Kind::NxDomain { soa } => {
                    if let Some(soa) = soa {
                        assert!(soa.name().is_within(&zone) && asked.is_within(soa.name()));
                    }
                }
                Kind::Lame | Kind::Failed(_) => {}
            }
        }
    }
});
