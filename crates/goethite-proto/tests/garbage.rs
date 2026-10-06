//! Arbitrary bytes must never make the decoder panic, hang or misbehave.

mod strategies;

use goethite_proto::{DnsCodec, HickoryCodec};
use proptest::prelude::*;

/// The fuzz target's invariant: decoding never panics, and anything that
/// decodes re-encodes to something that decodes to the same query.
fn check(wire: &[u8]) -> Result<(), TestCaseError> {
    let fail = |e: &dyn std::fmt::Display| TestCaseError::fail(e.to_string());
    if let Ok(query) = HickoryCodec.decode_query(wire) {
        let mut reencoded = Vec::new();
        HickoryCodec
            .encode_query(&query, &mut reencoded)
            .map_err(|e| fail(&e))?;
        let again = HickoryCodec
            .decode_query(&reencoded)
            .map_err(|e| fail(&e))?;
        prop_assert_eq!(again, query);
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn random_bytes(wire in prop::collection::vec(any::<u8>(), 0..1024)) {
        check(&wire)?;
    }

    /// Random bytes behind a header that passes the cheap checks, so the
    /// full parser actually runs.
    #[test]
    fn random_body_behind_a_plausible_header(
        id in any::<u16>(),
        additional in 0..=2_u8,
        body in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let mut wire = id.to_be_bytes().to_vec();
        wire.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, additional]);
        wire.extend_from_slice(&body);
        check(&wire)?;
    }

    /// Valid queries with some bytes overwritten.
    #[test]
    fn mutated_queries(
        query in strategies::query(),
        mutations in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..8),
    ) {
        let mut wire = Vec::new();
        HickoryCodec.encode_query(&query, &mut wire).unwrap();
        for (index, byte) in mutations {
            let at = index.index(wire.len());
            wire[at] = byte;
        }
        check(&wire)?;
    }
}

#[test]
fn compression_pointer_loop_is_rejected() {
    // Header (one question), then a name that is a pointer to itself.
    let mut wire = vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    wire.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
    assert!(HickoryCodec.decode_query(&wire).is_err());

    // A name whose pointer points forward to another pointer back to it.
    let mut wire = vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    wire.extend_from_slice(&[0xc0, 18, 0, 1, 0, 1, 0xc0, 12]);
    assert!(HickoryCodec.decode_query(&wire).is_err());
}

#[test]
fn huge_header_counts_do_not_allocate_or_parse() {
    let wire = [0, 1, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let err = HickoryCodec.decode_query(&wire).unwrap_err();
    assert!(err.response().is_some(), "answered with FORMERR");
}
