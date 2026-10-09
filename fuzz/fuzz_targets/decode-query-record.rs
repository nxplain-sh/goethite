//! Fuzz target: decoding query log records read back from the store.
//!
//! The store is goethite's own file, but a damaged or tampered one must not
//! crash it. Invariants checked on every input:
//! - decoding never panics;
//! - a decoded record encodes back to bytes that decode to the same record.

#![no_main]

use goethite_store::querylog::{decode, encode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some(record) = decode(data) else {
        return;
    };
    let again = decode(&encode(&record)).expect("an encoded record decodes");
    assert_eq!(again, record);
});
