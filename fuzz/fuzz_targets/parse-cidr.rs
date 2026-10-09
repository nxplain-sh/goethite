//! Fuzz target: parsing client networks (`192.168.1.0/24`) from the config
//! and the API.
//!
//! Invariants checked on every input:
//! - parsing never panics;
//! - a parsed network displays as text that parses back to the same
//!   network, and contains its own address.

#![no_main]

use goethite_resolver::Cidr;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(network) = text.parse::<Cidr>() else {
        return;
    };
    let shown = network.to_string();
    let again: Cidr = shown
        .parse()
        .expect("the display of a parsed network parses back");
    assert_eq!(again, network);
    assert!(network.contains(network.addr()));
});
