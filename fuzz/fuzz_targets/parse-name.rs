//! Fuzz target: parsing domain names from text (config today, filter lists
//! and the API later).
//!
//! Invariants checked on every input:
//! - parsing never panics;
//! - a parsed name displays as text that parses back to the same name,
//!   including the case of every label.

#![no_main]

use goethite_proto::Name;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(name) = text.parse::<Name>() else {
        return;
    };
    let shown = name.to_string();
    let again: Name = shown
        .parse()
        .expect("the display of a parsed name parses back");
    assert_eq!(again, name);
    assert_eq!(again.to_string(), shown);
});
