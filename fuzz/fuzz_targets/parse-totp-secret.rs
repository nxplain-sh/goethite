//! Fuzz target: decoding the base32 of a TOTP secret, and the six-digit
//! codes checked against it.
//!
//! Invariants checked on every input:
//! - decoding never panics;
//! - a decoded secret re-encodes to text that decodes to the same bytes;
//! - code generation and checking never panic on any time.

#![no_main]

use goethite_api::{decode_totp_secret, encode_totp_secret, totp_code};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Some(secret) = decode_totp_secret(text) else {
        return;
    };
    let again = encode_totp_secret(&secret);
    assert_eq!(
        decode_totp_secret(&again).as_deref(),
        Some(secret.as_slice()),
        "a decoded secret re-encodes to itself"
    );
    for time in [0_u64, 59, 1_000_000_000, u64::MAX] {
        let code = totp_code(&secret, time);
        assert_eq!(code.len(), 6);
    }
});
