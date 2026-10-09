//! Fuzz target: reading a DNS over QUIC stream, everything a client sent
//! on one stream: a 2-byte length and a DNS message with ID 0.
//!
//! Invariants checked on every input:
//! - nothing panics;
//! - an accepted message is exactly what the length says, ends the stream,
//!   and has ID 0 (or is too short to have one).

#![no_main]

use goethite_server::doq;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(message) = doq::query(data) else {
        return;
    };
    assert_eq!(message.len() + 2, data.len());
    assert_eq!(
        usize::from(u16::from_be_bytes([data[0], data[1]])),
        message.len()
    );
    assert!(message.len() < 2 || message[..2] == [0, 0]);
});
