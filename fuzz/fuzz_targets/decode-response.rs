//! Fuzz target: decoding untrusted bytes as an upstream response.
//!
//! Invariants checked on every input:
//! - decoding never panics;
//! - a decoded response re-encodes, and the result decodes to the same
//!   response, which is what forwarding relies on.

#![no_main]

use goethite_proto::{DnsCodec, HickoryCodec};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let codec = HickoryCodec;
    let Ok(response) = codec.decode_response(data) else {
        return;
    };
    let mut out = Vec::new();
    codec
        .encode_response(&response, usize::from(u16::MAX), &mut out)
        .expect("a decoded response re-encodes");
    let again = codec
        .decode_response(&out)
        .expect("a re-encoded response decodes");
    assert_eq!(again, response);
});
