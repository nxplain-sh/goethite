//! Fuzz target: decoding untrusted bytes as a DNS query.
//!
//! Invariants checked on every input:
//! - decoding never panics;
//! - a decoded query re-encodes, and the result decodes to the same query
//!   (including the case of the name);
//! - the name displays as printable ASCII only, so it is safe to log;
//! - any response goethite would send fits in a 512-byte UDP datagram.

#![no_main]

use goethite_proto::{DnsCodec, HickoryCodec, MIN_UDP_PAYLOAD, Response, ResponseCode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let codec = HickoryCodec;
    let udp_limit = usize::from(MIN_UDP_PAYLOAD);
    let mut out = Vec::new();

    let response = match codec.decode_query(data) {
        Ok(query) => {
            codec
                .encode_query(&query, &mut out)
                .expect("a decoded query re-encodes");
            let again = codec
                .decode_query(&out)
                .expect("a re-encoded query decodes");
            assert_eq!(again, query);
            let shown = query.question.name.to_string();
            assert_eq!(again.question.name.to_string(), shown);
            assert!(shown.bytes().all(|b| b.is_ascii_graphic()));
            Response::for_query(&query, ResponseCode::REFUSED)
        }
        Err(err) => match err.response() {
            Some(response) => response,
            None => return,
        },
    };
    codec
        .encode_response(&response, udp_limit, &mut out)
        .expect("responses to queries fit in 512 bytes");
    assert!(out.len() <= udp_limit);
});
