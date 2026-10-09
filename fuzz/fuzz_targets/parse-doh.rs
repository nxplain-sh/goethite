//! Fuzz target: reading DNS over HTTPS requests and client IDs: the request
//! target (path and query string), the base64url `dns` parameter, and the
//! client ID in a TLS server name.
//!
//! The input is a request target such as `/dns-query/kid?dns=AAAB`, which
//! doubles as a TLS server name and as the name goethite is reached by.
//!
//! Invariants checked on every input:
//! - nothing panics;
//! - a client ID read from a path or a server name is a valid client ID;
//! - a decoded `dns` parameter is at most three quarters of its length.

#![no_main]

use goethite_resolver::is_client_id;
use goethite_server::doh;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (path, query) = match text.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (text, None),
    };
    if let Ok(Some(id)) = doh::client_id_from_path(path) {
        assert!(is_client_id(id), "{id:?} from the path {path:?}");
    }
    let mut message = Vec::new();
    if doh::decode_get(query, &mut message).is_ok() {
        assert!(message.len() <= doh::MAX_PARAM_LEN * 3 / 4);
    }
    if doh::decode_base64url(text, &mut message).is_ok() {
        assert!(message.len() <= text.len() * 3 / 4);
    }
    for (sni, ours) in [(text, "dns.example"), ("kid.dns.example", text)] {
        if let Some(id) = doh::client_id_from_server_name(sni, ours) {
            assert!(is_client_id(&id), "{id:?} from {sni:?} under {ours:?}");
        }
    }
});
