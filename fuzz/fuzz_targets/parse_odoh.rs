//! Fuzz target: Oblivious DoH (RFC 9230) messages as a target reads them
//! from a proxy, the plaintext inside them, and configurations as a
//! client reads them.
//!
//! Invariants checked on every input:
//! - nothing panics;
//! - a message that parses is exactly its fields, re-encoded;
//! - a plaintext that parses has a non-empty DNS message and zero padding;
//! - the input never decrypts as a query, even sent to the current key;
//! - a query encrypted to the target decrypts to the DNS message sent.

#![no_main]

use std::sync::OnceLock;

use goethite_server::odoh::{self, OdohKeys, client};
use libfuzzer_sys::fuzz_target;

/// The target's keys, and the current key's ID.
fn keys() -> &'static (OdohKeys, client::Config) {
    static KEYS: OnceLock<(OdohKeys, client::Config)> = OnceLock::new();
    KEYS.get_or_init(|| {
        let keys = OdohKeys::new().expect("keys");
        let config = client::parse_configs(&keys.configs()).expect("own configuration");
        (keys, config)
    })
}

/// `bytes`, prefixed with their length.
fn prefixed(bytes: &[u8]) -> Vec<u8> {
    let mut out = u16::try_from(bytes.len()).expect("short").to_be_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

fuzz_target!(|data: &[u8]| {
    let (keys, config) = keys();
    if let Ok(message) = odoh::parse_message(data) {
        let mut again = vec![message.message_type];
        again.extend(prefixed(message.key_id));
        again.extend(prefixed(message.encrypted));
        assert_eq!(again, data);
    }
    if let Ok(dns) = odoh::parse_plaintext(data) {
        assert!(!dns.is_empty() && dns.len() + 4 <= data.len());
        assert!(data[2 + dns.len() + 2..].iter().all(|&byte| byte == 0));
    }
    let _ = client::parse_configs(data);
    let _ = keys.open(data);
    if !data.is_empty() && data.len() <= usize::from(u16::MAX) {
        let mut wire = vec![1];
        wire.extend(prefixed(config.key_id()));
        wire.extend(prefixed(data));
        assert!(keys.open(&wire).is_err(), "decrypted without the key");
    }
    // Now and then, a real query: it must come back as sent.
    if data.first().is_some_and(|byte| byte & 7 == 0) && data.len() <= 4096 {
        let dns = &data[1..];
        if let Ok((wire, _)) = client::seal_query(config, dns, usize::from(data[0])) {
            let opened = keys.open(&wire).expect("a query for the current key");
            assert_eq!(opened.dns(), dns);
        } else {
            assert!(dns.is_empty());
        }
    }
});
