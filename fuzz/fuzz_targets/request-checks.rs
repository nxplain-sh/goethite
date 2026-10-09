//! Fuzz target: the checks on every API request's `Host` and `Origin`
//! headers and on the paths of web UI files.
//!
//! Invariants checked on every input:
//! - the checks never panic;
//! - a `Host` taken for loopback names this machine, with at most a
//!   numeric port after it;
//! - the authority taken from an `Origin` has no path;
//! - a path taken as a plain file path cannot leave the UI's folder.

#![no_main]

use goethite_api::fuzzing::{is_loopback_authority, is_plain, origin_authority};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if is_loopback_authority(text) {
        assert!(
            !text.contains(['/', '@', '?', '#', '\\', ' ']),
            "{text:?} has more than a name and a port"
        );
        let lower = text.to_ascii_lowercase();
        assert!(
            lower.starts_with("localhost")
                || lower.split(':').next().is_some_and(|name| name.ends_with(".localhost"))
                || lower.starts_with("127.")
                || lower.starts_with('['),
            "{text:?} is not a loopback name"
        );
    }
    if let Some(authority) = origin_authority(text) {
        assert!(!authority.is_empty() && !authority.contains('/'));
        assert!(text.ends_with(authority));
    }
    if is_plain(text) {
        assert!(!text.starts_with('/') && !text.contains(['\\', '%']));
        assert!(
            text.split('/')
                .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
        );
    }
});
