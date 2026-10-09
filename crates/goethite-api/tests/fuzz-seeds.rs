//! The committed `request_checks` fuzz seeds behave the way their names
//! say, so they keep steering the fuzzer at both sides of each check.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the no-panic rules cover non-test code"
)]

use goethite_api::fuzzing::{is_loopback_authority, is_plain, origin_authority};

#[test]
fn request_check_seeds() {
    let dir = format!(
        "{}/../../fuzz/seeds/request_checks",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut seen = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        let text = std::fs::read_to_string(&path).unwrap();
        match name.as_str() {
            n if n.starts_with("host-") => assert!(is_loopback_authority(&text), "{name}"),
            "origin" => assert!(origin_authority(&text).is_some(), "{name}"),
            "path-asset" => assert!(is_plain(&text), "{name}"),
            "path-climb" => assert!(!is_plain(&text), "{name}"),
            _ => panic!("unexpected seed {name}: say here what it should do"),
        }
        seen += 1;
    }
    assert!(seen >= 7);
}
