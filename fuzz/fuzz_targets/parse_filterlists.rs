//! Fuzz target: reading the FilterLists directory, third-party JSON the
//! node fetches when someone browses it: `/lists`, `/lists/{id}`, and the
//! names of syntaxes, tags and licenses.
//!
//! Invariants checked on every input:
//! - nothing panics;
//! - every list kept is in a syntax goethite reads, named, and bounded;
//! - every address kept is `https://`, bounded and free of control
//!   characters.

#![no_main]

use goethite_api::catalog;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The same bytes as every input, and a fixed set of names.
    let names = catalog::parse_names(
        br#"[{"id": 1, "name": "Hosts"}, {"id": 2, "name": "Domains"}]"#,
        br#"[{"id": 2, "name": "ads"}]"#,
        b"[]",
    )
    .expect("fixed names parse");
    let _ = catalog::parse_names(data, data, data);
    if let Ok(lists) = catalog::parse_lists(data, &names) {
        assert!(lists.len() <= catalog::MAX_LISTS);
        for list in &lists {
            assert!(!list.name.is_empty() && list.name.chars().count() <= 200);
            assert!(list.description.chars().count() <= 1_000);
            assert!(list.name.chars().chain(list.description.chars()).all(|c| !c.is_control()));
        }
        assert!(lists.windows(2).all(|pair| pair[0].name.to_lowercase() <= pair[1].name.to_lowercase()));
    }
    if let Ok(list) = catalog::parse_list(data, &names) {
        assert!(list.urls.len() <= 32);
        for url in &list.urls {
            let scheme = url.url.get(..8).unwrap_or_default();
            assert!(scheme.eq_ignore_ascii_case("https://"), "{}", url.url);
            assert!(url.url.len() <= 2_048 && !url.url.chars().any(char::is_control));
            assert!(url.segment >= 1);
        }
    }
});
