//! Fuzz target: parsing and compiling an untrusted filter list.
//!
//! Invariants checked on every input:
//! - parsing and compiling never panic;
//! - for every parsed rule's name, its parent and a child, the compiled
//!   filter gives the same verdict as the rule-by-rule reference, for every
//!   source and for a few sets of sources. Lines are spread over four
//!   sources by position.

#![no_main]

use goethite_filter::{FilterBuilder, Rule, Source, Sources, parse_line, reference_check};
use goethite_proto::Name;
use libfuzzer_sys::fuzz_target;

/// Keeps the reference check (quadratic) cheap.
const MAX_RULES: usize = 256;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let sources = [0, 1, 2, 63].map(|i| Source::new(i).expect("valid source"));
    let mut rules: Vec<(Source, Rule)> = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let source = sources[number % sources.len()];
        parse_line(line, |rule| {
            if rules.len() < MAX_RULES {
                rules.push((source, rule));
            }
        });
    }
    let mut builder = FilterBuilder::new();
    for (source, rule) in &rules {
        builder.add_rule(*source, rule);
    }
    // Also exercise the list path on the raw text.
    FilterBuilder::new().add_list(sources[0], &text);
    let filter = builder.build().expect("rules from the parser compile");

    let masks = [
        Sources::ALL,
        Sources::NONE,
        Sources::NONE.with(sources[0]),
        Sources::NONE.with(sources[1]).with(sources[3]),
    ];
    for (_, rule) in &rules {
        let own = rule.name.clone();
        let parent = Name::from_labels(own.labels().skip(1)).expect("a parent is a valid name");
        let child = Name::from_labels(std::iter::once(&b"x"[..]).chain(own.labels()));
        for query in [Some(own), Some(parent), child.ok()].into_iter().flatten() {
            for mask in masks {
                assert_eq!(
                    filter.check(&query, mask),
                    reference_check(&rules, &query, mask),
                    "{query} {mask:?}"
                );
            }
        }
    }
});
