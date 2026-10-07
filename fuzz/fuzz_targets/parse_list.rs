//! Fuzz target: parsing and compiling an untrusted filter list.
//!
//! Invariants checked on every input:
//! - parsing and compiling never panic;
//! - for every parsed rule's name, its parent and a child, the compiled
//!   filter gives the same verdict as the rule-by-rule reference.

#![no_main]

use goethite_filter::{FilterBuilder, Rule, parse_line, reference_check};
use goethite_proto::Name;
use libfuzzer_sys::fuzz_target;

/// Keeps the reference check (quadratic) cheap.
const MAX_RULES: usize = 256;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let mut rules: Vec<Rule> = Vec::new();
    for line in text.lines() {
        parse_line(line, |rule| {
            if rules.len() < MAX_RULES {
                rules.push(rule);
            }
        });
    }
    let mut builder = FilterBuilder::new();
    for rule in &rules {
        builder.add_rule(rule);
    }
    // Also exercise the list path on the raw text.
    FilterBuilder::new()
        .add_list(&text);
    let filter = builder.build().expect("rules from the parser compile");

    for rule in &rules {
        let own = rule.name.clone();
        let parent = Name::from_labels(own.labels().skip(1)).expect("a parent is a valid name");
        let child = Name::from_labels(std::iter::once(&b"x"[..]).chain(own.labels()));
        for query in [Some(own), Some(parent), child.ok()].into_iter().flatten() {
            assert_eq!(filter.check(&query), reference_check(&rules, &query), "{query}");
        }
    }
});
