//! The compiled filter must agree with the rule-by-rule reference.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use goethite_filter::{Action, FilterBuilder, Rule, Scope, Verdict, reference_check};
use goethite_proto::Name;
use proptest::prelude::*;

/// Names over a tiny alphabet, so rules and queries overlap a lot.
fn name() -> impl Strategy<Value = Name> {
    prop::collection::vec(
        prop::sample::select(vec!["a", "b", "ads", "x", "com", "example"]),
        1..5,
    )
    .prop_map(|labels| Name::from_labels(labels.iter().map(|l| l.as_bytes())).unwrap())
}

fn rule() -> impl Strategy<Value = Rule> {
    (
        name(),
        prop::sample::select(vec![Scope::Exact, Scope::Subtree, Scope::Subdomains]),
        prop::sample::select(vec![Action::Block, Action::Block, Action::Allow]),
    )
        .prop_map(|(name, scope, action)| Rule {
            name,
            scope,
            action,
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn compiled_filter_agrees_with_the_reference(
        rules in prop::collection::vec(rule(), 0..40),
        queries in prop::collection::vec(name(), 1..40),
    ) {
        let mut builder = FilterBuilder::new();
        for rule in &rules {
            builder.add_rule(rule);
        }
        let filter = builder.build().unwrap();
        for query in &queries {
            prop_assert_eq!(filter.check(query), reference_check(&rules, query), "{}", query);
        }
        // Every rule's own name, its parent and a child are interesting too.
        for rule in &rules {
            let own = rule.name.clone();
            let child = Name::from_labels(
                std::iter::once(&b"child"[..]).chain(own.labels()),
            )
            .unwrap();
            let parent = Name::from_labels(own.labels().skip(1)).unwrap();
            for query in [own, child, parent] {
                prop_assert_eq!(filter.check(&query), reference_check(&rules, &query), "{}", query);
            }
        }
    }

    #[test]
    fn query_case_does_not_matter(rules in prop::collection::vec(rule(), 1..20), query in name()) {
        let mut builder = FilterBuilder::new();
        for rule in &rules {
            builder.add_rule(rule);
        }
        let filter = builder.build().unwrap();
        let shouting = query.with_random_case(|| true);
        prop_assert_eq!(filter.check(&shouting), filter.check(&query));
    }
}

#[test]
fn an_empty_filter_passes_everything() {
    let filter = FilterBuilder::new().build().unwrap();
    assert_eq!(filter.check(&"ads.example".parse().unwrap()), Verdict::Pass);
}
