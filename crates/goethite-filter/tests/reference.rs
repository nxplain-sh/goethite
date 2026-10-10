//! The compiled filter must agree with the rule-by-rule reference.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use goethite_filter::{
    Action, FilterBuilder, Rule, Scope, Source, Sources, Verdict, reference_check,
};
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

/// A few sources, so rules from different sources share names.
fn source() -> impl Strategy<Value = Source> {
    prop::sample::select(vec![0_usize, 1, 2, 63]).prop_map(|i| Source::new(i).unwrap())
}

fn sources() -> impl Strategy<Value = Sources> {
    prop::collection::vec(source(), 0..4).prop_map(|list| list.into_iter().collect())
}

fn rule() -> impl Strategy<Value = (Source, Rule)> {
    (
        source(),
        name(),
        prop::sample::select(vec![Scope::Exact, Scope::Subtree, Scope::Subdomains]),
        prop::sample::select(vec![Action::Block, Action::Block, Action::Allow]),
        prop::sample::select(vec![false, true]),
        prop::sample::select(vec![false, false, false, true]),
    )
        .prop_map(
            |(source, name, scope, action, important, badfilter)| {
                (
                    source,
                    Rule {
                        name,
                        scope,
                        action,
                        important,
                        badfilter,
                    },
                )
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn compiled_filter_agrees_with_the_reference(
        rules in prop::collection::vec(rule(), 0..40),
        queries in prop::collection::vec(name(), 1..40),
        masks in prop::collection::vec(sources(), 1..4),
    ) {
        let mut builder = FilterBuilder::new();
        for (source, rule) in &rules {
            builder.add_rule(*source, rule);
        }
        let filter = builder.build().unwrap();
        let mut masks = masks;
        masks.push(Sources::ALL);
        // Every rule's own name, its parent and a child are interesting too.
        let mut all = queries;
        for (_, rule) in &rules {
            let own = rule.name.clone();
            all.push(Name::from_labels(std::iter::once(&b"child"[..]).chain(own.labels())).unwrap());
            all.push(Name::from_labels(own.labels().skip(1)).unwrap());
            all.push(own);
        }
        for query in &all {
            for &mask in &masks {
                prop_assert_eq!(
                    filter.check(query, mask),
                    reference_check(&rules, query, mask),
                    "{} {:?}", query, mask
                );
            }
        }
    }

    #[test]
    fn query_case_does_not_matter(rules in prop::collection::vec(rule(), 1..20), query in name()) {
        let mut builder = FilterBuilder::new();
        for (source, rule) in &rules {
            builder.add_rule(*source, rule);
        }
        let filter = builder.build().unwrap();
        let shouting = query.with_random_case(|| true);
        prop_assert_eq!(filter.check(&shouting, Sources::ALL), filter.check(&query, Sources::ALL));
    }
}

#[test]
fn an_empty_filter_passes_everything() {
    let filter = FilterBuilder::new().build().unwrap();
    assert_eq!(
        filter.check(&"ads.example".parse().unwrap(), Sources::ALL),
        Verdict::Pass
    );
}
