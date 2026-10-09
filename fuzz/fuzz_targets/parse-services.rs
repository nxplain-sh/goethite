//! Fuzz target: reading the services catalog, third-party JSON the node
//! downloads with the filter lists for groups' blocked services.
//!
//! Invariants checked on every input:
//! - nothing panics;
//! - at most `MAX_SERVICES` services, with valid, distinct IDs and kinds;
//! - names are non-empty, bounded and free of control characters;
//! - every service has 1 to `MAX_RULES_PER_SERVICE` distinct, bounded rules
//!   free of control characters.

#![no_main]

use std::collections::HashSet;

use goethite_api::services::{self, MAX_RULE_LEN, MAX_RULES_PER_SERVICE};
use goethite_resolver::{MAX_SERVICES, is_service_id};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(services) = services::parse_services(data) else {
        return;
    };
    assert!(!services.is_empty() && services.len() <= MAX_SERVICES);
    let mut ids = HashSet::new();
    for service in &services {
        assert!(is_service_id(&service.id) && ids.insert(&service.id));
        assert!(is_service_id(&service.group));
        assert!(!service.name.is_empty() && service.name.chars().count() <= 100);
        assert!(!service.name.chars().any(char::is_control));
        assert!((1..=MAX_RULES_PER_SERVICE).contains(&service.rules.len()));
        let distinct: HashSet<&String> = service.rules.iter().collect();
        assert_eq!(distinct.len(), service.rules.len());
        for rule in &service.rules {
            assert!(!rule.is_empty() && rule.len() <= MAX_RULE_LEN);
            assert!(!rule.chars().any(char::is_control));
        }
    }
});
