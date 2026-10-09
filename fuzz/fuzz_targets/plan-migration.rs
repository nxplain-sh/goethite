//! Fuzz target: planning a migration from what a Pi-hole or an AdGuard Home
//! answers, untrusted JSON. The first byte picks the source (even: Pi-hole,
//! odd: AdGuard Home); the rest is its answers. The input as text also goes
//! through Pi-hole's CNAME record parser.
//!
//! Invariants checked on every input:
//! - nothing panics, the report included;
//! - the plan holds only what goethite's store would accept: HTTPS lists
//!   within the limits, rules goethite supports, records it can answer
//!   with a CNAME alone at its name, clients with a valid address or client
//!   ID, unique group and client names, valid access entries.

#![no_main]

use std::collections::{HashMap, HashSet};

use goethite_filter::{LineKind, parse_line};
use goethite_migrate::{adguard, pihole};
use goethite_resolver::{Cidr, is_client_id};
use goethite_store::RecordKind;
use goethite_store::model::{MAX_LISTS, MAX_NAME_LEN, MAX_RECORD_TTL, MAX_SOURCE_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&source, json)) = data.split_first() else {
        return;
    };
    if let Ok(text) = std::str::from_utf8(json) {
        if let Some((aliases, target, _)) = pihole::cname_record(text) {
            assert!(!aliases.is_empty() && !target.is_empty());
        }
    }
    let plan = if source % 2 == 0 {
        let Ok(export) = serde_json::from_slice::<pihole::Export>(json) else {
            return;
        };
        export.plan()
    } else {
        let Ok(export) = serde_json::from_slice::<adguard::Export>(json) else {
            return;
        };
        export.plan()
    };
    let _ = plan.report();

    assert!(plan.lists.len() <= MAX_LISTS);
    let mut urls = HashSet::new();
    for list in &plan.lists {
        let url = list.url.as_deref().unwrap();
        assert!(url.starts_with("https://") && url.len() <= MAX_SOURCE_LEN);
        assert!(urls.insert(url));
        assert!(!list.name.trim().is_empty() && list.name.chars().count() <= MAX_NAME_LEN);
    }
    for url in plan.default_lists.iter().chain(plan.groups.iter().flat_map(|g| &g.lists)) {
        assert!(urls.contains(url.as_str()), "a group uses a list the plan does not add");
    }
    for rule in &plan.rules {
        assert!(matches!(parse_line(&rule.rule, |_| {}), LineKind::Rules(_)));
    }
    let mut enabled: HashMap<&str, (usize, bool)> = HashMap::new();
    for record in &plan.records {
        assert!(record.local().is_some(), "a record goethite cannot answer");
        assert!(record.ttl <= MAX_RECORD_TTL);
        if record.enabled {
            let (count, cname) = enabled.entry(record.name.as_str()).or_default();
            *count += 1;
            *cname |= record.kind == RecordKind::Cname;
            assert!(!(*cname && *count > 1), "a CNAME with another record");
        }
    }
    let groups: HashSet<&str> = plan.groups.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(groups.len(), plan.groups.len(), "group names repeat");
    let clients: HashSet<&str> = plan.clients.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(clients.len(), plan.clients.len(), "client names repeat");
    for client in &plan.clients {
        assert!(!client.addresses.is_empty() || !client.ids.is_empty());
        assert!(client.addresses.iter().all(|a| a.parse::<Cidr>().is_ok()));
        assert!(client.ids.iter().all(|id| is_client_id(id)));
        if let Some(group) = &client.group {
            assert!(groups.contains(group.as_str()));
        }
    }
    for entry in plan.access.allowed.iter().chain(&plan.access.blocked) {
        assert!(entry.parse::<Cidr>().is_ok() || is_client_id(entry), "{entry}");
    }
});

