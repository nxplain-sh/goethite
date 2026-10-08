//! The query log writer, end to end: events in, search and statistics out.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers; the no-panic rules cover non-test code"
)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use goethite_filter::{Action, Match, Scope, Source};
use goethite_store::{
    LogEvent, NameBuf, Protocol, QueryEntry, QueryLogConfig, QueryOutcome, RuleHit, Search, Store,
};
use jiff::Timestamp;

fn temp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "goethite-querylog-{name}-{}-{}.redb",
        std::process::id(),
        Timestamp::now().as_nanosecond().unsigned_abs()
    ))
}

fn event(name: &str, client: &str, outcome: QueryOutcome) -> LogEvent {
    LogEvent {
        time: Timestamp::now(),
        client: client.parse().unwrap(),
        protocol: Protocol::Udp,
        name: NameBuf::new(&name.parse().unwrap()),
        qtype: 1,
        rcode: 0,
        outcome,
        upstream: (outcome == QueryOutcome::Forwarded).then_some(0),
        rule: (outcome == QueryOutcome::Blocked).then(|| RuleHit {
            action: Action::Block,
            matched: Match {
                source: Source::new(1).unwrap(),
                scope: Scope::Subtree,
                labels: 2,
            },
            source: Some("li_ads".into()),
            cname: None,
        }),
        client_id: None,
        group: Some("default".into()),
        elapsed: Duration::from_micros(250),
    }
}

/// Searches until `want` entries show up, or fails after five seconds.
fn wait_for(store: &Store, search: &Search, want: usize) -> Vec<QueryEntry> {
    let start = Instant::now();
    loop {
        let page = store.search_queries(search).unwrap();
        if page.entries.len() >= want {
            return page.entries;
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "only {:?}",
            page.entries
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn search(limit: usize) -> Search {
    Search {
        limit,
        ..Search::default()
    }
}

#[test]
fn logs_searches_and_counts() {
    let path = temp("search");
    let store = Arc::new(Store::open(&path).unwrap());
    let log = store
        .start_query_log(QueryLogConfig::default(), vec!["9.9.9.9:853".into()])
        .unwrap();
    log.record(event(
        "www.example.com.",
        "192.0.2.1",
        QueryOutcome::Forwarded,
    ));
    log.record(event("x.ads.example.", "192.0.2.2", QueryOutcome::Blocked));
    log.record(event("www.example.com.", "192.0.2.1", QueryOutcome::Cached));

    let entries = wait_for(&store, &search(10), 3);
    assert_eq!(entries[0].outcome, QueryOutcome::Cached, "newest first");
    assert!(entries[0].id > entries[1].id);
    assert_eq!(entries[2].upstream.as_deref(), Some("9.9.9.9:853"));
    assert_eq!(entries[1].rule.as_deref(), Some("||ads.example^"));
    assert_eq!(entries[1].list.as_deref(), Some("li_ads"));

    let blocked = store
        .search_queries(&Search {
            outcome: Some(QueryOutcome::Blocked),
            ..search(10)
        })
        .unwrap();
    assert_eq!(blocked.entries.len(), 1);
    let by_client = store
        .search_queries(&Search {
            client: Some("192.0.2.1".into()),
            name: Some("EXAMPLE.COM".into()),
            ..search(10)
        })
        .unwrap();
    assert_eq!(by_client.entries.len(), 2);
    // Paging: one at a time, following the cursor.
    let first = store.search_queries(&search(1)).unwrap();
    let second = store
        .search_queries(&Search {
            before: first.next,
            ..search(1)
        })
        .unwrap();
    assert_eq!(second.entries[0].id, entries[1].id);
    let last = store
        .search_queries(&Search {
            before: Some(entries[2].id),
            ..search(10)
        })
        .unwrap();
    assert_eq!((last.entries.len(), last.next), (0, None));

    let stats = log.stats(24);
    assert_eq!(stats.totals.queries, 3);
    assert_eq!(stats.totals.blocked, 1);
    assert_eq!(stats.top_names[0].key, "www.example.com.");
    assert_eq!(stats.top_names[0].count, 2);
    assert_eq!(stats.top_blocked[0].key, "x.ads.example.");
    assert_eq!(stats.top_clients[0].key, "192.0.2.1");
    assert_eq!(log.dropped(), 0);
    assert_eq!(store.query_log_len().unwrap(), 3);

    drop(log);
    drop(store);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn anonymized_and_disabled_logs() {
    let path = temp("anon");
    let store = Arc::new(Store::open(&path).unwrap());
    let log = store
        .start_query_log(
            QueryLogConfig {
                anonymize: true,
                ..QueryLogConfig::default()
            },
            Vec::new(),
        )
        .unwrap();
    log.record(event("a.example.", "192.0.2.77", QueryOutcome::Forwarded));
    let entries = wait_for(&store, &search(1), 1);
    assert_eq!(entries[0].client, "192.0.2.0");
    drop(log);
    drop(store);
    let _ = std::fs::remove_file(&path);

    let path = temp("off");
    let store = Arc::new(Store::open(&path).unwrap());
    let log = store
        .start_query_log(
            QueryLogConfig {
                enabled: false,
                ..QueryLogConfig::default()
            },
            Vec::new(),
        )
        .unwrap();
    log.record(event("a.example.", "192.0.2.77", QueryOutcome::Forwarded));
    let start = Instant::now();
    while log.stats(1).totals.queries == 0 {
        assert!(start.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(store.query_log_len().unwrap(), 0, "counted, not logged");
    drop(log);
    drop(store);
    let _ = std::fs::remove_file(&path);
}
