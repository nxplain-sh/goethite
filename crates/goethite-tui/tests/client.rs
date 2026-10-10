//! The TUI's API client against a real API server on a temporary store.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test helpers; the no-panic rules cover non-test code"
)]

use std::sync::Arc;
use std::time::SystemTime;

use goethite_api::{
    Api, ApiConfig, ApiListeners, BoxFuture, Change, Control, FilterStatus, QueryLogStatus, Status,
    generate_token,
};
use goethite_store::{List, ListSpec, ManagedBy, QueryLogConfig, Store};
use goethite_tui::{Client, ClientError};
use hyper::Method;
use jiff::Timestamp;

struct Idle;

impl Control for Idle {
    fn status(&self) -> Status {
        Status {
            version: "test".into(),
            started_at: Timestamp::UNIX_EPOCH,
            protection: true,
            paused_until: None,
            filter: FilterStatus {
                rules: 0,
                memory_bytes: 0,
            },
            lists: Vec::new(),
            upstreams: Vec::new(),
            recursion: None,
            cache: None,
            query_log: QueryLogStatus {
                enabled: true,
                entries: 0,
                dropped: 0,
            },
            cluster: None,
            encrypted: None,
            api_docs: false,
            problems: Vec::new(),
        }
    }
    fn apply(&self, _change: Change) -> BoxFuture<'_> {
        Box::pin(async {})
    }
    fn refresh_lists(&self) {}
    fn pause(&self, _until: Option<SystemTime>) {}
    fn paused_until(&self) -> Option<SystemTime> {
        None
    }
    fn metrics(&self) -> String {
        String::new()
    }
}

#[tokio::test]
async fn talks_to_the_api() {
    let path = std::env::temp_dir().join(format!("goethite-tui-{}.redb", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let store = Arc::new(Store::open(&path).unwrap());
    let log = store
        .start_query_log(QueryLogConfig::default(), Vec::new())
        .unwrap();
    let (token, hash) = generate_token();
    let api = Arc::new(Api::new(
        store,
        log,
        Arc::new(Idle),
        ApiConfig {
            token: Some(hash),
            tls: None,
            web: None,
            docs: None,
        },
    ));
    let listeners = ApiListeners::bind(&["127.0.0.1:0".parse().unwrap()]).unwrap();
    let url = format!("http://{}", listeners.local_addrs().unwrap()[0]);
    tokio::spawn(goethite_api::serve(listeners, api, std::future::pending()));

    let client = Client::new(&url, Some(token), None).unwrap();
    let status: Status = client.get("/api/v1/status").await.unwrap();
    assert_eq!(status.version, "test");

    let spec = ListSpec {
        name: "Ads".into(),
        url: Some("https://lists.example/ads.txt".into()),
        path: None,
        enabled: true,
        comment: String::new(),
        managed_by: ManagedBy::Api,
    };
    let created: List = client
        .send(Method::POST, "/api/v1/lists", Some(&spec), None)
        .await
        .unwrap();
    let mut off = spec.clone();
    off.enabled = false;
    let item = format!("/api/v1/lists/{}", created.id);
    let updated: List = client
        .send(Method::PUT, &item, Some(&off), Some(created.revision))
        .await
        .unwrap();
    assert!(!updated.spec.enabled);
    let stale = client
        .send::<_, List>(Method::PUT, &item, Some(&spec), Some(created.revision))
        .await;
    assert!(
        matches!(stale, Err(ClientError::Api { status: 412, ref code, .. }) if code == "revision_mismatch"),
        "{stale:?}"
    );
    client
        .send_empty::<()>(Method::POST, "/api/v1/lists/refresh", None)
        .await
        .unwrap();

    let anonymous = Client::new(&url, None, None).unwrap();
    let refused = anonymous.get::<Status>("/api/v1/status").await;
    assert!(
        matches!(refused, Err(ClientError::Api { status: 401, .. })),
        "{refused:?}"
    );
    let nobody = Client::new("http://127.0.0.1:9", None, None).unwrap();
    assert!(matches!(
        nobody.get::<Status>("/api/v1/status").await,
        Err(ClientError::Connect { .. })
    ));
    let _ = std::fs::remove_file(&path);
}
