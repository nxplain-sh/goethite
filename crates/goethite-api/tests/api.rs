//! The API over real HTTP, against a temporary store and a fake data plane.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test helpers; the no-panic rules cover non-test code"
)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use goethite_api::{
    Api, ApiConfig, ApiListeners, BoxFuture, Change, Control, FilterStatus, QueryLogStatus, Status,
    generate_token,
};
use goethite_store::{QueryLogConfig, Store};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::header::{HeaderMap, HeaderValue};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use jiff::Timestamp;
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio::sync::oneshot;

/// A data plane that records what it is asked to do.
#[derive(Default)]
struct FakeControl {
    applied: Mutex<Vec<Change>>,
    paused: Mutex<Option<SystemTime>>,
    refreshed: Mutex<usize>,
}

impl Control for FakeControl {
    fn status(&self) -> Status {
        Status {
            version: "test".into(),
            started_at: Timestamp::UNIX_EPOCH,
            protection: true,
            paused_until: None,
            filter: FilterStatus {
                rules: 42,
                memory_bytes: 1000,
            },
            lists: Vec::new(),
            upstreams: Vec::new(),
            cache: None,
            query_log: QueryLogStatus {
                enabled: true,
                entries: 0,
                dropped: 0,
            },
        }
    }

    fn apply(&self, change: Change) -> BoxFuture<'_> {
        self.applied.lock().unwrap().push(change);
        Box::pin(async {})
    }

    fn refresh_lists(&self) {
        *self.refreshed.lock().unwrap() += 1;
    }

    fn pause(&self, until: Option<SystemTime>) {
        *self.paused.lock().unwrap() = until;
    }

    fn paused_until(&self) -> Option<SystemTime> {
        *self.paused.lock().unwrap()
    }

    fn metrics(&self) -> String {
        "goethite_up 1\n".into()
    }
}

struct Server {
    addr: SocketAddr,
    control: Arc<FakeControl>,
    stop: Option<oneshot::Sender<()>>,
    path: PathBuf,
    token: Option<String>,
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

fn start(with_token: bool) -> Server {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let path = std::env::temp_dir().join(format!(
        "goethite-api-{}-{}.redb",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);
    let store = Arc::new(Store::open(&path).unwrap());
    let log = store
        .start_query_log(QueryLogConfig::default(), Vec::new())
        .unwrap();
    let control = Arc::new(FakeControl::default());
    let (token, hash) = generate_token();
    let api = Arc::new(Api {
        store,
        log,
        control: Arc::clone(&control) as Arc<dyn Control>,
        config: ApiConfig {
            token: with_token.then_some(hash),
            tls: None,
        },
    });
    let listeners = ApiListeners::bind(&["127.0.0.1:0".parse().unwrap()]).unwrap();
    let addr = listeners.local_addrs().unwrap()[0];
    let (stop, stopped) = oneshot::channel::<()>();
    tokio::spawn(goethite_api::serve(listeners, api, async {
        let _ = stopped.await;
    }));
    Server {
        addr,
        control,
        stop: Some(stop),
        path,
        token: with_token.then_some(token),
    }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
    text: String,
}

impl Server {
    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        headers: &[(&str, &str)],
    ) -> Reply {
        self.try_send(method, path, body, headers).await.unwrap()
    }

    async fn try_send(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        headers: &[(&str, &str)],
    ) -> Result<Reply, hyper::Error> {
        let stream = TcpStream::connect(self.addr).await.unwrap();
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        tokio::spawn(connection);
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "goethite.test");
        if let Some(token) = &self.token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let bytes = body.map(|b| b.to_string()).unwrap_or_default();
        if !bytes.is_empty() {
            request = request.header("content-type", "application/json");
        }
        let response = sender
            .send_request(request.body(Full::new(Bytes::from(bytes))).unwrap())
            .await?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await?.to_bytes();
        let text = String::from_utf8_lossy(&body).into_owned();
        Ok(Reply {
            status,
            headers,
            body: serde_json::from_slice(&body).unwrap_or(Value::Null),
            text,
        })
    }

    async fn get(&self, path: &str) -> Reply {
        self.send(Method::GET, path, None, &[]).await
    }

    async fn post(&self, path: &str, body: Value) -> Reply {
        self.send(Method::POST, path, Some(body), &[]).await
    }
}

#[tokio::test]
async fn resources_round_trip_with_revisions_and_references() {
    let server = start(false);
    let created = server
        .post(
            "/api/v1/lists",
            json!({"name": "Ads", "url": "https://lists.example/ads.txt"}),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let id = created.body["id"].as_str().unwrap().to_owned();
    assert_eq!(created.body["revision"], 1);
    assert_eq!(created.body["spec"]["enabled"], true);
    assert_eq!(created.headers["etag"], "\"1\"");
    assert_eq!(created.headers["location"], format!("/api/v1/lists/{id}"));

    let fetched = server.get(&format!("/api/v1/lists/{id}")).await;
    assert_eq!(fetched.status, StatusCode::OK);
    assert_eq!(fetched.body, created.body);
    assert_eq!(
        server
            .get("/api/v1/lists")
            .await
            .body
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // Updates with a stale revision fail; with the current one they succeed.
    let renamed = json!({"name": "Advertising", "url": "https://lists.example/ads.txt"});
    let path = format!("/api/v1/lists/{id}");
    let stale = server
        .send(
            Method::PUT,
            &path,
            Some(renamed.clone()),
            &[("if-match", "\"7\"")],
        )
        .await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(stale.body["error"]["code"], "revision_mismatch");
    let updated = server
        .send(Method::PUT, &path, Some(renamed), &[("if-match", "\"1\"")])
        .await;
    assert_eq!(updated.status, StatusCode::OK, "{}", updated.text);
    assert_eq!(updated.body["revision"], 2);
    assert_eq!(updated.headers["etag"], "\"2\"");

    // A group using the list, and a client in the group.
    let group = server
        .post(
            "/api/v1/groups",
            json!({"name": "Kids", "lists": [{"list": id}], "safe_search": true}),
        )
        .await;
    assert_eq!(group.status, StatusCode::CREATED, "{}", group.text);
    let group_id = group.body["id"].as_str().unwrap().to_owned();
    let client = server
        .post(
            "/api/v1/clients",
            json!({"name": "Tablet", "addresses": ["192.168.1.23"], "group": group_id}),
        )
        .await;
    assert_eq!(client.status, StatusCode::CREATED, "{}", client.text);

    // References are checked both ways.
    let in_use = server.send(Method::DELETE, &path, None, &[]).await;
    assert_eq!(in_use.status, StatusCode::CONFLICT, "{}", in_use.text);
    assert_eq!(in_use.body["error"]["code"], "conflict");
    let dangling = server
        .post(
            "/api/v1/clients",
            json!({"name": "Phone", "addresses": ["192.168.1.24"], "group": "gr_none"}),
        )
        .await;
    assert_eq!(dangling.status, StatusCode::CONFLICT);
    let default_group = server
        .send(Method::DELETE, "/api/v1/groups/default", None, &[])
        .await;
    assert_eq!(default_group.status, StatusCode::CONFLICT);

    // Changes reached the data plane: filter for lists, policy for the rest.
    assert_eq!(
        *server.control.applied.lock().unwrap(),
        [
            Change::Filter,
            Change::Filter,
            Change::Policy,
            Change::Policy
        ]
    );

    // The audit log names the actor.
    let audit = server.get("/api/v1/audit?limit=2").await;
    assert_eq!(audit.status, StatusCode::OK);
    let entries = audit.body.as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["kind"], "client");
    assert_eq!(entries[0]["actor"]["kind"], "unauthenticated");
    assert_eq!(entries[0]["actor"]["address"], "127.0.0.1");
}

#[tokio::test]
async fn bad_requests_get_json_errors() {
    let server = start(false);
    let unknown_field = server
        .post(
            "/api/v1/clients",
            json!({"name": "x", "addresses": ["10.0.0.1"], "groop": "default"}),
        )
        .await;
    assert_eq!(unknown_field.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(unknown_field.body["error"]["code"], "invalid");
    assert!(
        unknown_field.body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unknown field")
    );

    let bad_address = server
        .post(
            "/api/v1/clients",
            json!({"name": "x", "addresses": ["192.168.1.5/24"]}),
        )
        .await;
    assert_eq!(bad_address.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        bad_address.body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("host bits")
    );

    let bad_rule = server
        .post("/api/v1/rules", json!({"rule": "/regex/"}))
        .await;
    assert_eq!(bad_rule.status, StatusCode::UNPROCESSABLE_ENTITY);

    let missing = server.get("/api/v1/clients/cl_nope").await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_eq!(missing.body["error"]["code"], "not_found");

    let no_route = server.get("/api/v2/anything").await;
    assert_eq!(no_route.status, StatusCode::NOT_FOUND);
    assert_eq!(no_route.body["error"]["code"], "not_found");

    let bad_query = server.get("/api/v1/querylog?limit=lots").await;
    assert_eq!(bad_query.status, StatusCode::BAD_REQUEST);
    assert_eq!(bad_query.body["error"]["code"], "bad_request");

    let bad_if_match = server
        .send(
            Method::PUT,
            "/api/v1/settings",
            Some(json!({})),
            &[("if-match", "yesterday")],
        )
        .await;
    assert_eq!(bad_if_match.status, StatusCode::BAD_REQUEST);

    // Too large: refused with 413, or the connection is closed before the
    // client has finished sending. Either way the server carries on.
    let huge = json!({"name": "x".repeat(2 * 1024 * 1024), "addresses": []});
    if let Ok(too_big) = server
        .try_send(Method::POST, "/api/v1/clients", Some(huge), &[])
        .await
    {
        assert_eq!(too_big.status, StatusCode::PAYLOAD_TOO_LARGE);
    }
    assert_eq!(server.get("/api/v1/health").await.status, StatusCode::OK);
}

#[tokio::test]
async fn the_token_is_required_once_configured() {
    let mut server = start(true);
    let token = server.token.clone().unwrap();
    assert_eq!(server.get("/api/v1/status").await.status, StatusCode::OK);
    let created = server
        .post("/api/v1/rules", json!({"rule": "||ads.example^"}))
        .await;
    assert_eq!(created.status, StatusCode::CREATED);
    let audit = server.get("/api/v1/audit?limit=1").await;
    assert_eq!(audit.body[0]["actor"]["kind"], "token");

    server.token = Some(format!("{token}x"));
    let wrong = server.get("/api/v1/status").await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.body["error"]["code"], "unauthorized");
    assert!(wrong.headers.contains_key("www-authenticate"));
    server.token = None;
    assert_eq!(
        server.get("/api/v1/status").await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        server.get("/metrics").await.status,
        StatusCode::UNAUTHORIZED
    );
    // Health checks need no token.
    let health = server.get("/api/v1/health").await;
    assert_eq!(health.status, StatusCode::OK);
    assert_eq!(health.body["status"], "ok");
}

#[tokio::test]
async fn pausing_refreshing_settings_and_observing() {
    let server = start(false);
    let paused = server
        .send(
            Method::PUT,
            "/api/v1/pause",
            Some(json!({"seconds": 600})),
            &[],
        )
        .await;
    assert_eq!(paused.status, StatusCode::OK, "{}", paused.text);
    assert!(paused.body["paused_until"].is_string());
    assert!(server.control.paused.lock().unwrap().is_some());
    let too_long = server
        .send(
            Method::PUT,
            "/api/v1/pause",
            Some(json!({"seconds": 0})),
            &[],
        )
        .await;
    assert_eq!(too_long.status, StatusCode::UNPROCESSABLE_ENTITY);
    let resumed = server
        .send(Method::DELETE, "/api/v1/pause", None, &[])
        .await;
    assert_eq!(resumed.status, StatusCode::OK);
    assert_eq!(resumed.body, json!({}));

    let refresh = server.post("/api/v1/lists/refresh", json!({})).await;
    assert_eq!(refresh.status, StatusCode::ACCEPTED);
    assert_eq!(*server.control.refreshed.lock().unwrap(), 1);

    let settings = server.get("/api/v1/settings").await;
    assert_eq!(settings.body["spec"]["protection"], true);
    let mut spec = settings.body["spec"].clone();
    spec["protection"] = json!(false);
    let changed = server
        .send(
            Method::PUT,
            "/api/v1/settings",
            Some(spec),
            &[("if-match", "\"1\"")],
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.text);
    assert_eq!(changed.body["revision"], 2);

    let audit = server.get("/api/v1/audit").await;
    let actions: Vec<&str> = audit
        .body
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["action"].as_str().unwrap())
        .collect();
    assert_eq!(actions, ["update", "refresh", "resume", "pause"]);

    let node = server.get("/api/v1/status").await;
    assert_eq!(node.body["filter"]["rules"], 42);
    let log = server.get("/api/v1/querylog?limit=5&outcome=blocked").await;
    assert_eq!(log.status, StatusCode::OK, "{}", log.text);
    assert_eq!(log.body["entries"], json!([]));
    let stats = server.get("/api/v1/stats?hours=48").await;
    assert_eq!(stats.body["totals"]["queries"], 0);
    let metrics = server.get("/metrics").await;
    assert_eq!(metrics.text, "goethite_up 1\n");
    assert!(
        metrics.headers["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    let spec = server.get("/api/v1/openapi.json").await;
    assert_eq!(spec.body["openapi"], "3.1.0");
}

#[tokio::test]
async fn responses_carry_security_headers() {
    let server = start(false);
    for path in ["/api/v1/health", "/api/v1/status", "/nowhere"] {
        let reply = server.get(path).await;
        let csp = reply.headers["content-security-policy"].to_str().unwrap();
        assert!(csp.contains("default-src 'self'") && csp.contains("frame-ancestors 'none'"));
        assert_eq!(
            reply.headers["x-content-type-options"],
            HeaderValue::from_static("nosniff")
        );
        assert_eq!(
            reply.headers["cache-control"],
            HeaderValue::from_static("no-store")
        );
        assert_eq!(
            reply.headers["x-frame-options"],
            HeaderValue::from_static("DENY")
        );
    }
}
