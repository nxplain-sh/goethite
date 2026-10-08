//! The API over real HTTP, against a temporary store and a fake data plane.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test helpers; the no-panic rules cover non-test code"
)]

use std::borrow::Cow;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use goethite_api::{
    Api, ApiConfig, ApiListeners, BoxFuture, BoxResult, Change, ClusterRole, ClusterStatus,
    Control, DOCS_SCALAR, FilterStatus, Forwarded, ForwardedAnswer, PeerStatus, QueryLogStatus,
    Status, WebAssets, Writes, generate_token,
};
use goethite_store::{
    Actor, ActorKind, ConfigVersion, QueryLogConfig, StatsReport, Store, TopEntry,
};
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
    /// Where changes go; local when unset.
    writes: Mutex<Option<Writes>>,
    /// Changes forwarded to the "primary".
    forwarded: Mutex<Vec<Forwarded>>,
    /// The version the "primary" reports after a forwarded change.
    answer_version: Mutex<ConfigVersion>,
    /// The cluster, if the node is in one.
    cluster: Mutex<Option<ClusterStatus>>,
    /// The other node's statistics; unreachable when unset.
    peer_stats: Mutex<Option<StatsReport>>,
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
            cluster: None,
            encrypted: None,
            problems: Vec::new(),
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

    fn cluster(&self) -> Option<ClusterStatus> {
        self.cluster.lock().unwrap().clone()
    }

    fn peer_stats(&self, _hours: u32) -> BoxResult<'_, StatsReport> {
        let stats = self.peer_stats.lock().unwrap().clone();
        Box::pin(async move {
            stats.ok_or_else(|| goethite_api::ApiError::unavailable("dns2 is unreachable"))
        })
    }

    fn writes(&self) -> Writes {
        self.writes.lock().unwrap().clone().unwrap_or(Writes::Local)
    }

    fn forward(&self, forwarded: Forwarded) -> BoxResult<'_, ForwardedAnswer> {
        self.forwarded.lock().unwrap().push(forwarded);
        let version = *self.answer_version.lock().unwrap();
        Box::pin(async move {
            Ok(ForwardedAnswer {
                status: 201,
                etag: Some("\"1\"".into()),
                location: Some("/api/v1/rules/ru_primary".into()),
                body: Some(r#"{"id":"ru_primary","revision":1}"#.into()),
                version,
            })
        })
    }
}

/// A web UI of three files.
#[derive(Debug)]
struct FakeWeb;

impl WebAssets for FakeWeb {
    fn file(&self, path: &str) -> Option<Cow<'static, [u8]>> {
        let data: &'static [u8] = match path {
            "index.html" => b"<!doctype html><title>goethite</title>",
            "assets/app-1234.js" => b"console.log(1)",
            "favicon.svg" => b"<svg/>",
            _ => return None,
        };
        Some(Cow::Borrowed(data))
    }
}

/// The API reference's one built file.
#[derive(Debug)]
struct FakeDocs;

impl WebAssets for FakeDocs {
    fn file(&self, path: &str) -> Option<Cow<'static, [u8]>> {
        (path == DOCS_SCALAR).then_some(Cow::Borrowed(b"gzipped scalar".as_slice()))
    }
}

struct Server {
    addr: SocketAddr,
    api: Arc<Api>,
    control: Arc<FakeControl>,
    stop: Option<oneshot::Sender<()>>,
    path: PathBuf,
    token: Option<String>,
    /// The Host header sent.
    host: String,
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
    start_with(with_token, None)
}

fn start_with(with_token: bool, web: Option<Arc<dyn WebAssets>>) -> Server {
    start_with_docs(with_token, web, None)
}

fn start_with_docs(
    with_token: bool,
    web: Option<Arc<dyn WebAssets>>,
    docs: Option<Arc<dyn WebAssets>>,
) -> Server {
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
            web,
            docs,
        },
    });
    let listeners = ApiListeners::bind(&["127.0.0.1:0".parse().unwrap()]).unwrap();
    let addr = listeners.local_addrs().unwrap()[0];
    let (stop, stopped) = oneshot::channel::<()>();
    tokio::spawn(goethite_api::serve(listeners, Arc::clone(&api), async {
        let _ = stopped.await;
    }));
    Server {
        addr,
        api,
        control,
        stop: Some(stop),
        path,
        token: with_token.then_some(token),
        host: format!("localhost:{}", addr.port()),
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
            .header("host", self.host.as_str());
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

#[tokio::test]
async fn serves_the_web_ui_without_shadowing_the_api() {
    let server = start_with(true, Some(Arc::new(FakeWeb)));
    let mut anonymous = start_with(true, Some(Arc::new(FakeWeb)));
    anonymous.token = None;

    // The UI's files need no token; deep links get index.html.
    for path in [
        "/",
        "/index.html",
        "/querylog?name=ads",
        "/a/deep/link",
        "/..%2f..%2fetc",
    ] {
        let page = anonymous.get(path).await;
        assert_eq!(page.status, StatusCode::OK, "{path}");
        assert_eq!(
            page.text, "<!doctype html><title>goethite</title>",
            "{path}"
        );
        assert_eq!(page.headers["content-type"], "text/html; charset=utf-8");
        assert_eq!(page.headers["cache-control"], "no-cache");
        assert!(page.headers.contains_key("content-security-policy"));
    }
    let script = anonymous.get("/assets/app-1234.js").await;
    assert_eq!(script.status, StatusCode::OK);
    assert_eq!(
        script.headers["content-type"],
        "text/javascript; charset=utf-8"
    );
    assert_eq!(
        script.headers["cache-control"],
        "public, max-age=31536000, immutable"
    );
    assert_eq!(
        anonymous.get("/favicon.svg").await.headers["content-type"],
        "image/svg+xml"
    );
    let head = anonymous.send(Method::HEAD, "/", None, &[]).await;
    assert_eq!(head.status, StatusCode::OK);

    // Missing assets and API paths are JSON 404s, never the page.
    for path in ["/assets/gone-9999.js", "/api", "/api/", "/api/v2/anything"] {
        let missing = anonymous.get(path).await;
        assert_eq!(missing.status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(missing.body["error"]["code"], "not_found", "{path}");
        assert_eq!(missing.headers["cache-control"], "no-store");
    }
    let posted = anonymous.send(Method::POST, "/", None, &[]).await;
    assert_eq!(posted.status, StatusCode::NOT_FOUND);

    // The API itself still needs the token.
    assert_eq!(
        anonymous.get("/api/v1/status").await.status,
        StatusCode::UNAUTHORIZED
    );
    let status = server.get("/api/v1/status").await;
    assert_eq!(status.status, StatusCode::OK);
    assert_eq!(status.headers["cache-control"], "no-store");
}

#[tokio::test]
async fn browsers_cannot_be_turned_against_the_api() {
    // Without a token: loopback names only, so DNS rebinding finds nothing.
    let mut server = start_with(false, Some(Arc::new(FakeWeb)));
    let port = server.addr.port();
    for host in [
        format!("localhost:{port}"),
        format!("127.0.0.1:{port}"),
        format!("[::1]:{port}"),
        "ui.localhost".to_owned(),
    ] {
        server.host = host.clone();
        assert_eq!(
            server.get("/api/v1/status").await.status,
            StatusCode::OK,
            "{host}"
        );
    }
    for host in [
        "rebound.example",
        "rebound.example:8053",
        "127.0.0.1.rebound.example",
    ] {
        server.host = host.to_owned();
        for path in ["/api/v1/status", "/", "/api/v1/health"] {
            let refused = server.get(path).await;
            assert_eq!(refused.status, StatusCode::FORBIDDEN, "{host} {path}");
            assert_eq!(refused.body["error"]["code"], "forbidden");
        }
    }
    server.host = format!("localhost:{port}");

    // Cross-site requests are refused; same-origin ones and those without
    // an Origin (curl, the TUI) are not.
    for origin in ["http://evil.example", "null", "http://localhost:1"] {
        let refused = server
            .send(
                Method::POST,
                "/api/v1/lists/refresh",
                None,
                &[("origin", origin)],
            )
            .await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{origin}");
    }
    assert_eq!(*server.control.refreshed.lock().unwrap(), 0);
    let same = format!("http://localhost:{port}");
    let accepted = server
        .send(
            Method::POST,
            "/api/v1/lists/refresh",
            None,
            &[("origin", &same)],
        )
        .await;
    assert_eq!(accepted.status, StatusCode::ACCEPTED);
    let accepted = server
        .send(Method::POST, "/api/v1/lists/refresh", None, &[])
        .await;
    assert_eq!(accepted.status, StatusCode::ACCEPTED);

    // With a token any name works (a rebinding page has no token), but the
    // origin check stays.
    let mut server = start(true);
    server.host = "dns.example.lan:8053".to_owned();
    assert_eq!(server.get("/api/v1/status").await.status, StatusCode::OK);
    let refused = server
        .send(
            Method::GET,
            "/api/v1/status",
            None,
            &[("origin", "https://evil.example")],
        )
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    let accepted = server
        .send(
            Method::GET,
            "/api/v1/status",
            None,
            &[("origin", "https://DNS.example.lan:8053")],
        )
        .await;
    assert_eq!(accepted.status, StatusCode::OK);
}

#[tokio::test]
async fn replicas_forward_configuration_changes() {
    let server = start(false);
    *server.control.writes.lock().unwrap() = Some(Writes::Forward);
    *server.control.answer_version.lock().unwrap() = server.api.store.version();

    let rule = json!({"rule": "||ads.example^"});
    let created = server.post("/api/v1/rules", rule.clone()).await;
    assert_eq!(created.status, StatusCode::CREATED);
    assert_eq!(
        created.text, r#"{"id":"ru_primary","revision":1}"#,
        "the primary's answer, as sent"
    );
    assert_eq!(created.headers["etag"], "\"1\"");
    assert_eq!(created.headers["location"], "/api/v1/rules/ru_primary");
    {
        let forwarded = server.control.forwarded.lock().unwrap();
        assert_eq!(forwarded.len(), 1);
        assert_eq!(
            (forwarded[0].method.as_str(), forwarded[0].path.as_str()),
            ("POST", "/api/v1/rules")
        );
        assert_eq!(
            forwarded[0].body.as_deref(),
            Some(rule.to_string().as_str())
        );
        assert_eq!(forwarded[0].actor.kind, ActorKind::Unauthenticated);
        assert_eq!(forwarded[0].actor.address.as_deref(), Some("127.0.0.1"));
    }
    assert!(
        server.api.store.config().rules.is_empty(),
        "nothing written here"
    );

    // Reads, pausing and list downloads stay on this node.
    assert_eq!(server.get("/api/v1/rules").await.status, StatusCode::OK);
    assert_eq!(
        server
            .send(Method::POST, "/api/v1/lists/refresh", None, &[])
            .await
            .status,
        StatusCode::ACCEPTED
    );
    let paused = server
        .send(
            Method::PUT,
            "/api/v1/pause",
            Some(json!({"seconds": 5})),
            &[],
        )
        .await;
    assert_eq!(paused.status, StatusCode::OK);
    assert_eq!(server.control.forwarded.lock().unwrap().len(), 1);

    // A replica that cannot reach the primary is read-only.
    *server.control.writes.lock().unwrap() =
        Some(Writes::ReadOnly("the primary dns1 is unreachable".into()));
    let refused = server.post("/api/v1/rules", rule).await;
    assert_eq!(refused.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(refused.body["error"]["code"], "unavailable");
    assert!(refused.text.contains("dns1"));

    // Not in a cluster: no cluster endpoints.
    assert_eq!(
        server.get("/api/v1/cluster").await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn the_primary_runs_forwarded_changes_as_their_caller() {
    let server = start(true);
    let caller = Actor {
        kind: ActorKind::Token,
        address: Some("192.0.2.7".into()),
        node: None,
    };
    let forwarded =
        |method: &str, path: &str, body: Option<&str>, if_match: Option<&str>| Forwarded {
            method: method.into(),
            path: path.into(),
            if_match: if_match.map(str::to_owned),
            body: body.map(str::to_owned),
            actor: caller.clone(),
        };
    let created = goethite_api::execute(
        &server.api,
        "dns2",
        forwarded(
            "POST",
            "/api/v1/rules",
            Some(r#"{"rule":"||ads.example^"}"#),
            None,
        ),
    )
    .await
    .unwrap();
    assert_eq!(created.status, 201);
    assert_eq!(created.version, server.api.store.version());
    let id = serde_json::from_str::<Value>(created.body.as_deref().unwrap()).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        created.location.as_deref(),
        Some(format!("/api/v1/rules/{id}").as_str())
    );
    let audit = server.api.store.audit(None, 1).unwrap();
    assert_eq!(audit[0].actor.kind, ActorKind::Token);
    assert_eq!(audit[0].actor.address.as_deref(), Some("192.0.2.7"));
    assert_eq!(audit[0].actor.node.as_deref(), Some("dns2"));

    // Revisions are checked as for any caller.
    let stale = goethite_api::execute(
        &server.api,
        "dns2",
        forwarded(
            "PUT",
            &format!("/api/v1/rules/{id}"),
            Some(r#"{"rule":"||ads.example^","comment":"x"}"#),
            Some("\"9\""),
        ),
    )
    .await
    .unwrap();
    assert_eq!(stale.status, 412);

    // Only configuration changes are forwarded.
    for (method, path) in [
        ("PUT", "/api/v1/pause"),
        ("GET", "/api/v1/rules"),
        ("POST", "/api/v1/cluster/promote"),
    ] {
        assert!(
            goethite_api::execute(&server.api, "dns2", forwarded(method, path, None, None))
                .await
                .is_err(),
            "{method} {path}"
        );
    }
}

#[tokio::test]
async fn cluster_statistics_add_up_every_node() {
    let server = start(false);
    // Not in a cluster: the node's own statistics.
    let alone = server.get("/api/v1/stats?scope=cluster").await;
    assert_eq!(alone.status, StatusCode::OK);
    assert!(alone.body.get("nodes").is_none());

    *server.control.cluster.lock().unwrap() = Some(ClusterStatus {
        node: "dns1".into(),
        role: ClusterRole::Primary,
        config: server.api.store.version(),
        writable: true,
        peer: PeerStatus {
            node: "dns2".into(),
            address: "192.0.2.12:8054".into(),
            reachable: true,
            checked_at: None,
            role: Some(ClusterRole::Replica),
            version: None,
            config: None,
            error: None,
        },
        sync: None,
        problems: Vec::new(),
    });
    let mut peer = server.api.log.stats(24);
    peer.totals.queries = 40;
    peer.totals.blocked = 4;
    peer.top_blocked = vec![TopEntry {
        key: "ads.example".into(),
        count: 4,
    }];
    *server.control.peer_stats.lock().unwrap() = Some(peer);
    let both = server.get("/api/v1/stats?scope=cluster").await;
    assert_eq!(both.body["totals"]["queries"], 40);
    assert_eq!(both.body["top_blocked"][0]["key"], "ads.example");
    assert_eq!(both.body["nodes"], json!(["dns1", "dns2"]));
    // The node's own statistics stay the node's.
    assert_eq!(
        server.get("/api/v1/stats").await.body["totals"]["queries"],
        0
    );

    // An unreachable node is named, not silently left out.
    *server.control.peer_stats.lock().unwrap() = None;
    let partial = server.get("/api/v1/stats?scope=cluster").await;
    assert_eq!(partial.body["nodes"], json!(["dns1"]));
    assert_eq!(partial.body["unreachable"], json!(["dns2"]));
    assert_eq!(
        server.get("/api/v1/stats?scope=everyone").await.status,
        StatusCode::BAD_REQUEST
    );
}

/// The API reference: off by default; on, a page with a fresh nonce in its
/// policy, its files and the OpenAPI document, without a token.
#[tokio::test]
async fn api_reference_is_off_unless_turned_on() {
    let off = start(false);
    for path in [
        "/api/docs",
        "/api/docs/scalar.js",
        "/api/docs/start.js",
        "/api/docs/openapi.json",
    ] {
        assert_eq!(off.get(path).await.status, StatusCode::NOT_FOUND, "{path}");
    }

    let mut on = start_with_docs(true, None, Some(Arc::new(FakeDocs)));
    // The docs need no token; the rest of the API still does.
    on.token = None;
    assert_eq!(
        on.get("/api/v1/openapi.json").await.status,
        StatusCode::UNAUTHORIZED
    );

    let page = on.get("/api/docs").await;
    assert_eq!(page.status, StatusCode::OK);
    let policy = page.headers["content-security-policy"]
        .to_str()
        .unwrap()
        .to_owned();
    let nonce = policy
        .split("'nonce-")
        .nth(1)
        .and_then(|rest| rest.split('\'').next())
        .unwrap()
        .to_owned();
    assert_eq!(nonce.len(), 32);
    assert!(policy.contains("script-src 'self';"), "{policy}");
    // Inline style attributes only: style elements need the nonce or a hash.
    assert!(
        policy.contains("style-src-attr 'unsafe-inline'"),
        "{policy}"
    );
    assert_eq!(policy.matches("unsafe-inline").count(), 1, "{policy}");
    assert!(
        policy.contains(&format!("style-src-elem 'self' 'nonce-{nonce}' 'sha256-")),
        "{policy}"
    );
    assert!(page.text.contains(&format!(
        "<meta property=\"csp-nonce\" content=\"{nonce}\">"
    )));
    let again = on.get("/api/docs").await;
    assert!(!again.text.contains(&nonce), "a nonce is used once");

    let scalar = on
        .send(
            Method::GET,
            "/api/docs/scalar.js",
            None,
            &[("accept-encoding", "gzip, br")],
        )
        .await;
    assert_eq!(scalar.status, StatusCode::OK);
    assert_eq!(scalar.headers["content-encoding"], "gzip");
    assert_eq!(scalar.text, "gzipped scalar");
    assert_eq!(
        on.get("/api/docs/scalar.js").await.status,
        StatusCode::NOT_ACCEPTABLE
    );
    let start = on.get("/api/docs/start.js").await;
    assert!(start.text.contains("/api/docs/openapi.json"));
    let document = on.get("/api/docs/openapi.json").await;
    assert_eq!(document.status, StatusCode::OK);
    assert!(document.body["paths"]["/api/v1/lists"].is_object());
    // Every other page keeps the strict policy.
    let other = on.get("/api/docs/start.js").await;
    assert!(
        !other.headers["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("nonce")
    );
}
