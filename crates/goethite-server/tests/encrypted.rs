//! End-to-end tests of DNS over TLS and DNS over HTTPS on ephemeral ports,
//! with a self-signed certificate for `dns.example` and `*.dns.example`.
//!
//! Queries are built and responses checked with hickory-proto, and spoken
//! to with tokio-rustls and hyper's clients.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test helpers; the no-panic rules cover non-test code"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use goethite_filter::{Filter, Sources};
use goethite_resolver::{
    BlockResponse, ClientPolicy, GroupPolicy, Policy, PolicyParts, PolicyState, Resolver,
    test_record,
};
use goethite_server::{
    QueryEvent, QueryObserver, Server, ServerConfig, ServerError, ServerStats, Transport,
};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType, rdata::A};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

const WAIT: Duration = Duration::from_secs(5);

/// Records who each answered query was from.
#[derive(Default)]
struct Seen(Mutex<Vec<(Transport, Option<String>)>>);

impl QueryObserver for Seen {
    fn observe(&self, event: &QueryEvent<'_>) {
        self.0.lock().unwrap().push((
            event.transport,
            event.resolution.client.as_deref().map(str::to_owned),
        ));
    }
}

impl Seen {
    fn last(&self) -> (Transport, Option<String>) {
        self.0.lock().unwrap().last().cloned().unwrap()
    }
}

struct Running {
    dot: SocketAddr,
    doh: SocketAddr,
    roots: Arc<rustls::RootCertStore>,
    seen: Arc<Seen>,
    stats: Arc<ServerStats>,
    stop: oneshot::Sender<()>,
    task: JoinHandle<Result<(), ServerError>>,
}

impl Running {
    async fn shutdown(self) {
        self.stop.send(()).unwrap();
        timeout(WAIT, self.task).await.unwrap().unwrap().unwrap();
    }
}

/// A resolver that knows the client `cl_kid` by its ID `kid-1` and the
/// client `cl_tv` by `tv`.
fn resolver() -> Resolver {
    let client = |id: &str, client_id: &str| ClientPolicy {
        id: id.into(),
        addresses: Vec::new(),
        ids: vec![client_id.into()],
        group: 0,
    };
    let policy = Policy::new(PolicyParts {
        filter: Arc::new(Filter::empty()),
        source_ids: Vec::new(),
        groups: vec![GroupPolicy::new("default", Sources::ALL)],
        clients: vec![client("cl_kid", "kid-1"), client("cl_tv", "tv")],
        block_response: BlockResponse::NullIp,
        blocked_ttl: 10,
        protection: true,
    })
    .unwrap();
    Resolver::new(vec![test_record().unwrap()]).with_policy(Arc::new(PolicyState::new(policy)))
}

/// A certificate for `dns.example` and `*.dns.example`, and roots that
/// trust it.
fn certificate() -> (Arc<rustls::ServerConfig>, Arc<rustls::RootCertStore>) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["dns.example".into(), "*.dns.example".into()])
            .unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key)
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::clone(cert.der())).unwrap();
    (Arc::new(config), Arc::new(roots))
}

fn start_with(configure: impl FnOnce(&mut ServerConfig)) -> Running {
    let mut config = ServerConfig::new(vec!["127.0.0.1:0".parse().unwrap()]);
    config.dot = vec!["127.0.0.1:0".parse().unwrap()];
    config.doh = vec!["127.0.0.1:0".parse().unwrap()];
    config.server_name = Some("dns.example".into());
    configure(&mut config);
    let (tls, roots) = certificate();
    let seen = Arc::new(Seen::default());
    let server = Server::bind(config, Arc::new(resolver()))
        .unwrap()
        .with_tls(tls)
        .with_observer(Arc::clone(&seen) as Arc<dyn QueryObserver>);
    let dot = server.dot_local_addrs().unwrap()[0];
    let doh = server.doh_local_addrs().unwrap()[0];
    let stats = server.stats();
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(server.run(async {
        let _ = stopped.await;
    }));
    Running {
        dot,
        doh,
        roots,
        seen,
        stats,
        stop,
        task,
    }
}

fn start() -> Running {
    start_with(|_| {})
}

fn query(id: u16, name: &str) -> Vec<u8> {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
    message.to_vec().unwrap()
}

fn assert_test_answer(response: &Message, id: u16) {
    assert_eq!(response.metadata.id, id);
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(response.answers.len(), 1);
    assert_eq!(
        response.answers[0].data,
        RData::A(A(Ipv4Addr::new(127, 0, 0, 53)))
    );
}

/// A TLS connection to `addr` for `server_name`, offering `alpn`.
async fn connect(
    server: &Running,
    addr: SocketAddr,
    server_name: &str,
    alpn: &[&[u8]],
) -> TlsStream<TcpStream> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(Arc::clone(&server.roots))
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    let stream = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from(server_name.to_owned()).unwrap();
    timeout(
        WAIT,
        TlsConnector::from(Arc::new(config)).connect(name, stream),
    )
    .await
    .unwrap()
    .unwrap()
}

async fn dot_exchange(stream: &mut TlsStream<TcpStream>, wire: &[u8]) -> Message {
    let len = u16::try_from(wire.len()).unwrap().to_be_bytes();
    stream.write_all(&len).await.unwrap();
    stream.write_all(wire).await.unwrap();
    stream.flush().await.unwrap();
    let mut len = [0; 2];
    timeout(WAIT, stream.read_exact(&mut len))
        .await
        .unwrap()
        .unwrap();
    let mut buf = vec![0; usize::from(u16::from_be_bytes(len))];
    timeout(WAIT, stream.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    Message::from_vec(&buf).unwrap()
}

#[tokio::test]
async fn dot_answers_and_reads_the_client_id_from_the_server_name() {
    let server = start();
    let mut stream = connect(&server, server.dot, "kid-1.dns.example", &[b"dot"]).await;
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"dot"[..]));
    for id in [1, 2] {
        let response = dot_exchange(&mut stream, &query(id, "goethite.test.")).await;
        assert_test_answer(&response, id);
        assert_eq!(
            server.seen.last(),
            (Transport::Tls, Some("cl_kid".to_owned()))
        );
    }

    // Without a client ID, the address decides: an unknown one here.
    let mut stream = connect(&server, server.dot, "dns.example", &[]).await;
    assert_test_answer(
        &dot_exchange(&mut stream, &query(3, "goethite.test.")).await,
        3,
    );
    assert_eq!(server.seen.last(), (Transport::Tls, None));
    server.shutdown().await;
}

#[tokio::test]
async fn failed_tls_handshakes_are_counted() {
    let server = start();
    let mut plain = TcpStream::connect(server.dot).await.unwrap();
    plain
        .write_all(b"\x00\x1fnot a TLS client hello at all")
        .await
        .unwrap();
    timeout(WAIT, async {
        while server
            .stats
            .tls_handshake_failures
            .load(std::sync::atomic::Ordering::Relaxed)
            == 0
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    server.shutdown().await;
}

/// An HTTP response: status, headers, body.
struct Answer {
    status: StatusCode,
    headers: hyper::HeaderMap,
    body: Bytes,
}

impl Answer {
    fn message(&self) -> Message {
        assert_eq!(self.status, StatusCode::OK);
        assert_eq!(
            self.headers.get("content-type").unwrap(),
            "application/dns-message"
        );
        Message::from_vec(&self.body).unwrap()
    }
}

/// An HTTP/1.1 or HTTP/2 client on one connection.
enum Http {
    One(hyper::client::conn::http1::SendRequest<Full<Bytes>>),
    Two(hyper::client::conn::http2::SendRequest<Full<Bytes>>),
}

impl Http {
    async fn connect(server: &Running, server_name: &str, http2: bool) -> (Self, JoinHandle<()>) {
        let alpn: &[&[u8]] = if http2 { &[b"h2"] } else { &[b"http/1.1"] };
        let stream = connect(server, server.doh, server_name, alpn).await;
        let io = TokioIo::new(stream);
        if http2 {
            let (sender, connection) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
                    .await
                    .unwrap();
            let task = tokio::spawn(async move {
                let _ = connection.await;
            });
            (Self::Two(sender), task)
        } else {
            let (sender, connection) = hyper::client::conn::http1::handshake(io).await.unwrap();
            let task = tokio::spawn(async move {
                let _ = connection.await;
            });
            (Self::One(sender), task)
        }
    }

    async fn send(&mut self, request: Request<Full<Bytes>>) -> Answer {
        let response = timeout(WAIT, async {
            match self {
                Self::One(sender) => sender.send_request(request).await,
                Self::Two(sender) => sender.send_request(request).await,
            }
        })
        .await
        .unwrap()
        .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        Answer {
            status,
            headers,
            body,
        }
    }
}

fn get(target: &str) -> Request<Full<Bytes>> {
    Request::get(format!("https://dns.example{target}"))
        .header("accept", "application/dns-message")
        .body(Full::default())
        .unwrap()
}

fn post(target: &str, content_type: &str, body: Vec<u8>) -> Request<Full<Bytes>> {
    Request::post(format!("https://dns.example{target}"))
        .header("content-type", content_type)
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// base64url without padding, as RFC 8484 sends the `dns` parameter.
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut text = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            text.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]));
        }
    }
    text
}

#[tokio::test]
async fn doh_answers_get_and_post_over_http1_and_http2() {
    let server = start();
    for http2 in [false, true] {
        let (mut http, _connection) = Http::connect(&server, "dns.example", http2).await;
        let wire = query(0, "goethite.test.");
        let answer = http
            .send(get(&format!("/dns-query?dns={}", base64url(&wire))))
            .await;
        assert_test_answer(&answer.message(), 0);
        // Cacheable for as long as the answer's time to live.
        assert_eq!(answer.headers.get("cache-control").unwrap(), "max-age=60");
        let answer = http
            .send(post("/dns-query", "application/dns-message", wire))
            .await;
        assert_test_answer(&answer.message(), 0);
        assert_eq!(server.seen.last(), (Transport::Https, None));
    }
    server.shutdown().await;
}

#[tokio::test]
async fn doh_client_ids_come_from_the_path_first() {
    let server = start();
    let (mut http, _connection) = Http::connect(&server, "kid-1.dns.example", true).await;
    let wire = query(0, "goethite.test.");
    http.send(post("/dns-query", "application/dns-message", wire.clone()))
        .await
        .message();
    assert_eq!(
        server.seen.last(),
        (Transport::Https, Some("cl_kid".to_owned()))
    );
    http.send(post(
        "/dns-query/tv",
        "application/dns-message",
        wire.clone(),
    ))
    .await
    .message();
    assert_eq!(
        server.seen.last(),
        (Transport::Https, Some("cl_tv".to_owned()))
    );
    // A valid ID nobody uses: the address decides.
    http.send(post("/dns-query/unknown", "application/dns-message", wire))
        .await
        .message();
    assert_eq!(server.seen.last(), (Transport::Https, None));
    server.shutdown().await;
}

#[tokio::test]
async fn doh_refuses_what_is_not_a_dns_query() {
    let server = start();
    let (mut http, _connection) = Http::connect(&server, "dns.example", true).await;
    let wire = query(0, "goethite.test.");
    let cases = [
        (get("/"), StatusCode::NOT_FOUND),
        (get("/api/v1/status"), StatusCode::NOT_FOUND),
        (get("/dns-query"), StatusCode::BAD_REQUEST),
        (get("/dns-query?dns=not+base64"), StatusCode::BAD_REQUEST),
        (
            get("/dns-query/Not-Valid?dns=AAAB"),
            StatusCode::BAD_REQUEST,
        ),
        (
            post("/dns-query", "text/plain", wire.clone()),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            post("/dns-query", "application/dns-message", vec![0; 65_536]),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
        (
            post("/dns-query", "application/dns-message", b"garbage".to_vec()),
            StatusCode::BAD_REQUEST,
        ),
        (
            Request::builder()
                .method(Method::PUT)
                .uri("https://dns.example/dns-query")
                .body(Full::new(Bytes::from(wire)))
                .unwrap(),
            StatusCode::METHOD_NOT_ALLOWED,
        ),
    ];
    let count = cases.len();
    for (request, status) in cases {
        let target = request.uri().to_string();
        assert_eq!(http.send(request).await.status, status, "{target}");
    }
    assert_eq!(
        server
            .stats
            .https_rejected
            .load(std::sync::atomic::Ordering::Relaxed),
        u64::try_from(count).unwrap()
    );
    // The connection still answers.
    let answer = http
        .send(post(
            "/dns-query",
            "application/dns-message",
            query(7, "goethite.test."),
        ))
        .await;
    assert_test_answer(&answer.message(), 7);
    server.shutdown().await;
}

#[tokio::test]
async fn idle_doh_connections_are_closed() {
    let server = start_with(|config| config.tls_idle_timeout = Duration::from_millis(300));
    for http2 in [false, true] {
        let (mut http, connection) = Http::connect(&server, "dns.example", http2).await;
        http.send(post(
            "/dns-query",
            "application/dns-message",
            query(1, "goethite.test."),
        ))
        .await
        .message();
        timeout(WAIT, connection).await.unwrap().unwrap();
    }
    server.shutdown().await;
}

#[tokio::test]
async fn only_known_client_ids_are_answered_when_required() {
    let server = start_with(|config| config.require_client_id = true);
    let refused = |message: &Message| {
        assert_eq!(message.metadata.response_code, ResponseCode::Refused);
        assert_eq!(message.answers.len(), 0);
    };
    let mut known = connect(&server, server.dot, "kid-1.dns.example", &[]).await;
    assert_test_answer(
        &dot_exchange(&mut known, &query(1, "goethite.test.")).await,
        1,
    );
    for name in ["dns.example", "nobody.dns.example"] {
        let mut stream = connect(&server, server.dot, name, &[]).await;
        refused(&dot_exchange(&mut stream, &query(2, "goethite.test.")).await);
    }
    assert_eq!(server.seen.last(), (Transport::Tls, None));

    let (mut http, _connection) = Http::connect(&server, "dns.example", true).await;
    let wire = query(0, "goethite.test.");
    let answer = http
        .send(post(
            "/dns-query/tv",
            "application/dns-message",
            wire.clone(),
        ))
        .await;
    assert_test_answer(&answer.message(), 0);
    for target in ["/dns-query", "/dns-query/nobody"] {
        let answer = http
            .send(post(target, "application/dns-message", wire.clone()))
            .await;
        refused(&answer.message());
    }
    server.shutdown().await;
}

#[tokio::test]
async fn encrypted_listeners_need_a_certificate() {
    let mut config = ServerConfig::new(vec!["127.0.0.1:0".parse().unwrap()]);
    config.dot = vec!["127.0.0.1:0".parse().unwrap()];
    let server = Server::bind(config, Arc::new(resolver())).unwrap();
    let ran = timeout(WAIT, server.run(std::future::pending()))
        .await
        .unwrap();
    assert!(matches!(ran, Err(ServerError::NoCertificate)), "{ran:?}");
}
