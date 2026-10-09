//! End-to-end tests of DNS over TLS, HTTPS and QUIC on ephemeral ports, with
//! a self-signed certificate for `dns.example` and `*.dns.example`.
//!
//! Queries are built and responses checked with hickory-proto, and spoken
//! to with tokio-rustls, hyper's and quinn's clients.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    reason = "test helpers; the no-panic rules cover non-test code"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use goethite_filter::{Filter, Sources};
use goethite_proto::RESPONSE_PADDING_BLOCK;
use goethite_resolver::{
    BlockResponse, ClientPolicy, GroupPolicy, Policy, PolicyParts, PolicyState, Resolver,
    test_record,
};
use goethite_server::{
    QueryEvent, QueryObserver, Server, ServerConfig, ServerError, ServerStats, Transport,
};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
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
    doq: SocketAddr,
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
    resolver_with(goethite_resolver::Access::default())
}

/// [`resolver`], with the access lists `access`.
fn resolver_with(access: goethite_resolver::Access) -> Resolver {
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
        services: Arc::new(goethite_resolver::ServiceFilter::empty()),
        access,
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
    start_resolving(configure, resolver())
}

fn start_resolving(configure: impl FnOnce(&mut ServerConfig), resolver: Resolver) -> Running {
    let mut config = ServerConfig::new(vec!["127.0.0.1:0".parse().unwrap()]);
    config.dot = vec!["127.0.0.1:0".parse().unwrap()];
    config.doh = vec!["127.0.0.1:0".parse().unwrap()];
    config.doq = vec!["127.0.0.1:0".parse().unwrap()];
    config.server_name = Some("dns.example".into());
    configure(&mut config);
    let (tls, roots) = certificate();
    let seen = Arc::new(Seen::default());
    let server = Server::bind(config, Arc::new(resolver))
        .unwrap()
        .with_tls(tls)
        .with_observer(Arc::clone(&seen) as Arc<dyn QueryObserver>);
    let dot = server.dot_local_addrs().unwrap()[0];
    let doh = server.doh_local_addrs().unwrap()[0];
    let doq = server.doq_local_addrs().unwrap()[0];
    let stats = server.stats();
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(server.run(async {
        let _ = stopped.await;
    }));
    Running {
        dot,
        doh,
        doq,
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
    Message::from_vec(&dot_exchange_raw(stream, wire).await).unwrap()
}

async fn dot_exchange_raw(stream: &mut TlsStream<TcpStream>, wire: &[u8]) -> Vec<u8> {
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
    buf
}

/// A query with EDNS, padded with a Padding option (RFC 7830) if `padded`.
fn edns_query(id: u16, name: &str, padded: bool) -> Vec<u8> {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
    let mut edns = Edns::new();
    edns.set_max_payload(1232);
    if padded {
        edns.options_mut()
            .insert(EdnsOption::Unknown(EdnsCode::Padding.into(), vec![0; 40]));
    }
    message.set_edns(edns);
    message.to_vec().unwrap()
}

fn is_padded(wire: &[u8]) -> bool {
    Message::from_vec(wire)
        .unwrap()
        .edns
        .is_some_and(|edns| edns.options().get(EdnsCode::Padding).is_some())
}

#[tokio::test]
async fn padded_queries_get_padded_answers_over_tls_and_quic() {
    let server = start();
    let mut stream = connect(&server, server.dot, "dns.example", &[b"dot"]).await;
    let padded = dot_exchange_raw(&mut stream, &edns_query(1, "goethite.test.", true)).await;
    assert!(is_padded(&padded));
    assert_eq!(padded.len() % RESPONSE_PADDING_BLOCK, 0);
    assert_test_answer(&Message::from_vec(&padded).unwrap(), 1);
    // A query without padding gets an answer without it.
    let plain = dot_exchange_raw(&mut stream, &edns_query(2, "goethite.test.", false)).await;
    assert!(!is_padded(&plain));
    assert!(plain.len() < padded.len());

    let (_endpoint, connection) = quic(&server, "dns.example").await;
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    let wire = edns_query(0, "goethite.test.", true);
    send.write_all(&u16::try_from(wire.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    send.write_all(&wire).await.unwrap();
    send.finish().unwrap();
    let reply = timeout(WAIT, recv.read_to_end(65_537))
        .await
        .unwrap()
        .unwrap();
    let answer = &reply[2..];
    assert!(is_padded(answer));
    assert_eq!(answer.len() % RESPONSE_PADDING_BLOCK, 0);
    server.shutdown().await;
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
async fn odoh_target_answers_over_http1_and_http2() {
    use goethite_server::odoh::client::{parse_configs, seal_query};

    let server = start_with(|config| config.odoh = true);
    for http2 in [false, true] {
        let (mut http, _connection) = Http::connect(&server, "dns.example", http2).await;
        let configs = http.send(get("/.well-known/odohconfigs")).await;
        assert_eq!(configs.status, StatusCode::OK);
        assert_eq!(
            configs.headers.get("content-type").unwrap(),
            "application/octet-stream"
        );
        let config = parse_configs(&configs.body).unwrap();

        let (wire, pending) = seal_query(&config, &query(9, "goethite.test."), 16).unwrap();
        let answer = http
            .send(post(
                "/dns-query",
                "application/oblivious-dns-message",
                wire,
            ))
            .await;
        assert_eq!(answer.status, StatusCode::OK);
        assert_eq!(
            answer.headers.get("content-type").unwrap(),
            "application/oblivious-dns-message"
        );
        assert_eq!(
            answer.headers.get("cache-control").unwrap(),
            "no-cache, no-store"
        );
        let message = Message::from_vec(&pending.open(&answer.body).unwrap()).unwrap();
        assert_test_answer(&message, 9);
        assert_eq!(server.seen.last(), (Transport::Oblivious, None));

        // A client may name itself in the target path.
        let (wire, pending) = seal_query(&config, &query(10, "goethite.test."), 0).unwrap();
        let answer = http
            .send(post(
                "/dns-query/tv",
                "application/oblivious-dns-message",
                wire,
            ))
            .await;
        pending.open(&answer.body).unwrap();
        assert_eq!(
            server.seen.last(),
            (Transport::Oblivious, Some("cl_tv".to_owned()))
        );

        // A key the target does not have: 401, so the client fetches the
        // configuration again. Anything else wrong: 400.
        let (mut wire, _) = seal_query(&config, &query(11, "goethite.test."), 0).unwrap();
        wire[3] ^= 1;
        let refused = http
            .send(post(
                "/dns-query",
                "application/oblivious-dns-message",
                wire,
            ))
            .await;
        assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
        let refused = http
            .send(post(
                "/dns-query",
                "application/oblivious-dns-message",
                b"garbage".to_vec(),
            ))
            .await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST);
        let (wire, _) = seal_query(&config, b"not DNS", 0).unwrap();
        let refused = http
            .send(post(
                "/dns-query",
                "application/oblivious-dns-message",
                wire,
            ))
            .await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    }
    server.shutdown().await;
}

#[tokio::test]
async fn odoh_is_off_unless_asked_for() {
    use goethite_server::odoh::client::{parse_configs, seal_query};

    let target = start_with(|config| config.odoh = true);
    let (mut http, _connection) = Http::connect(&target, "dns.example", true).await;
    let config = parse_configs(&http.send(get("/.well-known/odohconfigs")).await.body).unwrap();
    target.shutdown().await;

    let server = start();
    let (mut http, _connection) = Http::connect(&server, "dns.example", true).await;
    assert_eq!(
        http.send(get("/.well-known/odohconfigs")).await.status,
        StatusCode::NOT_FOUND
    );
    let (wire, _) = seal_query(&config, &query(0, "goethite.test."), 0).unwrap();
    assert_eq!(
        http.send(post(
            "/dns-query",
            "application/oblivious-dns-message",
            wire
        ))
        .await
        .status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
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

    let (_endpoint, known) = quic(&server, "tv.dns.example").await;
    assert_test_answer(&doq_exchange(&known, &wire).await, 0);
    let (_other, unknown) = quic(&server, "dns.example").await;
    refused(&doq_exchange(&unknown, &wire).await);
    server.shutdown().await;
}

#[tokio::test]
async fn blocked_client_ids_are_refused() {
    let blocked = goethite_resolver::AccessList {
        networks: Vec::new(),
        ids: vec!["tv".into()],
    };
    let access =
        goethite_resolver::Access::new(&goethite_resolver::AccessList::default(), &blocked);
    let server = start_resolving(|_| {}, resolver_with(access));
    let refused = |message: &Message| {
        assert_eq!(message.metadata.response_code, ResponseCode::Refused);
        assert_eq!(message.answers.len(), 0);
    };
    let wire = query(0, "goethite.test.");

    let mut blocked = connect(&server, server.dot, "tv.dns.example", &[]).await;
    refused(&dot_exchange(&mut blocked, &wire).await);
    let mut other = connect(&server, server.dot, "kid-1.dns.example", &[]).await;
    assert_test_answer(&dot_exchange(&mut other, &wire).await, 0);

    let (mut http, _connection) = Http::connect(&server, "dns.example", true).await;
    let answer = http
        .send(post(
            "/dns-query/tv",
            "application/dns-message",
            wire.clone(),
        ))
        .await;
    refused(&answer.message());
    let answer = http
        .send(post("/dns-query", "application/dns-message", wire.clone()))
        .await;
    assert_test_answer(&answer.message(), 0);

    let (_endpoint, blocked) = quic(&server, "tv.dns.example").await;
    refused(&doq_exchange(&blocked, &wire).await);

    for transport in [Transport::Tls, Transport::Https, Transport::Quic] {
        assert_eq!(server.stats.access_refused.get(transport), 1, "{transport}");
    }
    server.shutdown().await;
}

/// A DNS over QUIC connection for `server_name`, and its endpoint.
async fn quic(server: &Running, server_name: &str) -> (quinn::Endpoint, quinn::Connection) {
    let (endpoint, connection) = try_quic(server, server_name).await;
    (endpoint, connection.unwrap())
}

/// A DNS over QUIC connection attempt for `server_name`, and its endpoint.
async fn try_quic(
    server: &Running,
    server_name: &str,
) -> (
    quinn::Endpoint,
    Result<quinn::Connection, quinn::ConnectionError>,
) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(Arc::clone(&server.roots))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"doq".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(config).unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let connecting = endpoint.connect(server.doq, server_name).unwrap();
    let connection = timeout(WAIT, connecting).await.unwrap();
    (endpoint, connection)
}

/// Sends `wire` on a stream of its own, as RFC 9250 says, and reads the
/// answer.
async fn doq_exchange(connection: &quinn::Connection, wire: &[u8]) -> Message {
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    let mut frame = u16::try_from(wire.len()).unwrap().to_be_bytes().to_vec();
    frame.extend_from_slice(wire);
    send.write_all(&frame).await.unwrap();
    send.finish().unwrap();
    let stream = timeout(WAIT, recv.read_to_end(65_537))
        .await
        .unwrap()
        .unwrap();
    let len = usize::from(u16::from_be_bytes([stream[0], stream[1]]));
    assert_eq!(len, stream.len() - 2);
    Message::from_vec(&stream[2..]).unwrap()
}

/// The DoQ error code the server closed `connection` with.
async fn closed_with(connection: &quinn::Connection) -> u64 {
    match timeout(WAIT, connection.closed()).await.unwrap() {
        quinn::ConnectionError::ApplicationClosed(close) => close.error_code.into_inner(),
        other => panic!("closed by {other:?}"),
    }
}

#[tokio::test]
async fn doq_answers_each_stream_and_reads_the_client_id() {
    let server = start();
    let (_endpoint, connection) = quic(&server, "kid-1.dns.example").await;
    assert_eq!(
        connection
            .handshake_data()
            .unwrap()
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .unwrap()
            .protocol,
        Some(b"doq".to_vec())
    );
    // Several queries at once, each on its own stream, all with ID 0.
    let wire = query(0, "goethite.test.");
    let answers = exchange_at_once(&connection, &wire, 5).await;
    for answer in &answers {
        assert_test_answer(answer, 0);
    }
    assert_eq!(
        server.seen.last(),
        (Transport::Quic, Some("cl_kid".to_owned()))
    );

    let (_other, plain) = quic(&server, "dns.example").await;
    assert_test_answer(&doq_exchange(&plain, &wire).await, 0);
    assert_eq!(server.seen.last(), (Transport::Quic, None));

    // Shutting down closes connections without an error.
    server.shutdown().await;
    assert_eq!(closed_with(&connection).await, 0);
}

/// `count` exchanges of `wire` on `connection` at once.
async fn exchange_at_once(
    connection: &quinn::Connection,
    wire: &[u8],
    count: usize,
) -> Vec<Message> {
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..count {
        let connection = connection.clone();
        let wire = wire.to_vec();
        tasks.spawn(async move { doq_exchange(&connection, &wire).await });
    }
    let mut answers = Vec::new();
    while let Some(answer) = tasks.join_next().await {
        answers.push(answer.unwrap());
    }
    answers
}

#[tokio::test]
async fn doq_protocol_errors_close_the_connection() {
    let server = start();
    let wire = query(0, "goethite.test.");
    let mut numbered = query(7, "goethite.test.");
    let mut short = vec![0, 40];
    short.extend_from_slice(&wire);
    // Too short for a DNS header: a malformed query with a header gets
    // FORMERR instead, as over TCP.
    let garbage = b"\x00\x00\x01".to_vec();
    // A nonzero ID, a length that does not match, and no DNS at all.
    let cases: [Vec<u8>; 3] = [
        {
            let mut frame = u16::try_from(numbered.len())
                .unwrap()
                .to_be_bytes()
                .to_vec();
            frame.append(&mut numbered);
            frame
        },
        short,
        {
            let mut frame = u16::try_from(garbage.len()).unwrap().to_be_bytes().to_vec();
            frame.extend_from_slice(&garbage);
            frame
        },
    ];
    for (case, stream) in cases.iter().enumerate() {
        let (_endpoint, connection) = quic(&server, "dns.example").await;
        let (mut send, _recv) = connection.open_bi().await.unwrap();
        send.write_all(stream).await.unwrap();
        send.finish().unwrap();
        assert_eq!(
            closed_with(&connection).await,
            2,
            "case {case}: DOQ_PROTOCOL_ERROR"
        );
    }
    // The server allows no unidirectional stream, so a client cannot open
    // one (a client that did anyway would break QUIC's stream limit).
    let (_endpoint, connection) = quic(&server, "dns.example").await;
    let uni = timeout(Duration::from_millis(300), connection.open_uni()).await;
    assert!(uni.is_err(), "a unidirectional stream opened");
    assert_test_answer(&doq_exchange(&connection, &wire).await, 0);
    server.shutdown().await;
}

#[tokio::test]
async fn doq_shares_the_connection_limits() {
    let server = start_with(|config| {
        config.max_tcp_connections = 1;
        config.max_tcp_connections_per_client = 1;
    });
    let (_first, connection) = quic(&server, "dns.example").await;
    assert_test_answer(
        &doq_exchange(&connection, &query(0, "goethite.test.")).await,
        0,
    );
    // The one slot is taken, by QUIC as by TCP.
    let (_second, refused) = try_quic(&server, "dns.example").await;
    assert!(
        matches!(refused, Err(quinn::ConnectionError::ConnectionClosed(_))),
        "{refused:?}"
    );
    assert!(TcpStream::connect(server.dot).await.is_ok());
    assert_eq!(
        server
            .stats
            .tcp_refused
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    // Once it is closed, the slot is free again.
    connection.close(0_u32.into(), b"");
    drop(connection);
    let mut freed = false;
    for _ in 0..50 {
        if try_quic(&server, "dns.example").await.1.is_ok() {
            freed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(freed, "the slot was not freed");
    server.shutdown().await;
}

#[tokio::test]
async fn idle_doq_connections_are_closed() {
    let server = start_with(|config| config.tls_idle_timeout = Duration::from_millis(300));
    let (_endpoint, connection) = quic(&server, "dns.example").await;
    assert_test_answer(
        &doq_exchange(&connection, &query(0, "goethite.test.")).await,
        0,
    );
    let closed = timeout(WAIT, connection.closed()).await.unwrap();
    assert!(
        matches!(closed, quinn::ConnectionError::TimedOut),
        "{closed:?}"
    );
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
