//! DNS over TLS and DNS over HTTPS against local servers that use the test
//! certificate authority in `tests/fixtures`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test helpers; the no-panic rules cover non-test code"
)]

use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use goethite_proto::{
    Edns, QUERY_PADDING_BLOCK, Query, Question, RecordClass, RecordType, Response, ResponseCode,
};
use goethite_resolver::{Forwarder, ForwarderConfig, ForwarderError, TlsRoots, UpstreamConfig};
use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::rr::rdata::opt::EdnsCode;
use hickory_proto::rr::{self, RData, rdata};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::CONTENT_TYPE;
use hyper::service::service_fn;
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const CA: &[u8] = include_bytes!("fixtures/ca.pem");
const CERT: &[u8] = include_bytes!("fixtures/server.pem");
const KEY: &[u8] = include_bytes!("fixtures/server.key");
const SERVER_NAME: &str = "dns.goethite.test";

fn acceptor(alpn: &[&[u8]]) -> TlsAcceptor {
    let certs = vec![CertificateDer::from_pem_slice(CERT).unwrap()];
    let key = PrivateKeyDer::from_pem_slice(KEY).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    TlsAcceptor::from(Arc::new(config))
}

fn test_roots() -> TlsRoots {
    TlsRoots::Custom(vec![CertificateDer::from_pem_slice(CA).unwrap().to_vec()])
}

/// A reply echoing the query's ID and question with one A record.
fn answer(query: &Message, ip: Ipv4Addr) -> Message {
    let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
    reply.metadata.recursion_available = true;
    reply.add_queries(query.queries.clone());
    let name = query.queries[0].name().clone();
    reply.add_answer(rr::Record::from_rdata(name, 300, RData::A(rdata::A(ip))));
    reply
}

#[derive(Clone, Default)]
struct Counters {
    connections: Arc<AtomicUsize>,
    queries: Arc<AtomicUsize>,
    ids: Arc<std::sync::Mutex<Vec<u16>>>,
    /// Each query's length on the wire, and whether it carried Padding.
    sizes: Arc<std::sync::Mutex<Vec<(usize, bool)>>>,
}

/// Notes `wire`'s length and padding in `counters`.
fn note_size(counters: &Counters, wire: &[u8], query: &Message) {
    let padded = query
        .edns
        .as_ref()
        .is_some_and(|edns| edns.options().get(EdnsCode::Padding).is_some());
    counters.sizes.lock().unwrap().push((wire.len(), padded));
}

impl Counters {
    /// Whether every query was padded to a multiple of 128 bytes.
    fn all_padded(&self) -> bool {
        let sizes = self.sizes.lock().unwrap();
        !sizes.is_empty()
            && sizes
                .iter()
                .all(|&(len, padded)| padded && len % QUERY_PADDING_BLOCK == 0)
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn queries(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }
}

/// A DoT server answering every query with `ip`. With `one_per_connection`
/// it closes each connection after one answer, like a server whose idle
/// timeout has passed.
async fn dot_server(ip: Ipv4Addr, one_per_connection: bool) -> (SocketAddr, Counters) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = acceptor(&[]);
    let counters = Counters::default();
    let seen = counters.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            seen.connections.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let seen = seen.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                loop {
                    let mut prefix = [0; 2];
                    if tls.read_exact(&mut prefix).await.is_err() {
                        return;
                    }
                    let mut buf = vec![0; usize::from(u16::from_be_bytes(prefix))];
                    tls.read_exact(&mut buf).await.unwrap();
                    let query = Message::from_vec(&buf).unwrap();
                    note_size(&seen, &buf, &query);
                    seen.queries.fetch_add(1, Ordering::SeqCst);
                    let wire = answer(&query, ip).to_vec().unwrap();
                    let len = u16::try_from(wire.len()).unwrap().to_be_bytes();
                    tls.write_all(&[&len[..], &wire].concat()).await.unwrap();
                    tls.flush().await.unwrap();
                    if one_per_connection {
                        return;
                    }
                }
            });
        }
    });
    (addr, counters)
}

#[derive(Clone, Copy)]
enum DohReply {
    Answer,
    Status(StatusCode),
    WrongContentType,
}

/// A DoH server over HTTP/2 on `/dns-query`.
async fn doh_server(ip: Ipv4Addr, reply: DohReply) -> (SocketAddr, Counters) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = acceptor(&[b"h2"]);
    let counters = Counters::default();
    let seen = counters.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            seen.connections.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let seen = seen.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let service = service_fn(move |request: Request<Incoming>| {
                    let seen = seen.clone();
                    async move {
                        assert_eq!(request.method(), Method::POST);
                        assert_eq!(request.uri().path(), "/dns-query");
                        assert_eq!(request.headers()[CONTENT_TYPE], "application/dns-message");
                        let body = request.into_body().collect().await.unwrap().to_bytes();
                        let query = Message::from_vec(&body).unwrap();
                        note_size(&seen, &body, &query);
                        seen.queries.fetch_add(1, Ordering::SeqCst);
                        seen.ids.lock().unwrap().push(query.metadata.id);
                        let wire = Bytes::from(answer(&query, ip).to_vec().unwrap());
                        let (status, content_type) = match reply {
                            DohReply::Answer => (StatusCode::OK, "application/dns-message"),
                            DohReply::Status(status) => (status, "application/dns-message"),
                            DohReply::WrongContentType => (StatusCode::OK, "text/html"),
                        };
                        let response = hyper::Response::builder()
                            .status(status)
                            .header(CONTENT_TYPE, content_type)
                            .body(Full::new(wire))
                            .unwrap();
                        Ok::<_, Infallible>(response)
                    }
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    (addr, counters)
}

fn query(name: &str) -> Query {
    Query {
        id: 99,
        recursion_desired: true,
        checking_disabled: false,
        authentic_data: false,
        question: Question {
            name: name.parse().unwrap(),
            qtype: RecordType::A,
            qclass: RecordClass::IN,
        },
        edns: Some(Edns {
            udp_payload_size: 1232,
            dnssec_ok: false,
            padding: false,
        }),
    }
}

fn forwarder(upstream: UpstreamConfig, roots: TlsRoots) -> Forwarder {
    let mut config = ForwarderConfig::new(vec![upstream]);
    config.tls_roots = roots;
    config.attempt_timeout = Duration::from_secs(2);
    config.total_timeout = Duration::from_secs(2);
    Forwarder::new(config).unwrap()
}

fn ip(response: &Response) -> Option<std::net::IpAddr> {
    response
        .answers
        .first()
        .and_then(goethite_proto::Record::ip)
}

#[tokio::test]
async fn dot_forwards_and_reuses_connections() {
    let (addr, counters) = dot_server(Ipv4Addr::new(192, 0, 2, 10), false).await;
    let forwarder = forwarder(UpstreamConfig::tls(addr, SERVER_NAME), test_roots());
    for name in ["a.example.", "b.example.", "c.example."] {
        let response = forwarder.forward(&query(name)).await;
        assert_eq!(response.rcode, ResponseCode::NO_ERROR, "{name}");
        assert_eq!(ip(&response), Some(Ipv4Addr::new(192, 0, 2, 10).into()));
        assert_eq!(response.id, 99);
    }
    assert_eq!(counters.queries(), 3);
    assert_eq!(
        counters.connections(),
        1,
        "one TLS connection for all queries"
    );
    assert!(
        counters.all_padded(),
        "{:?}",
        counters.sizes.lock().unwrap()
    );
}

#[tokio::test]
async fn dot_reconnects_when_the_server_closed_the_connection() {
    let (addr, counters) = dot_server(Ipv4Addr::new(192, 0, 2, 11), true).await;
    let forwarder = forwarder(UpstreamConfig::tls(addr, SERVER_NAME), test_roots());
    for name in ["a.example.", "b.example."] {
        let response = forwarder.forward(&query(name)).await;
        assert_eq!(ip(&response), Some(Ipv4Addr::new(192, 0, 2, 11).into()));
    }
    assert_eq!(counters.queries(), 2);
    assert_eq!(counters.connections(), 2);
}

#[tokio::test]
async fn dot_accepts_an_ip_address_as_server_name() {
    let (addr, _) = dot_server(Ipv4Addr::new(192, 0, 2, 12), false).await;
    let forwarder = forwarder(UpstreamConfig::tls(addr, "127.0.0.1"), test_roots());
    let response = forwarder.forward(&query("ip.example.")).await;
    assert_eq!(ip(&response), Some(Ipv4Addr::new(192, 0, 2, 12).into()));
}

#[tokio::test]
async fn dot_rejects_a_certificate_for_another_name() {
    let (addr, counters) = dot_server(Ipv4Addr::new(192, 0, 2, 13), false).await;
    let forwarder = forwarder(
        UpstreamConfig::tls(addr, "other.goethite.test"),
        test_roots(),
    );
    let response = forwarder.forward(&query("mitm.example.")).await;
    assert_eq!(response.rcode, ResponseCode::SERV_FAIL);
    assert_eq!(
        counters.queries(),
        0,
        "nothing is sent before the name checks out"
    );
}

#[tokio::test]
async fn dot_rejects_an_untrusted_certificate() {
    let (addr, counters) = dot_server(Ipv4Addr::new(192, 0, 2, 14), false).await;
    // The bundled Mozilla roots do not include the test CA.
    let forwarder = forwarder(UpstreamConfig::tls(addr, SERVER_NAME), TlsRoots::Bundled);
    let response = forwarder.forward(&query("untrusted.example.")).await;
    assert_eq!(response.rcode, ResponseCode::SERV_FAIL);
    assert_eq!(counters.queries(), 0);
}

#[tokio::test]
async fn doh_multiplexes_queries_over_one_connection_with_id_zero() {
    let (addr, counters) = doh_server(Ipv4Addr::new(192, 0, 2, 20), DohReply::Answer).await;
    let url = format!("https://{SERVER_NAME}:{}/dns-query", addr.port());
    let forwarder = Arc::new(forwarder(UpstreamConfig::https(addr, url), test_roots()));

    // Open the connection, then send three queries at once over it.
    let first = forwarder.forward(&query("first.example.")).await;
    assert_eq!(ip(&first), Some(Ipv4Addr::new(192, 0, 2, 20).into()));
    let concurrent = ["a.example.", "b.example.", "c.example."].map(|name| {
        let forwarder = Arc::clone(&forwarder);
        tokio::spawn(async move { forwarder.forward(&query(name)).await })
    });
    for task in concurrent {
        let response = task.await.unwrap();
        assert_eq!(response.rcode, ResponseCode::NO_ERROR);
        assert_eq!(response.id, 99, "the client's own ID comes back");
    }
    assert_eq!(counters.queries(), 4);
    assert_eq!(counters.connections(), 1, "HTTP/2 multiplexing");
    assert!(counters.ids.lock().unwrap().iter().all(|&id| id == 0));
    assert!(
        counters.all_padded(),
        "{:?}",
        counters.sizes.lock().unwrap()
    );
}

#[tokio::test]
async fn doh_http_errors_and_wrong_content_types_are_failures() {
    for reply in [
        DohReply::Status(StatusCode::SERVICE_UNAVAILABLE),
        DohReply::WrongContentType,
    ] {
        let (addr, counters) = doh_server(Ipv4Addr::new(192, 0, 2, 21), reply).await;
        let url = format!("https://{SERVER_NAME}:{}/dns-query", addr.port());
        let forwarder = forwarder(UpstreamConfig::https(addr, url), test_roots());
        let response = forwarder.forward(&query("err.example.")).await;
        assert_eq!(response.rcode, ResponseCode::SERV_FAIL);
        assert_eq!(counters.queries(), 1);
    }
}

#[test]
fn invalid_tls_settings_are_rejected() {
    let addr: SocketAddr = "127.0.0.1:853".parse().unwrap();
    let new = |upstream| Forwarder::new(ForwarderConfig::new(vec![upstream]));
    assert!(matches!(
        new(UpstreamConfig::tls(addr, "not a name!")),
        Err(ForwarderError::InvalidServerName(_))
    ));
    for url in [
        "http://dns.example/dns-query",
        "https:///dns-query",
        "dns.example",
        "",
    ] {
        assert!(
            matches!(
                new(UpstreamConfig::https(addr, url)),
                Err(ForwarderError::InvalidUrl(_))
            ),
            "{url}"
        );
    }
    let mut config = ForwarderConfig::new(vec![UpstreamConfig::tls(addr, SERVER_NAME)]);
    config.tls_roots = TlsRoots::Custom(vec![b"not a certificate".to_vec()]);
    assert!(matches!(
        Forwarder::new(config),
        Err(ForwarderError::Tls(_))
    ));
}
