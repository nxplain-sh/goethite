//! End-to-end tests of the UDP and TCP listeners on ephemeral ports.
//!
//! Queries are built and responses checked with hickory-proto directly, as an
//! independent reference rather than goethite's own codec.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers; the no-panic rules cover non-test code"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use goethite_resolver::{Forwarder, ForwarderConfig, Resolver, UpstreamConfig, test_record};
use goethite_server::{
    Listeners, RateLimitConfig, Server, ServerConfig, ServerError, ServerStats, Transport,
};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType, rdata::A};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(5);

struct Running {
    udp: SocketAddr,
    tcp: SocketAddr,
    stats: std::sync::Arc<ServerStats>,
    stop: oneshot::Sender<()>,
    task: JoinHandle<Result<(), ServerError>>,
}

impl Running {
    async fn shutdown(self) {
        self.stop.send(()).unwrap();
        timeout(WAIT, self.task).await.unwrap().unwrap().unwrap();
    }
}

fn start_with(config: impl FnOnce(&mut ServerConfig)) -> Running {
    start_resolving(config, Resolver::new(vec![test_record().unwrap()]))
}

fn start_resolving(config: impl FnOnce(&mut ServerConfig), resolver: Resolver) -> Running {
    let mut server_config = ServerConfig::new(vec!["127.0.0.1:0".parse().unwrap()]);
    config(&mut server_config);
    let server = Server::bind(server_config, std::sync::Arc::new(resolver)).unwrap();
    let udp = server.udp_local_addrs().unwrap()[0];
    let tcp = server.tcp_local_addrs().unwrap()[0];
    let stats = server.stats();
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(server.run(async {
        let _ = stopped.await;
    }));
    Running {
        udp,
        tcp,
        stats,
        stop,
        task,
    }
}

fn start() -> Running {
    start_with(|_| {})
}

fn query(id: u16, name: &str, record_type: RecordType) -> Vec<u8> {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_str(name).unwrap(), record_type));
    message.set_edns(Edns::new());
    message.to_vec().unwrap()
}

async fn udp_exchange(server: SocketAddr, wire: &[u8]) -> Option<Message> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(wire, server).await.unwrap();
    let mut buf = vec![0; 65_535];
    let len = timeout(Duration::from_millis(500), socket.recv(&mut buf))
        .await
        .ok()?
        .unwrap();
    Some(Message::from_vec(&buf[..len]).unwrap())
}

async fn tcp_send(stream: &mut TcpStream, wire: &[u8]) {
    let len = u16::try_from(wire.len()).unwrap().to_be_bytes();
    stream.write_all(&len).await.unwrap();
    stream.write_all(wire).await.unwrap();
}

async fn tcp_receive(stream: &mut TcpStream) -> Message {
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

/// Waits for the server to close the connection.
async fn assert_closed(stream: &mut TcpStream) {
    let mut buf = [0; 1];
    let read = timeout(WAIT, stream.read(&mut buf)).await.unwrap();
    assert!(matches!(read, Ok(0) | Err(_)), "connection still open");
}

fn assert_test_answer(response: &Message, id: u16) {
    assert_eq!(response.metadata.id, id);
    assert_eq!(response.metadata.message_type, MessageType::Response);
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(response.metadata.authoritative);
    assert_eq!(response.answers.len(), 1);
    let answer = &response.answers[0];
    assert_eq!(answer.name, Name::from_str("goethite.test.").unwrap());
    assert_eq!(answer.data, RData::A(A(Ipv4Addr::new(127, 0, 0, 53))));
    assert_eq!(answer.ttl, 60);
}

#[tokio::test]
async fn udp_answers_the_test_name() {
    let server = start();
    let response = udp_exchange(server.udp, &query(1, "goethite.test.", RecordType::A))
        .await
        .unwrap();
    assert_test_answer(&response, 1);
    assert!(response.edns.is_some(), "EDNS is echoed");
    server.shutdown().await;
}

#[tokio::test]
async fn tcp_answers_the_test_name() {
    let server = start();
    let mut stream = TcpStream::connect(server.tcp).await.unwrap();
    tcp_send(&mut stream, &query(2, "goethite.test.", RecordType::A)).await;
    assert_test_answer(&tcp_receive(&mut stream).await, 2);
    drop(stream);
    server.shutdown().await;
}

#[tokio::test]
async fn other_names_are_refused() {
    let server = start();
    let wire = query(3, "example.com.", RecordType::A);

    let over_udp = udp_exchange(server.udp, &wire).await.unwrap();
    let mut stream = TcpStream::connect(server.tcp).await.unwrap();
    tcp_send(&mut stream, &wire).await;
    let over_tcp = tcp_receive(&mut stream).await;

    for response in [over_udp, over_tcp] {
        assert_eq!(response.metadata.id, 3);
        assert_eq!(response.metadata.response_code, ResponseCode::Refused);
        assert_eq!(response.answers, vec![]);
    }
    drop(stream);
    server.shutdown().await;
}

#[tokio::test]
async fn other_types_of_the_test_name_get_nodata() {
    let server = start();
    let response = udp_exchange(server.udp, &query(4, "goethite.test.", RecordType::AAAA))
        .await
        .unwrap();
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(response.metadata.id, 4);
    assert_eq!(response.answers, vec![]);
    server.shutdown().await;
}

#[tokio::test]
async fn garbage_is_dropped_and_the_server_keeps_answering() {
    let server = start();
    let valid = query(5, "goethite.test.", RecordType::A);
    let garbage: [&[u8]; 4] = [
        b"",
        b"\x00\x01",
        // A plausible header, then a name that is a dangling compression pointer.
        &[0, 8, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 1, 0, 1],
        // Cut off inside the question.
        &valid[..20],
    ];
    for wire in garbage {
        assert!(udp_exchange(server.udp, wire).await.is_none(), "{wire:?}");
    }

    // A response must never be answered (reflection loops).
    let mut response = Message::from_vec(&valid).unwrap();
    response.metadata.message_type = MessageType::Response;
    assert!(
        udp_exchange(server.udp, &response.to_vec().unwrap())
            .await
            .is_none()
    );

    let mut stream = TcpStream::connect(server.tcp).await.unwrap();
    tcp_send(&mut stream, b"garbage").await;
    assert_closed(&mut stream).await;

    assert_test_answer(&udp_exchange(server.udp, &valid).await.unwrap(), 5);
    server.shutdown().await;
}

#[tokio::test]
async fn malformed_queries_with_a_valid_header_get_error_responses() {
    let server = start();
    // A header with no question: FORMERR.
    let no_question = [0, 6, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let response = udp_exchange(server.udp, &no_question).await.unwrap();
    assert_eq!(response.metadata.id, 6);
    assert_eq!(response.metadata.response_code, ResponseCode::FormErr);

    // A readable question but a cut-off OPT record: FORMERR.
    let valid = query(8, "goethite.test.", RecordType::A);
    let response = udp_exchange(server.udp, &valid[..valid.len() - 3])
        .await
        .unwrap();
    assert_eq!(response.metadata.id, 8);
    assert_eq!(response.metadata.response_code, ResponseCode::FormErr);

    // A NOTIFY: NOTIMP.
    let mut notify = Message::from_vec(&query(7, "goethite.test.", RecordType::SOA)).unwrap();
    notify.metadata.op_code = OpCode::Notify;
    let response = udp_exchange(server.udp, &notify.to_vec().unwrap())
        .await
        .unwrap();
    assert_eq!(response.metadata.response_code, ResponseCode::NotImp);
    server.shutdown().await;
}

#[tokio::test]
async fn tcp_serves_several_queries_per_connection() {
    let server = start();
    let mut stream = TcpStream::connect(server.tcp).await.unwrap();
    tcp_send(&mut stream, &query(10, "goethite.test.", RecordType::A)).await;
    tcp_send(&mut stream, &query(11, "example.com.", RecordType::A)).await;
    assert_test_answer(&tcp_receive(&mut stream).await, 10);
    let refused = tcp_receive(&mut stream).await;
    assert_eq!(refused.metadata.id, 11);
    assert_eq!(refused.metadata.response_code, ResponseCode::Refused);
    drop(stream);
    server.shutdown().await;
}

#[tokio::test]
async fn tcp_connections_beyond_the_limit_are_closed() {
    let server = start_with(|config| config.max_tcp_connections = 1);
    let mut first = TcpStream::connect(server.tcp).await.unwrap();
    // Make sure the server has accepted the first connection.
    tcp_send(&mut first, &query(12, "goethite.test.", RecordType::A)).await;
    tcp_receive(&mut first).await;

    let mut second = TcpStream::connect(server.tcp).await.unwrap();
    assert_closed(&mut second).await;

    // The first connection is unaffected.
    tcp_send(&mut first, &query(13, "goethite.test.", RecordType::A)).await;
    assert_test_answer(&tcp_receive(&mut first).await, 13);
    drop(first);
    server.shutdown().await;
}

#[tokio::test]
async fn huge_connection_limits_are_clamped_not_fatal() {
    let server = start_with(|config| config.max_tcp_connections = usize::MAX);
    let mut stream = TcpStream::connect(server.tcp).await.unwrap();
    tcp_send(&mut stream, &query(16, "goethite.test.", RecordType::A)).await;
    assert_test_answer(&tcp_receive(&mut stream).await, 16);
    drop(stream);
    server.shutdown().await;
}

#[tokio::test]
async fn zone_transfers_and_meta_types_are_not_answered_with_data() {
    let server = start();
    let mut stream = TcpStream::connect(server.tcp).await.unwrap();
    tcp_send(&mut stream, &query(17, "goethite.test.", RecordType::AXFR)).await;
    let axfr = tcp_receive(&mut stream).await;
    assert_eq!(axfr.metadata.response_code, ResponseCode::Refused);
    assert_eq!(axfr.answers, vec![]);
    drop(stream);

    let tsig = udp_exchange(server.udp, &query(18, "goethite.test.", RecordType::TSIG))
        .await
        .unwrap();
    assert_eq!(tsig.metadata.response_code, ResponseCode::FormErr);
    server.shutdown().await;
}

#[tokio::test]
async fn idle_tcp_connections_are_closed() {
    let server = start_with(|config| config.tcp_idle_timeout = Duration::from_millis(200));
    let mut stream = TcpStream::connect(server.tcp).await.unwrap();
    assert_closed(&mut stream).await;
    server.shutdown().await;
}

#[tokio::test]
async fn shutdown_closes_listeners_and_idle_connections() {
    let server = start();
    let (udp, tcp) = (server.udp, server.tcp);
    let mut idle = TcpStream::connect(tcp).await.unwrap();
    tcp_send(&mut idle, &query(14, "goethite.test.", RecordType::A)).await;
    tcp_receive(&mut idle).await;

    server.shutdown().await;

    assert_closed(&mut idle).await;
    assert!(TcpStream::connect(tcp).await.is_err());
    assert!(
        udp_exchange(udp, &query(15, "goethite.test.", RecordType::A))
            .await
            .is_none()
    );
}

#[tokio::test]
async fn binding_a_busy_address_fails() {
    let server = start();
    let config = ServerConfig::new(vec![server.tcp]);
    let result = Server::bind(config, std::sync::Arc::new(Resolver::new(Vec::new())));
    assert!(matches!(result, Err(ServerError::Bind { .. })));
    server.shutdown().await;
}

#[test]
fn listen_addresses_are_bounded() {
    let none = ServerConfig::new(Vec::new());
    assert!(matches!(
        Listeners::bind(&none),
        Err(ServerError::NoListenAddresses)
    ));
    let many = ServerConfig::new(vec!["127.0.0.1:0".parse().unwrap(); 17]);
    assert!(matches!(
        Listeners::bind(&many),
        Err(ServerError::TooManyListenAddresses(17))
    ));
}

#[tokio::test]
async fn serves_every_listen_address() {
    let localhost: SocketAddr = "127.0.0.1:0".parse().unwrap();
    // Bound before the runtime is involved, as the binary does.
    let config = ServerConfig::new(vec![localhost, localhost]);
    let listeners = Listeners::bind(&config).unwrap();
    let udp = listeners.udp_local_addrs().unwrap();
    let tcp = listeners.tcp_local_addrs().unwrap();
    assert_eq!((udp.len(), tcp.len()), (2, 2));
    assert_ne!(udp[0], udp[1]);
    let resolver = std::sync::Arc::new(Resolver::new(vec![test_record().unwrap()]));
    let server = Server::new(listeners, config, resolver).unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(server.run(async {
        let _ = stopped.await;
    }));
    for (id, (&udp, &tcp)) in (40..).zip(udp.iter().zip(&tcp)) {
        let answer = udp_exchange(udp, &query(id, "goethite.test.", RecordType::A)).await;
        assert_test_answer(&answer.unwrap(), id);
        let mut stream = TcpStream::connect(tcp).await.unwrap();
        tcp_send(&mut stream, &query(id, "goethite.test.", RecordType::A)).await;
        assert_test_answer(&tcp_receive(&mut stream).await, id);
    }
    stop.send(()).unwrap();
    timeout(WAIT, task).await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn several_udp_sockets_all_answer() {
    // On Linux these are SO_REUSEPORT sockets sharing the port, and the
    // kernel spreads clients over them; elsewhere there is one socket.
    let server = start_with(|config| config.udp_sockets = 4);
    let udp = server.udp;
    let mut exchanges = tokio::task::JoinSet::new();
    for id in 0..64 {
        let wire = query(id, "goethite.test.", RecordType::A);
        exchanges.spawn(async move { (id, udp_exchange_waiting(udp, wire).await) });
    }
    while let Some(joined) = exchanges.join_next().await {
        let (id, answer) = joined.unwrap();
        assert_test_answer(&answer.unwrap(), id);
    }
    server.shutdown().await;
}

#[tokio::test]
async fn tcp_connections_per_client_are_limited() {
    let server = start_with(|config| config.max_tcp_connections_per_client = 1);
    let mut first = TcpStream::connect(server.tcp).await.unwrap();
    tcp_send(&mut first, &query(50, "goethite.test.", RecordType::A)).await;
    tcp_receive(&mut first).await;

    let mut second = TcpStream::connect(server.tcp).await.unwrap();
    assert_closed(&mut second).await;
    tcp_send(&mut first, &query(51, "goethite.test.", RecordType::A)).await;
    assert_test_answer(&tcp_receive(&mut first).await, 51);

    // Closing the first connection frees the client's slot.
    drop(first);
    let mut third = None;
    for _ in 0..50 {
        let mut stream = TcpStream::connect(server.tcp).await.unwrap();
        tcp_send(&mut stream, &query(52, "goethite.test.", RecordType::A)).await;
        let mut len = [0; 2];
        if timeout(WAIT, stream.read_exact(&mut len))
            .await
            .unwrap()
            .is_ok()
        {
            third = Some(());
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(third.is_some(), "the slot was not released");
    server.shutdown().await;
}

#[tokio::test]
async fn rate_limited_clients_are_told_to_use_tcp_then_refused() {
    let server = start_with(|config| {
        config.rate_limit = RateLimitConfig {
            queries_per_second: 1,
            burst: 2,
            slip: 1,
            exempt_loopback: false,
            ..RateLimitConfig::default()
        };
    });
    for id in [60, 61] {
        let answer = udp_exchange(server.udp, &query(id, "goethite.test.", RecordType::A)).await;
        assert_test_answer(&answer.unwrap(), id);
    }
    let limited = udp_exchange(server.udp, &query(62, "goethite.test.", RecordType::A))
        .await
        .unwrap();
    assert_eq!(limited.metadata.id, 62);
    assert!(limited.metadata.truncation, "TC is set");
    assert_eq!(limited.answers, vec![]);
    assert_eq!(limited.queries.len(), 1, "the question is echoed");
    assert_eq!(server.stats.rate_limited.get(Transport::Udp), 1);
    assert_eq!(
        server
            .stats
            .rate_limit_slips
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );

    // The same client over TCP shares the budget, and is refused.
    let mut stream = TcpStream::connect(server.tcp).await.unwrap();
    tcp_send(&mut stream, &query(63, "goethite.test.", RecordType::A)).await;
    let refused = tcp_receive(&mut stream).await;
    assert_eq!(refused.metadata.id, 63);
    assert_eq!(refused.metadata.response_code, ResponseCode::Refused);
    assert!(!refused.metadata.truncation, "TCP needs no retry hint");
    assert_eq!(server.stats.rate_limited.get(Transport::Tcp), 1);
    drop(stream);
    server.shutdown().await;
}

/// A fake upstream on loopback that answers every query with `ip` after
/// `delay`, or never if `ip` is `None`.
async fn upstream(ip: Option<Ipv4Addr>, delay: Duration) -> SocketAddr {
    let socket = std::sync::Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0; 65_535];
        loop {
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            let Some(ip) = ip else { continue };
            let query = Message::from_vec(&buf[..len]).unwrap();
            let socket = std::sync::Arc::clone(&socket);
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let mut reply =
                    Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                reply.add_queries(query.queries.clone());
                let name = query.queries[0].name().clone();
                reply.add_answer(hickory_proto::rr::Record::from_rdata(
                    name,
                    300,
                    RData::A(A(ip)),
                ));
                socket
                    .send_to(&reply.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            });
        }
    });
    addr
}

fn forwarding_to(upstream: SocketAddr, attempt: Duration) -> Resolver {
    let mut config = ForwarderConfig::new(vec![UpstreamConfig::udp(upstream)]);
    config.attempt_timeout = attempt;
    config.total_timeout = attempt;
    Resolver::new(vec![test_record().unwrap()]).with_forwarder(Forwarder::new(config).unwrap())
}

#[tokio::test]
async fn other_names_are_forwarded_upstream() {
    let upstream = upstream(Some(Ipv4Addr::new(192, 0, 2, 80)), Duration::ZERO).await;
    let server = start_resolving(|_| {}, forwarding_to(upstream, Duration::from_secs(2)));

    let over_udp = udp_exchange(server.udp, &query(20, "example.com.", RecordType::A))
        .await
        .unwrap();
    let mut stream = TcpStream::connect(server.tcp).await.unwrap();
    tcp_send(&mut stream, &query(21, "example.com.", RecordType::A)).await;
    let over_tcp = tcp_receive(&mut stream).await;

    for (response, id) in [(over_udp, 20), (over_tcp, 21)] {
        assert_eq!(response.metadata.id, id);
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.metadata.recursion_available);
        assert!(!response.metadata.authoritative);
        assert_eq!(
            response.answers[0].data,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 80)))
        );
    }
    // The local name is still answered locally, now with RA set.
    let local = udp_exchange(server.udp, &query(22, "goethite.test.", RecordType::A))
        .await
        .unwrap();
    assert_test_answer(&local, 22);
    assert!(local.metadata.recursion_available);
    drop(stream);
    server.shutdown().await;
}

#[tokio::test]
async fn a_slow_upstream_does_not_block_other_queries() {
    let upstream = upstream(
        Some(Ipv4Addr::new(192, 0, 2, 81)),
        Duration::from_millis(800),
    )
    .await;
    let server = start_resolving(|_| {}, forwarding_to(upstream, Duration::from_secs(3)));
    let slow = tokio::spawn(udp_exchange_waiting(
        server.udp,
        query(23, "slow.example.", RecordType::A),
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let started = tokio::time::Instant::now();
    let local = udp_exchange(server.udp, &query(24, "goethite.test.", RecordType::A))
        .await
        .unwrap();
    assert_test_answer(&local, 24);
    assert!(started.elapsed() < Duration::from_millis(500));
    let slow = slow.await.unwrap().unwrap();
    assert_eq!(
        slow.answers[0].data,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 81)))
    );
    server.shutdown().await;
}

#[tokio::test]
async fn queries_beyond_the_inflight_limit_are_dropped() {
    let silent = upstream(None, Duration::ZERO).await;
    let server = start_resolving(
        |config| config.max_inflight_udp_queries = 1,
        forwarding_to(silent, Duration::from_millis(1500)),
    );
    let stuck = tokio::spawn(udp_exchange_waiting(
        server.udp,
        query(25, "stuck.example.", RecordType::A),
    ));
    tokio::time::sleep(Duration::from_millis(200)).await;
    // The only slot is taken, so even a local name is dropped for now.
    assert!(
        udp_exchange(server.udp, &query(26, "goethite.test.", RecordType::A))
            .await
            .is_none()
    );
    // Once the stuck query gives up (SERVFAIL), the slot is free again.
    let failed = stuck.await.unwrap().unwrap();
    assert_eq!(failed.metadata.response_code, ResponseCode::ServFail);
    let local = udp_exchange(server.udp, &query(27, "goethite.test.", RecordType::A))
        .await
        .unwrap();
    assert_test_answer(&local, 27);
    server.shutdown().await;
}

#[tokio::test]
async fn shutdown_abandons_slow_queries_after_the_grace_period() {
    let silent = upstream(None, Duration::ZERO).await;
    let server = start_resolving(
        |config| config.shutdown_grace = Duration::from_millis(200),
        forwarding_to(silent, Duration::from_secs(30)),
    );
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(&query(28, "stuck.example.", RecordType::A), server.udp)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let started = tokio::time::Instant::now();
    server.shutdown().await;
    assert!(started.elapsed() < Duration::from_secs(3));
}

/// Like `udp_exchange`, but waits up to five seconds for the answer.
async fn udp_exchange_waiting(server: SocketAddr, wire: Vec<u8>) -> Option<Message> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&wire, server).await.unwrap();
    let mut buf = vec![0; 65_535];
    let len = timeout(WAIT, socket.recv(&mut buf)).await.ok()?.unwrap();
    Some(Message::from_vec(&buf[..len]).unwrap())
}
