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

use goethite_resolver::{Resolver, test_record};
use goethite_server::{Server, ServerConfig, ServerError};
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
    stop: oneshot::Sender<()>,
    task: JoinHandle<Result<(), ServerError>>,
}

impl Running {
    async fn shutdown(self) {
        self.stop.send(()).unwrap();
        timeout(WAIT, self.task).await.unwrap().unwrap().unwrap();
    }
}

async fn start_with(config: impl FnOnce(&mut ServerConfig)) -> Running {
    let mut server_config = ServerConfig::new("127.0.0.1:0".parse().unwrap());
    config(&mut server_config);
    let resolver = Resolver::new(vec![test_record().unwrap()]);
    let server = Server::bind(server_config, resolver).await.unwrap();
    let udp = server.udp_local_addr().unwrap();
    let tcp = server.tcp_local_addr().unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(server.run(async {
        let _ = stopped.await;
    }));
    Running {
        udp,
        tcp,
        stop,
        task,
    }
}

async fn start() -> Running {
    start_with(|_| {}).await
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
    let server = start().await;
    let response = udp_exchange(server.udp, &query(1, "goethite.test.", RecordType::A))
        .await
        .unwrap();
    assert_test_answer(&response, 1);
    assert!(response.edns.is_some(), "EDNS is echoed");
    server.shutdown().await;
}

#[tokio::test]
async fn tcp_answers_the_test_name() {
    let server = start().await;
    let mut stream = TcpStream::connect(server.tcp).await.unwrap();
    tcp_send(&mut stream, &query(2, "goethite.test.", RecordType::A)).await;
    assert_test_answer(&tcp_receive(&mut stream).await, 2);
    drop(stream);
    server.shutdown().await;
}

#[tokio::test]
async fn other_names_are_refused() {
    let server = start().await;
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
    let server = start().await;
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
    let server = start().await;
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
    let server = start().await;
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
    let server = start().await;
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
    let server = start_with(|config| config.max_tcp_connections = 1).await;
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
async fn zone_transfers_and_meta_types_are_not_answered_with_data() {
    let server = start().await;
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
    let server = start_with(|config| config.tcp_idle_timeout = Duration::from_millis(200)).await;
    let mut stream = TcpStream::connect(server.tcp).await.unwrap();
    assert_closed(&mut stream).await;
    server.shutdown().await;
}

#[tokio::test]
async fn shutdown_closes_listeners_and_idle_connections() {
    let server = start().await;
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
    let server = start().await;
    let config = ServerConfig::new(server.tcp);
    let result = Server::bind(config, Resolver::new(Vec::new())).await;
    assert!(matches!(result, Err(ServerError::Bind { .. })));
    server.shutdown().await;
}
