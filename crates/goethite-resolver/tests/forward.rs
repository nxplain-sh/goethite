//! Forwarding against scripted fake upstreams on loopback.
//!
//! The fakes are built with hickory-proto directly, so they check goethite's
//! wire format against an independent implementation.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test helpers; the no-panic rules cover non-test code"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use goethite_filter::{Filter, FilterBuilder, Source};
use goethite_proto::{Edns, Name, Query, Question, RecordClass, RecordType, ResponseCode};
use goethite_resolver::{
    BlockResponse, Blocking, Cache, CacheConfig, Forwarder, ForwarderConfig, RebindingProtection,
    Resolver, Transport, UpstreamConfig,
};
use hickory_proto::op::{self, Message, MessageType, OpCode};
use hickory_proto::rr::{self, RData, rdata};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// Turns one query into the messages the fake sends back, in order.
type Script = Arc<dyn Fn(&Message) -> Vec<Message> + Send + Sync>;

struct Fake {
    addr: SocketAddr,
    /// Every query the fake received, as parsed by hickory.
    seen: Arc<Mutex<Vec<Message>>>,
}

impl Fake {
    fn seen_names(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|m| m.queries[0].name().to_ascii())
            .collect()
    }
}

/// A fake upstream answering on UDP and TCP on the same port.
async fn fake(udp: Script, tcp: Script) -> Fake {
    let (socket, listener) = loop {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)).await {
            break (socket, listener);
        }
    };
    let addr = socket.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));

    let udp_seen = Arc::clone(&seen);
    tokio::spawn(async move {
        let mut buf = vec![0; 65_535];
        loop {
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            let query = Message::from_vec(&buf[..len]).unwrap();
            udp_seen.lock().unwrap().push(query.clone());
            for reply in udp(&query) {
                socket
                    .send_to(&reply.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        }
    });

    let tcp_seen = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut prefix = [0; 2];
            stream.read_exact(&mut prefix).await.unwrap();
            let mut buf = vec![0; usize::from(u16::from_be_bytes(prefix))];
            stream.read_exact(&mut buf).await.unwrap();
            let query = Message::from_vec(&buf).unwrap();
            tcp_seen.lock().unwrap().push(query.clone());
            for reply in tcp(&query) {
                let wire = reply.to_vec().unwrap();
                let len = u16::try_from(wire.len()).unwrap().to_be_bytes();
                stream.write_all(&[&len[..], &wire].concat()).await.unwrap();
            }
        }
    });

    Fake { addr, seen }
}

/// A reply to `query` echoing its ID and question, with an A record for the
/// question name (in the case the query used).
fn answer(query: &Message, ip: Ipv4Addr) -> Message {
    let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
    reply.metadata.recursion_desired = query.metadata.recursion_desired;
    reply.metadata.recursion_available = true;
    reply.add_queries(query.queries.clone());
    let name = query.queries[0].name().clone();
    reply.add_answer(rr::Record::from_rdata(name, 300, RData::A(rdata::A(ip))));
    if let Some(edns) = &query.edns {
        let mut ours = op::Edns::new();
        ours.set_max_payload(1232)
            .set_dnssec_ok(edns.flags().dnssec_ok);
        reply.set_edns(ours);
    }
    reply
}

fn script(f: impl Fn(&Message) -> Vec<Message> + Send + Sync + 'static) -> Script {
    Arc::new(f)
}

fn always(ip: Ipv4Addr) -> Script {
    script(move |q| vec![answer(q, ip)])
}

fn silent() -> Script {
    script(|_| Vec::new())
}

fn query(name: &str) -> Query {
    Query {
        id: 4242,
        recursion_desired: true,
        checking_disabled: false,
        authentic_data: false,
        question: Question {
            name: name.parse().unwrap(),
            qtype: RecordType::A,
            qclass: RecordClass::IN,
        },
        edns: Some(Edns {
            udp_payload_size: 4096,
            dnssec_ok: false,
        }),
    }
}

fn forwarder(upstreams: Vec<UpstreamConfig>) -> Forwarder {
    let mut config = ForwarderConfig::new(upstreams);
    config.attempt_timeout = Duration::from_millis(300);
    config.total_timeout = Duration::from_secs(2);
    Forwarder::new(config).unwrap()
}

fn ip(response: &goethite_proto::Response) -> Option<std::net::IpAddr> {
    response
        .answers
        .first()
        .and_then(goethite_proto::Record::ip)
}

#[tokio::test]
async fn forwards_and_restores_the_clients_view() {
    let upstream = fake(always(Ipv4Addr::new(192, 0, 2, 7)), silent()).await;
    let forwarder = forwarder(vec![UpstreamConfig::udp(upstream.addr)]);

    let query = query("Example.COM.");
    let response = forwarder.forward(&query).await;

    assert_eq!(response.rcode, ResponseCode::NO_ERROR);
    assert_eq!(response.id, 4242);
    assert!(response.recursion_available);
    assert!(!response.authoritative);
    assert!(
        response
            .question
            .as_ref()
            .unwrap()
            .matches_exactly(&query.question)
    );
    assert_eq!(ip(&response), Some(Ipv4Addr::new(192, 0, 2, 7).into()));
    // The answer's owner name is in the client's case, not the randomized one.
    assert!(response.answers[0].name().eq_exact(&query.question.name));

    let sent = upstream.seen.lock().unwrap()[0].clone();
    assert_ne!(sent.metadata.id, 4242, "a fresh random ID is used upstream");
    assert!(sent.metadata.recursion_desired);
    assert_eq!(sent.edns.as_ref().unwrap().max_payload(), 1232);
}

#[tokio::test]
async fn query_names_are_case_randomized() {
    let upstream = fake(always(Ipv4Addr::new(192, 0, 2, 1)), silent()).await;
    let forwarder = forwarder(vec![UpstreamConfig::udp(upstream.addr)]);
    // 40 letters: the chance of no flip at all is 2^-40.
    let name = "abcdefghijklmnopqrstuvwxyzabcdefghijklmn.test.";
    let response = forwarder.forward(&query(name)).await;
    assert_eq!(response.rcode, ResponseCode::NO_ERROR);

    let seen = upstream.seen_names();
    assert_eq!(seen[0].to_ascii_lowercase(), name);
    assert_ne!(seen[0], name, "the upstream saw a randomized case");
}

#[tokio::test]
async fn spoofed_responses_are_ignored() {
    let real = Ipv4Addr::new(192, 0, 2, 9);
    let fake_ip = Ipv4Addr::new(203, 0, 113, 66);
    let upstream = fake(
        script(move |q| {
            let mut wrong_id = answer(q, fake_ip);
            wrong_id.metadata.id = q.metadata.id.wrapping_add(1);
            let mut wrong_case = answer(q, fake_ip);
            let lower = wrong_case.queries[0].name().to_lowercase();
            wrong_case.queries[0].set_name(lower);
            let mut wrong_type = answer(q, fake_ip);
            wrong_type.queries[0].set_query_type(rr::RecordType::AAAA);
            vec![wrong_id, wrong_case, wrong_type, answer(q, real)]
        }),
        silent(),
    )
    .await;
    let forwarder = forwarder(vec![UpstreamConfig::udp(upstream.addr)]);
    let response = forwarder.forward(&query("SpOoFeD.ExAmPlE.")).await;
    assert_eq!(ip(&response), Some(real.into()));
}

#[tokio::test]
async fn truncated_answers_are_retried_over_tcp() {
    let upstream = fake(
        script(|q| {
            let mut reply = answer(q, Ipv4Addr::new(192, 0, 2, 1));
            reply.answers.clear();
            reply.metadata.truncation = true;
            vec![reply]
        }),
        always(Ipv4Addr::new(192, 0, 2, 2)),
    )
    .await;
    let forwarder = forwarder(vec![UpstreamConfig::udp(upstream.addr)]);
    let response = forwarder.forward(&query("big.example.")).await;
    assert_eq!(ip(&response), Some(Ipv4Addr::new(192, 0, 2, 2).into()));
    assert!(!response.truncated);
    assert_eq!(upstream.seen.lock().unwrap().len(), 2, "one UDP, one TCP");
}

#[tokio::test]
async fn tcp_only_upstreams_are_supported() {
    let upstream = fake(silent(), always(Ipv4Addr::new(192, 0, 2, 3))).await;
    let mut config = UpstreamConfig::udp(upstream.addr);
    config.transport = Transport::Tcp;
    let response = forwarder(vec![config])
        .forward(&query("tcp.example."))
        .await;
    assert_eq!(ip(&response), Some(Ipv4Addr::new(192, 0, 2, 3).into()));
}

#[tokio::test]
async fn fails_over_to_the_next_upstream() {
    let dead = fake(silent(), silent()).await;
    let servfail = fake(
        script(|q| {
            let mut reply = answer(q, Ipv4Addr::new(192, 0, 2, 1));
            reply.answers.clear();
            reply.metadata.response_code = op::ResponseCode::ServFail;
            vec![reply]
        }),
        silent(),
    )
    .await;
    let good = fake(always(Ipv4Addr::new(192, 0, 2, 4)), silent()).await;
    let forwarder = forwarder(vec![
        UpstreamConfig::udp(dead.addr),
        UpstreamConfig::udp(servfail.addr),
        UpstreamConfig::udp(good.addr),
    ]);
    let response = forwarder.forward(&query("failover.example.")).await;
    assert_eq!(ip(&response), Some(Ipv4Addr::new(192, 0, 2, 4).into()));
    assert_eq!(dead.seen.lock().unwrap().len(), 1);
    assert_eq!(servfail.seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn servfail_when_no_upstream_answers() {
    let dead = fake(silent(), silent()).await;
    let forwarder = forwarder(vec![UpstreamConfig::udp(dead.addr)]);
    let started = tokio::time::Instant::now();
    let response = forwarder.forward(&query("nobody.example.")).await;
    assert_eq!(response.rcode, ResponseCode::SERV_FAIL);
    assert!(response.recursion_available);
    assert_eq!(response.answers, vec![]);
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn upstreams_that_do_not_preserve_case_need_randomization_off() {
    let lowercasing = script(|q| {
        let mut reply = answer(q, Ipv4Addr::new(192, 0, 2, 5));
        let lower = reply.queries[0].name().to_lowercase();
        reply.queries[0].set_name(lower);
        vec![reply]
    });
    let upstream = fake(lowercasing, silent()).await;

    let strict = forwarder(vec![UpstreamConfig::udp(upstream.addr)]);
    let response = strict.forward(&query("MiXeD.example.")).await;
    assert_eq!(
        response.rcode,
        ResponseCode::SERV_FAIL,
        "case mismatch is rejected"
    );

    let mut relaxed = UpstreamConfig::udp(upstream.addr);
    relaxed.randomize_case = false;
    let response = forwarder(vec![relaxed])
        .forward(&query("lower.example."))
        .await;
    assert_eq!(ip(&response), Some(Ipv4Addr::new(192, 0, 2, 5).into()));
}

#[tokio::test]
async fn dnssec_ok_bit_is_passed_up_and_copied_back() {
    let upstream = fake(always(Ipv4Addr::new(192, 0, 2, 6)), silent()).await;
    let forwarder = forwarder(vec![UpstreamConfig::udp(upstream.addr)]);
    let mut query = query("dnssec.example.");
    query.edns = Some(Edns {
        udp_payload_size: 1232,
        dnssec_ok: true,
    });
    let response = forwarder.forward(&query).await;
    assert!(response.edns.unwrap().dnssec_ok);
    let sent = upstream.seen.lock().unwrap()[0].clone();
    assert!(sent.edns.unwrap().flags().dnssec_ok);
}

#[tokio::test]
async fn nxdomain_is_passed_through_with_its_soa() {
    let upstream = fake(
        script(|q| {
            let mut reply = answer(q, Ipv4Addr::new(192, 0, 2, 1));
            reply.answers.clear();
            reply.metadata.response_code = op::ResponseCode::NXDomain;
            let zone = rr::Name::from_ascii("example.").unwrap();
            let soa = rdata::SOA::new(zone.clone(), zone.clone(), 1, 3600, 600, 86_400, 30);
            reply.add_authority(rr::Record::from_rdata(zone, 300, RData::SOA(soa)));
            vec![reply]
        }),
        silent(),
    )
    .await;
    let forwarder = forwarder(vec![UpstreamConfig::udp(upstream.addr)]);
    let response = forwarder.forward(&query("missing.example.")).await;
    assert_eq!(response.rcode, ResponseCode::NX_DOMAIN);
    assert_eq!(response.authority.len(), 1);
    assert_eq!(response.authority[0].soa_minimum(), Some(30));
    assert_eq!(
        response.authority[0].name(),
        &"example.".parse::<Name>().unwrap()
    );
}

#[test]
fn forwarders_need_between_one_and_sixteen_upstreams() {
    assert!(Forwarder::new(ForwarderConfig::new(Vec::new())).is_err());
    let addr: SocketAddr = "127.0.0.1:53".parse().unwrap();
    let many = vec![UpstreamConfig::udp(addr); 17];
    assert!(Forwarder::new(ForwarderConfig::new(many)).is_err());
}

#[tokio::test]
async fn cached_answers_are_served_without_asking_upstream() {
    let upstream = fake(always(Ipv4Addr::new(192, 0, 2, 90)), silent()).await;
    let resolver = Resolver::new(Vec::new())
        .with_cache(Cache::new(CacheConfig::default()))
        .with_forwarder(forwarder(vec![UpstreamConfig::udp(upstream.addr)]));

    let first = resolver.resolve(&query("cached.example.")).await;
    let second_query = query("CACHED.Example.");
    let second = resolver.resolve(&second_query).await;

    assert_eq!(upstream.seen.lock().unwrap().len(), 1, "one upstream query");
    assert_eq!(ip(&first), Some(Ipv4Addr::new(192, 0, 2, 90).into()));
    assert_eq!(ip(&second), ip(&first));
    assert!(
        second.answers[0]
            .name()
            .eq_exact(&second_query.question.name)
    );
    assert!(second.recursion_available);
    let stats = resolver.cache().unwrap().stats();
    assert_eq!((stats.hits, stats.misses), (1, 1));
}

#[tokio::test]
async fn failures_are_not_cached() {
    let dead = fake(silent(), silent()).await;
    let resolver = Resolver::new(Vec::new())
        .with_cache(Cache::new(CacheConfig::default()))
        .with_forwarder(forwarder(vec![UpstreamConfig::udp(dead.addr)]));
    let response = resolver.resolve(&query("down.example.")).await;
    assert_eq!(response.rcode, ResponseCode::SERV_FAIL);
    assert!(resolver.cache().unwrap().is_empty());
}

fn filter(list: &str) -> Filter {
    let mut builder = FilterBuilder::new();
    builder.add_list(Source::new(0).unwrap(), list);
    builder.build().unwrap()
}

#[tokio::test]
async fn blocked_names_never_reach_the_upstream() {
    let upstream = fake(always(Ipv4Addr::new(192, 0, 2, 70)), silent()).await;
    let blocking = Arc::new(Blocking::new(
        filter("||ads.example^\n@@||ok.ads.example^\n"),
        BlockResponse::NullIp,
        10,
    ));
    let resolver = Resolver::new(Vec::new())
        .with_blocking(Arc::clone(&blocking))
        .with_cache(Cache::new(CacheConfig::default()))
        .with_forwarder(forwarder(vec![UpstreamConfig::udp(upstream.addr)]));

    let blocked = resolver.resolve(&query("x.ADS.example.")).await;
    assert_eq!(blocked.rcode, ResponseCode::NO_ERROR);
    assert_eq!(ip(&blocked), Some(Ipv4Addr::UNSPECIFIED.into()));
    assert_eq!(blocked.answers[0].ttl(), 10);
    assert!(blocked.recursion_available);

    let exempt = resolver.resolve(&query("ok.ads.example.")).await;
    assert_eq!(ip(&exempt), Some(Ipv4Addr::new(192, 0, 2, 70).into()));
    assert_eq!(
        upstream.seen_names().len(),
        1,
        "only the exception went upstream"
    );

    // A new filter applies at once, without a restart...
    blocking.replace(Filter::empty());
    let unblocked = resolver.resolve(&query("x.ads.example.")).await;
    assert_eq!(ip(&unblocked), Some(Ipv4Addr::new(192, 0, 2, 70).into()));

    // ...including to names whose answers are already cached.
    blocking.replace(filter("||ok.ads.example^\n"));
    let now_blocked = resolver.resolve(&query("ok.ads.example.")).await;
    assert_eq!(ip(&now_blocked), Some(Ipv4Addr::UNSPECIFIED.into()));
    assert_eq!(upstream.seen_names().len(), 2);
}

#[tokio::test]
async fn rebinding_protection_strips_private_answers_for_public_names() {
    let upstream = fake(always(Ipv4Addr::new(192, 168, 1, 1)), silent()).await;
    let resolver = Resolver::new(Vec::new())
        .with_rebinding_protection(RebindingProtection::new(vec!["lan".parse().unwrap()]))
        .with_cache(Cache::new(CacheConfig::default()))
        .with_forwarder(forwarder(vec![UpstreamConfig::udp(upstream.addr)]));

    let attack = resolver.resolve(&query("rebind.attacker.example.")).await;
    assert_eq!(attack.rcode, ResponseCode::NO_ERROR);
    assert_eq!(attack.answers, vec![], "the private address is removed");
    // Asking again, from the cache or upstream, does not bring it back.
    let again = resolver.resolve(&query("rebind.attacker.example.")).await;
    assert_eq!(again.answers, vec![]);

    let router = resolver.resolve(&query("router.lan.")).await;
    assert_eq!(ip(&router), Some(Ipv4Addr::new(192, 168, 1, 1).into()));
}
