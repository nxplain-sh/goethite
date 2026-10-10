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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use goethite_filter::{Action, Filter, FilterBuilder, Source, Sources};
use goethite_proto::{Edns, Name, Query, Question, RecordClass, RecordType, ResponseCode};
use goethite_resolver::{
    BlockResponse, Cache, CacheConfig, ClientPolicy, Forwarder, ForwarderConfig, GroupPolicy,
    Outcome, Policy, PolicyParts, PolicyState, RebindingProtection, Recursor, RecursorConfig,
    Resolution, Resolver, ScheduledServices, ScheduledSources, ServiceFilter, ServiceMask,
    ServiceRules, Transport, UpstreamConfig,
};
use hickory_proto::op::{self, Message, MessageType, OpCode};
use hickory_proto::rr::{self, RData, rdata};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// The address queries come from, unless a test says otherwise.
const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

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
            padding: false,
            extended_error: None,
        }),
    }
}

fn forwarder(upstreams: Vec<UpstreamConfig>) -> Forwarder {
    let mut config = ForwarderConfig::new(upstreams);
    config.attempt_timeout = Duration::from_millis(300);
    config.total_timeout = Duration::from_secs(2);
    Forwarder::new(config).unwrap()
}

fn ip(response: &goethite_proto::Response) -> Option<IpAddr> {
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
        padding: false,
        extended_error: None,
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

    let first = resolver
        .resolve(&query("cached.example."), CLIENT)
        .await
        .response;
    let second_query = query("CACHED.Example.");
    let second = resolver.resolve(&second_query, CLIENT).await.response;

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
async fn goethites_own_names_never_leave() {
    let upstream = fake(always(Ipv4Addr::new(192, 0, 2, 90)), silent()).await;
    let resolver = Resolver::new(vec![goethite_resolver::test_record().unwrap()])
        .with_forwarder(forwarder(vec![UpstreamConfig::udp(upstream.addr)]));
    for name in [
        "0123456789abcdef0123456789abcdef-1.leak.goethite.test.",
        "anything.goethite.test.",
    ] {
        let resolution = resolver.resolve(&query(name), CLIENT).await;
        assert_eq!(resolution.response.rcode, ResponseCode::NX_DOMAIN, "{name}");
        assert!(resolution.response.authoritative);
        assert_eq!(resolution.outcome, Outcome::Local);
    }
    let own = resolver.resolve(&query("goethite.test."), CLIENT).await;
    assert_eq!(ip(&own.response), Some(Ipv4Addr::new(127, 0, 0, 53).into()));
    assert!(upstream.seen.lock().unwrap().is_empty(), "never forwarded");
}

#[tokio::test]
async fn failures_are_not_cached() {
    let dead = fake(silent(), silent()).await;
    let resolver = Resolver::new(Vec::new())
        .with_cache(Cache::new(CacheConfig::default()))
        .with_forwarder(forwarder(vec![UpstreamConfig::udp(dead.addr)]));
    let response = resolver
        .resolve(&query("down.example."), CLIENT)
        .await
        .response;
    assert_eq!(response.rcode, ResponseCode::SERV_FAIL);
    assert!(resolver.cache().unwrap().is_empty());
}

fn filter(list: &str) -> Filter {
    filter_from(&[list])
}

/// A filter with one source per list, in order.
fn filter_from(lists: &[&str]) -> Filter {
    let mut builder = FilterBuilder::new();
    for (index, list) in lists.iter().enumerate() {
        builder.add_list(Source::new(index).unwrap(), list);
    }
    builder.build().unwrap()
}

/// One group for everyone; the source is called `ads`.
fn simple(filter: Filter) -> Policy {
    Policy::simple(
        Arc::new(filter),
        vec!["ads".into()],
        BlockResponse::NullIp,
        10,
        true,
    )
}

fn sources(indexes: &[usize]) -> Sources {
    indexes.iter().map(|&i| Source::new(i).unwrap()).collect()
}

#[tokio::test]
async fn blocked_names_never_reach_the_upstream() {
    let upstream = fake(always(Ipv4Addr::new(192, 0, 2, 70)), silent()).await;
    let state = Arc::new(PolicyState::new(simple(filter(
        "||ads.example^\n@@||ok.ads.example^\n",
    ))));
    let resolver = Resolver::new(Vec::new())
        .with_policy(Arc::clone(&state))
        .with_cache(Cache::new(CacheConfig::default()))
        .with_forwarder(forwarder(vec![UpstreamConfig::udp(upstream.addr)]));

    let blocked = resolver.resolve(&query("x.ADS.example."), CLIENT).await;
    assert_eq!(blocked.outcome, Outcome::Blocked);
    let hit = blocked.filter.as_ref().unwrap();
    assert_eq!(hit.action, Action::Block);
    assert_eq!(hit.source.as_deref(), Some("ads"));
    assert_eq!(
        hit.rule_text(&"x.ADS.example.".parse().unwrap()),
        "||ads.example^"
    );
    assert_eq!(blocked.group.as_deref(), Some("default"));
    assert_eq!(blocked.client, None);
    let blocked = blocked.response;
    assert_eq!(blocked.rcode, ResponseCode::NO_ERROR);
    assert_eq!(ip(&blocked), Some(Ipv4Addr::UNSPECIFIED.into()));
    assert_eq!(blocked.answers[0].ttl(), 10);
    assert!(blocked.recursion_available);

    let exempt = resolver.resolve(&query("ok.ads.example."), CLIENT).await;
    assert_eq!(exempt.outcome, Outcome::Upstream(0));
    assert_eq!(exempt.filter.as_ref().unwrap().action, Action::Allow);
    assert_eq!(
        ip(&exempt.response),
        Some(Ipv4Addr::new(192, 0, 2, 70).into())
    );
    assert_eq!(
        upstream.seen_names().len(),
        1,
        "only the exception went upstream"
    );
    let again = resolver.resolve(&query("ok.ads.example."), CLIENT).await;
    assert_eq!(again.outcome, Outcome::Cached);

    // A new policy applies at once, without a restart...
    state.replace(simple(Filter::empty()));
    let unblocked = resolver.resolve(&query("x.ads.example."), CLIENT).await;
    assert_eq!(
        ip(&unblocked.response),
        Some(Ipv4Addr::new(192, 0, 2, 70).into())
    );

    // ...including to names whose answers are already cached.
    state.replace(simple(filter("||ok.ads.example^\n")));
    let now_blocked = resolver.resolve(&query("ok.ads.example."), CLIENT).await;
    assert_eq!(
        ip(&now_blocked.response),
        Some(Ipv4Addr::UNSPECIFIED.into())
    );
    assert_eq!(upstream.seen_names().len(), 2);
}

#[tokio::test]
async fn rebinding_protection_strips_private_answers_for_public_names() {
    let upstream = fake(always(Ipv4Addr::new(192, 168, 1, 1)), silent()).await;
    let resolver = Resolver::new(Vec::new())
        .with_rebinding_protection(RebindingProtection::new(vec!["lan".parse().unwrap()]))
        .with_cache(Cache::new(CacheConfig::default()))
        .with_forwarder(forwarder(vec![UpstreamConfig::udp(upstream.addr)]));

    let attack = resolver
        .resolve(&query("rebind.attacker.example."), CLIENT)
        .await
        .response;
    assert_eq!(attack.rcode, ResponseCode::NO_ERROR);
    assert_eq!(attack.answers, vec![], "the private address is removed");
    // Asking again, from the cache or upstream, does not bring it back.
    let again = resolver
        .resolve(&query("rebind.attacker.example."), CLIENT)
        .await
        .response;
    assert_eq!(again.answers, vec![]);

    let router = resolver
        .resolve(&query("router.lan."), CLIENT)
        .await
        .response;
    assert_eq!(ip(&router), Some(Ipv4Addr::new(192, 168, 1, 1).into()));
}

/// Sources: 0 is ads, 1 is social media. The default group uses ads; the
/// kids group (10.0.0.2 and 10.0.1.0/24) uses ads, and social media while
/// schedule 2 is active, with safe search.
fn grouped() -> Policy {
    let mut kids = GroupPolicy::new("kids", sources(&[0]));
    kids.scheduled.push(ScheduledSources {
        schedule: 2,
        sources: sources(&[1]),
    });
    kids.safe_search = true;
    let mut adults = GroupPolicy::new("adults", sources(&[0, 1]));
    adults.filtering = false;
    Policy::new(PolicyParts {
        filter: Arc::new(filter_from(&["||ads.example^\n", "||social.example^\n"])),
        source_ids: vec!["ads".into(), "social".into()],
        groups: vec![GroupPolicy::new("default", sources(&[0])), kids, adults],
        clients: vec![
            ClientPolicy {
                id: "tablet".into(),
                addresses: vec!["10.0.0.2".parse().unwrap(), "10.0.1.0/24".parse().unwrap()],
                ids: Vec::new(),
                group: 1,
            },
            ClientPolicy {
                id: "laptop".into(),
                addresses: vec!["10.0.0.3".parse().unwrap()],
                ids: vec!["laptop".into()],
                group: 2,
            },
        ],
        block_response: BlockResponse::NxDomain,
        blocked_ttl: 10,
        protection: true,
        services: Arc::new(ServiceFilter::empty()),
        access: goethite_resolver::Access::default(),
        records: goethite_resolver::LocalRecords::default(),
    })
    .unwrap()
}

fn from(ip: &str) -> IpAddr {
    ip.parse().unwrap()
}

#[tokio::test]
async fn groups_schedules_and_pausing() {
    let upstream = fake(always(Ipv4Addr::new(192, 0, 2, 80)), silent()).await;
    let state = Arc::new(PolicyState::new(grouped()));
    let resolver = Resolver::new(Vec::new())
        .with_policy(Arc::clone(&state))
        .with_forwarder(forwarder(vec![UpstreamConfig::udp(upstream.addr)]));
    let outcome = async |name: &str, client: &str| -> (Outcome, ResponseCode) {
        let resolution: Resolution = resolver.resolve(&query(name), from(client)).await;
        (resolution.outcome, resolution.response.rcode)
    };
    let blocked = (Outcome::Blocked, ResponseCode::NX_DOMAIN);

    // Everyone gets the ads list; social media only applies to the kids'
    // group while its schedule is active; the adults' group is unfiltered.
    assert_eq!(outcome("ads.example.", "10.9.9.9").await, blocked);
    assert_eq!(outcome("ads.example.", "10.0.1.77").await, blocked);
    assert_eq!(
        outcome("ads.example.", "10.0.0.3").await.0,
        Outcome::Upstream(0)
    );
    assert_eq!(
        outcome("social.example.", "10.0.0.2").await.0,
        Outcome::Upstream(0)
    );
    state.set_active_schedules(1 << 2);
    assert_eq!(outcome("social.example.", "10.0.0.2").await, blocked);
    assert_eq!(
        outcome("social.example.", "10.9.9.9").await.0,
        Outcome::Upstream(0)
    );
    let resolution = resolver
        .resolve(&query("social.example."), from("10.0.0.2"))
        .await;
    assert_eq!(resolution.client.as_deref(), Some("tablet"));
    assert_eq!(resolution.group.as_deref(), Some("kids"));
    assert_eq!(resolution.filter.unwrap().source.as_deref(), Some("social"));

    // A client ID identifies the laptop wherever it is.
    let resolution = resolver
        .resolve_with_id(&query("ads.example."), from("10.9.9.9"), Some("laptop"))
        .await;
    assert_eq!(resolution.client.as_deref(), Some("laptop"));
    assert_eq!(resolution.outcome, Outcome::Upstream(0));

    // Pausing turns filtering off for everyone, until the pause ends.
    state.pause(Some(SystemTime::now() + Duration::from_secs(60)));
    assert_eq!(
        outcome("ads.example.", "10.9.9.9").await.0,
        Outcome::Upstream(0)
    );
    state.pause(None);
    assert_eq!(outcome("ads.example.", "10.9.9.9").await, blocked);
}

/// A catalog of two services, compiled.
fn services() -> Arc<ServiceFilter> {
    let rules = |lines: &[&str]| {
        let mut rules = Vec::new();
        for line in lines {
            goethite_filter::parse_line(line, |rule| rules.push(rule));
        }
        rules
    };
    Arc::new(
        ServiceFilter::build(&[
            ServiceRules {
                id: "tiktok".into(),
                rules: rules(&["||tiktok.com^", "||tiktokv.com^"]),
            },
            ServiceRules {
                id: "youtube".into(),
                rules: rules(&["||youtube.com^"]),
            },
        ])
        .unwrap(),
    )
}

#[tokio::test]
async fn groups_block_services_always_or_on_a_schedule() {
    let upstream = fake(always(Ipv4Addr::new(192, 0, 2, 80)), silent()).await;
    let services = services();
    let tiktok = services.index("tiktok").unwrap();
    let youtube = services.index("youtube").unwrap();
    let mut kids = GroupPolicy::new("kids", sources(&[0]));
    kids.services = ServiceMask::NONE.with(tiktok);
    kids.scheduled_services.push(ScheduledServices {
        schedule: 1,
        services: ServiceMask::NONE.with(youtube),
    });
    let policy = Policy::new(PolicyParts {
        // A list that makes an exception for TikTok, which does not undo
        // the group's choice.
        filter: Arc::new(filter("@@||tiktok.com^\n")),
        source_ids: vec!["allow".into()],
        groups: vec![GroupPolicy::new("default", sources(&[0])), kids],
        clients: vec![ClientPolicy {
            id: "tablet".into(),
            addresses: vec!["10.0.0.2".parse().unwrap()],
            ids: Vec::new(),
            group: 1,
        }],
        block_response: BlockResponse::NxDomain,
        blocked_ttl: 10,
        protection: true,
        services,
        access: goethite_resolver::Access::default(),
        records: goethite_resolver::LocalRecords::default(),
    })
    .unwrap();
    let state = Arc::new(PolicyState::new(policy));
    let resolver = Resolver::new(Vec::new())
        .with_policy(Arc::clone(&state))
        .with_forwarder(forwarder(vec![UpstreamConfig::udp(upstream.addr)]));
    let ask = async |name: &str, client: &str| resolver.resolve(&query(name), from(client)).await;

    let blocked = ask("www.tiktok.com.", "10.0.0.2").await;
    assert_eq!(blocked.outcome, Outcome::Blocked);
    assert_eq!(blocked.response.rcode, ResponseCode::NX_DOMAIN);
    let hit = blocked.filter.unwrap();
    assert_eq!(hit.source.as_deref(), Some("service:tiktok"));
    assert_eq!(
        hit.matched
            .rule_text(&"www.tiktok.com".parse().unwrap(), hit.action),
        "||tiktok.com^"
    );
    // Not for other groups, and YouTube only while its schedule is on.
    assert_eq!(
        ask("www.tiktok.com.", "10.9.9.9").await.outcome,
        Outcome::Upstream(0)
    );
    assert_eq!(
        ask("m.youtube.com.", "10.0.0.2").await.outcome,
        Outcome::Upstream(0)
    );
    state.set_active_schedules(1 << 1);
    assert_eq!(
        ask("m.youtube.com.", "10.0.0.2").await.outcome,
        Outcome::Blocked
    );
    // A pause stops it, like any filtering.
    state.pause(Some(SystemTime::now() + Duration::from_secs(60)));
    assert_eq!(
        ask("www.tiktok.com.", "10.0.0.2").await.outcome,
        Outcome::Upstream(0)
    );
}

/// Answers every query with a CNAME from the question name to `target`,
/// then an A record for the target.
fn cname_to(target: &'static str) -> Script {
    script(move |q| {
        let mut reply = answer(q, Ipv4Addr::new(192, 0, 2, 90));
        let owner = q.queries[0].name().clone();
        let target = rr::Name::from_ascii(target).unwrap();
        reply.answers = vec![
            rr::Record::from_rdata(owner, 300, RData::CNAME(rdata::CNAME(target.clone()))),
            rr::Record::from_rdata(
                target,
                300,
                RData::A(rdata::A(Ipv4Addr::new(192, 0, 2, 90))),
            ),
        ];
        vec![reply]
    })
}

#[tokio::test]
async fn cname_uncloaking() {
    let upstream = fake(cname_to("collect.tracker.example."), silent()).await;
    let state = Arc::new(PolicyState::new(simple(filter(
        "||tracker.example^\n@@||allowed.example^\n",
    ))));
    let resolver = Resolver::new(Vec::new())
        .with_policy(Arc::clone(&state))
        .with_cache(Cache::new(CacheConfig::default()))
        .with_forwarder(forwarder(vec![UpstreamConfig::udp(upstream.addr)]));

    let cloaked = resolver
        .resolve(&query("metrics.shop.example."), CLIENT)
        .await;
    assert_eq!(cloaked.outcome, Outcome::Blocked);
    assert_eq!(ip(&cloaked.response), Some(Ipv4Addr::UNSPECIFIED.into()));
    let hit = cloaked.filter.unwrap();
    assert_eq!(hit.cname.unwrap().to_string(), "collect.tracker.example.");
    assert_eq!(hit.source.as_deref(), Some("ads"));
    // From the cache too: the cache is shared, the policy is checked per query.
    let cached = resolver
        .resolve(&query("metrics.shop.example."), CLIENT)
        .await;
    assert_eq!(cached.outcome, Outcome::Blocked);
    // An exception for the name asked for wins over its CNAMEs.
    let allowed = resolver.resolve(&query("x.allowed.example."), CLIENT).await;
    assert_eq!(allowed.outcome, Outcome::Upstream(0));
    assert_eq!(allowed.response.answers.len(), 2);
    // With filtering paused the chain is answered as is.
    state.pause(Some(SystemTime::now() + Duration::from_secs(60)));
    let paused = resolver
        .resolve(&query("metrics.shop.example."), CLIENT)
        .await;
    assert_eq!(paused.outcome, Outcome::Cached);
}

/// Answers every query with a CNAME chain of `links` records from the
/// question name to `target`, and an A record at the end.
fn cname_chain(links: usize, target: &'static str) -> Script {
    script(move |q| {
        let mut reply = answer(q, Ipv4Addr::new(192, 0, 2, 90));
        let mut owner = q.queries[0].name().clone();
        for link in 0..links {
            let next = if link.saturating_add(1) == links {
                rr::Name::from_ascii(target).unwrap()
            } else {
                rr::Name::from_ascii(format!("c{link}.chain.example.")).unwrap()
            };
            reply.answers.push(rr::Record::from_rdata(
                owner,
                300,
                RData::CNAME(rdata::CNAME(next.clone())),
            ));
            owner = next;
        }
        reply.answers.push(rr::Record::from_rdata(
            owner,
            300,
            RData::A(rdata::A(Ipv4Addr::new(192, 0, 2, 90))),
        ));
        vec![reply]
    })
}

/// A resolver blocking `tracker.example`, with an upstream that answers a
/// chain of `links` from the question name to it.
async fn chain_resolver(links: usize) -> Resolver {
    let upstream = fake(cname_chain(links, "collect.tracker.example."), silent()).await;
    let state = Arc::new(PolicyState::new(simple(filter("||tracker.example^\n"))));
    Resolver::new(Vec::new())
        .with_policy(Arc::clone(&state))
        .with_forwarder(forwarder(vec![UpstreamConfig::udp(upstream.addr)]))
}

#[tokio::test]
async fn a_long_cname_chain_cannot_hide_a_blocked_target() {
    // At the limit the chain is still uncloaked...
    let blocked = chain_resolver(16)
        .await
        .resolve(&query("metrics.shop.example."), CLIENT)
        .await;
    assert_eq!(blocked.outcome, Outcome::Blocked);
    assert_eq!(
        blocked.filter.unwrap().cname.unwrap().to_string(),
        "collect.tracker.example."
    );

    // ... past it nothing passes unchecked.
    let escaped = chain_resolver(17)
        .await
        .resolve(&query("metrics.shop.example."), CLIENT)
        .await;
    assert_eq!(escaped.outcome, Outcome::Failed);
    assert_eq!(escaped.response.rcode, ResponseCode::SERV_FAIL);
}

#[tokio::test]
async fn safe_search_sends_search_hosts_to_their_safe_endpoint() {
    let upstream = fake(always(Ipv4Addr::new(216, 239, 38, 120)), silent()).await;
    let state = Arc::new(PolicyState::new(grouped()));
    let resolver = Resolver::new(Vec::new())
        .with_policy(Arc::clone(&state))
        .with_cache(Cache::new(CacheConfig::default()))
        .with_forwarder(forwarder(vec![UpstreamConfig::udp(upstream.addr)]));

    let kids = resolver
        .resolve(&query("www.google.de."), from("10.0.0.2"))
        .await;
    assert_eq!(kids.outcome, Outcome::SafeSearch);
    let answers = &kids.response.answers;
    assert_eq!(answers.len(), 2);
    assert_eq!(
        answers[0].cname_target().unwrap().to_string(),
        "forcesafesearch.google.com."
    );
    assert_eq!(answers[0].name().to_string(), "www.google.de.");
    assert_eq!(
        answers[1].ip(),
        Some(Ipv4Addr::new(216, 239, 38, 120).into())
    );
    let seen: Vec<String> = upstream
        .seen_names()
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect();
    assert_eq!(
        seen,
        ["forcesafesearch.google.com."],
        "0x20 changes the case"
    );

    // Yandex's safe endpoint is a pinned address, answered without an
    // upstream.
    let yandex = resolver
        .resolve(&query("yandex.ru."), from("10.0.0.2"))
        .await;
    assert_eq!(yandex.outcome, Outcome::SafeSearch);
    assert_eq!(yandex.response.answers.len(), 1);
    assert_eq!(
        yandex.response.answers[0].ip(),
        Some(Ipv4Addr::new(213, 180, 193, 56).into())
    );

    // The pinned address answers `A` only; other types resolve normally.
    let mut aaaa = query("yandex.ru.");
    aaaa.question.qtype = RecordType::AAAA;
    let aaaa = resolver.resolve(&aaaa, from("10.0.0.2")).await;
    assert_eq!(aaaa.outcome, Outcome::Upstream(0));

    // The default group has safe search off.
    let others = resolver
        .resolve(&query("www.google.de."), from("10.9.9.9"))
        .await;
    assert_eq!(others.outcome, Outcome::Upstream(0));
    assert_eq!(others.response.answers.len(), 1);
}

#[tokio::test]
async fn failed_forwarding_is_reported() {
    let dead = fake(silent(), silent()).await;
    let resolver =
        Resolver::new(Vec::new()).with_forwarder(forwarder(vec![UpstreamConfig::udp(dead.addr)]));
    let failed = resolver.resolve(&query("down.example."), CLIENT).await;
    assert_eq!(failed.outcome, Outcome::Failed);
    assert_eq!(failed.response.rcode, ResponseCode::SERV_FAIL);
    let status = resolver.forwarder().unwrap().upstreams();
    assert_eq!(status.len(), 1);
    assert_eq!(status[0].consecutive_failures, 1);
    assert!(status[0].healthy);
}

/// Recursion over real sockets, against one server playing every zone: it
/// answers directly, truncates `big.example.` over UDP, and serves it over
/// TCP.
#[tokio::test]
async fn recursion_asks_over_udp_and_tcp() {
    let udp = script(|query| {
        let mut reply = answer(query, Ipv4Addr::new(192, 0, 2, 80));
        reply.metadata.authoritative = true;
        if query.queries[0]
            .name()
            .to_ascii()
            .eq_ignore_ascii_case("big.example.")
        {
            reply.answers.clear();
            reply.metadata.truncation = true;
        }
        vec![reply]
    });
    let server = fake(udp, always(Ipv4Addr::new(192, 0, 2, 81))).await;
    let recursor = Recursor::new(RecursorConfig {
        roots: Some(vec![server.addr.ip()]),
        port: server.addr.port(),
        ipv6: false,
        total_timeout: Duration::from_secs(2),
        // An unsigned test server.
        dnssec: false,
        ..RecursorConfig::default()
    });
    let resolver = Resolver::new(Vec::new()).with_recursor(recursor);

    let answered = resolver
        .resolve(&query("www.example."), from("10.0.0.1"))
        .await;
    assert_eq!(answered.outcome, Outcome::Recursive(server.addr));
    assert_eq!(
        ip(&answered.response),
        Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 80)))
    );
    assert!(answered.response.recursion_available);
    // Recursion asks without recursion desired, and the case echoed back
    // was checked.
    let seen = server.seen.lock().unwrap().clone();
    assert!(seen.iter().all(|query| !query.metadata.recursion_desired));

    let big = resolver
        .resolve(&query("big.example."), from("10.0.0.1"))
        .await;
    assert_eq!(
        ip(&big.response),
        Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 81))),
        "over TCP"
    );
    assert!(resolver.recursor().unwrap().stats().tcp >= 1);

    // Special-use names never leave the house.
    let before = server.seen.lock().unwrap().len();
    let private = resolver
        .resolve(&query("1.1.168.192.in-addr.arpa."), from("10.0.0.1"))
        .await;
    assert_eq!(private.outcome, Outcome::Local);
    assert_eq!(private.response.rcode, ResponseCode::NX_DOMAIN);
    assert_eq!(server.seen.lock().unwrap().len(), before);
}

#[tokio::test]
async fn local_records_answer_first_and_lead_to_upstream_answers() {
    use goethite_resolver::{LocalData, LocalRecord, LocalRecords};

    let upstream = fake(always(Ipv4Addr::new(192, 0, 2, 80)), silent()).await;
    let name = |text: &str| text.parse::<Name>().unwrap();
    let local = |text: &str, data| LocalRecord {
        name: name(text),
        wildcard: false,
        data,
        ttl: 300,
    };
    let policy = Policy::new(PolicyParts {
        filter: Arc::new(filter("||ads.example^\n||nas.lan^\n")),
        source_ids: vec!["ads".into()],
        groups: vec![GroupPolicy::new("default", sources(&[0]))],
        clients: Vec::new(),
        block_response: BlockResponse::NxDomain,
        blocked_ttl: 10,
        protection: true,
        services: Arc::new(ServiceFilter::empty()),
        access: goethite_resolver::Access::default(),
        records: LocalRecords::new([
            local("nas.lan", LocalData::A(Ipv4Addr::new(192, 168, 1, 10))),
            local("docs.lan", LocalData::Cname(name("docs.example"))),
            local("tracker.lan", LocalData::Cname(name("ads.example"))),
        ]),
    })
    .unwrap();
    let resolver = Resolver::new(Vec::new())
        .with_policy(Arc::new(PolicyState::new(policy)))
        .with_forwarder(forwarder(vec![UpstreamConfig::udp(upstream.addr)]));

    // Answered locally, before the filter that would block the name.
    let nas = resolver.resolve(&query("nas.lan."), CLIENT).await;
    assert_eq!(nas.outcome, Outcome::Local);
    assert!(nas.response.authoritative);
    assert_eq!(
        ip(&nas.response),
        Some(Ipv4Addr::new(192, 168, 1, 10).into())
    );

    // A CNAME out of the local records: the target's own answer follows.
    let docs = resolver.resolve(&query("docs.lan."), CLIENT).await;
    assert_eq!(docs.outcome, Outcome::Upstream(0));
    assert_eq!(docs.response.answers.len(), 2);
    assert_eq!(
        docs.response.answers[0].cname_target(),
        Some(name("docs.example"))
    );
    assert_eq!(
        docs.response.answers[1].ip(),
        Some(Ipv4Addr::new(192, 0, 2, 80).into())
    );

    // The target goes through the filter like any other name.
    let tracker = resolver.resolve(&query("tracker.lan."), CLIENT).await;
    assert_eq!(tracker.outcome, Outcome::Blocked);
    assert_eq!(tracker.response.rcode, ResponseCode::NX_DOMAIN);
}

/// Records the spans opened on the thread that claims it, and the `name`
/// fields recorded on them. Spans other tests open are ignored.
///
/// The subscriber is installed process-wide (once) because a scoped one
/// races with the other tests in this binary: the first thread to touch a
/// callsite fills in the process-wide interest cache for it, and a thread
/// with no subscriber disables it for everyone.
struct Spans {
    thread: std::sync::OnceLock<std::thread::ThreadId>,
    log: Mutex<(Vec<String>, Vec<String>)>,
}

static SPANS: Spans = Spans {
    thread: std::sync::OnceLock::new(),
    log: Mutex::new((Vec::new(), Vec::new())),
};

struct SpansLayer;

impl Spans {
    fn claimed_by_this_thread(&self) -> bool {
        self.thread.get() == Some(&std::thread::current().id())
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SpansLayer {
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _: &tracing::span::Id,
        _: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if !SPANS.claimed_by_this_thread() {
            return;
        }
        SPANS
            .log
            .lock()
            .unwrap()
            .0
            .push(attrs.metadata().name().to_owned());
    }

    fn on_record(
        &self,
        _: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        _: tracing_subscriber::layer::Context<'_, S>,
    ) {
        struct Names<'a>(&'a mut Vec<String>);
        impl tracing::field::Visit for Names<'_> {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "name" {
                    self.0.push(format!("{value:?}"));
                }
            }
        }
        if !SPANS.claimed_by_this_thread() {
            return;
        }
        values.record(&mut Names(&mut SPANS.log.lock().unwrap().1));
    }
}

/// Spans are opened on the slow path only: a forwarded query opens a
/// `resolve` span with an `upstream` span inside, a cache hit opens none.
/// The name looked up is on the span only with span details on.
#[tokio::test]
async fn spans_only_on_the_slow_path() {
    use tracing_subscriber::layer::SubscriberExt as _;

    static INSTALL: std::sync::Once = std::sync::Once::new();
    SPANS.thread.get_or_init(|| std::thread::current().id());
    INSTALL.call_once(|| {
        tracing::subscriber::set_global_default(tracing_subscriber::registry().with(SpansLayer))
            .unwrap();
    });

    let upstream = fake(always(Ipv4Addr::new(192, 0, 2, 7)), silent()).await;
    let resolver = Resolver::new(Vec::new())
        .with_cache(Cache::new(CacheConfig::default()))
        .with_forwarder(forwarder(vec![UpstreamConfig::udp(upstream.addr)]));

    let first = resolver.resolve(&query("example.com."), CLIENT).await;
    assert_eq!(first.outcome, Outcome::Upstream(0));
    assert_eq!(SPANS.log.lock().unwrap().0, ["resolve", "upstream"]);
    let again = resolver.resolve(&query("example.com."), CLIENT).await;
    assert_eq!(again.outcome, Outcome::Cached);
    assert_eq!(
        SPANS.log.lock().unwrap().0.len(),
        2,
        "a cache hit opens no span"
    );
    assert!(
        SPANS.log.lock().unwrap().1.is_empty(),
        "no names by default"
    );

    let detailed = Resolver::new(Vec::new())
        .with_forwarder(forwarder(vec![UpstreamConfig::udp(upstream.addr)]))
        .with_span_details(true);
    detailed.resolve(&query("named.example."), CLIENT).await;
    assert_eq!(SPANS.log.lock().unwrap().1, ["named.example."]);
}
