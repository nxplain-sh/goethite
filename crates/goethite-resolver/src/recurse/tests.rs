//! Recursion against a simulated DNS: authoritative servers by address,
//! each serving zones, some of them misbehaving.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::struct_excessive_bools,
    clippy::too_many_lines,
    reason = "test helpers and fixtures; the no-panic rules cover non-test code"
)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use goethite_proto::{
    Edns, Name, Query, Question, Record, RecordClass, RecordType, Response, ResponseCode,
};

use super::infra::MAX_FETCHES_PER_SERVER;
use super::{Budget, Exchanged, Network, Recursor, RecursorConfig};
use crate::exchange::ExchangeError;

fn name(text: &str) -> Name {
    text.parse().unwrap()
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

/// How a simulated server misbehaves.
#[derive(Clone, Copy, Default)]
struct Quirks {
    /// Never answers.
    silent: bool,
    /// Truncates every UDP answer.
    truncates: bool,
    /// Never answers over TCP: pairs with `truncates` to stall the TCP
    /// fallback.
    tcp_silent: bool,
    /// Lowercases the question, so 0x20 fails.
    lowercases: bool,
    /// Says NXDOMAIN for names that only have names below them.
    denies_empty_non_terminals: bool,
    /// Adds these records to every answer and referral, in the answer and
    /// additional sections: attempted poisoning.
    poison: &'static [(&'static str, [u8; 4])],
    /// Changes the addresses in its answers, keeping their signatures.
    tampers: bool,
    /// Sends no RRSIG, NSEC or NSEC3 records.
    strips: bool,
}

/// One zone's records.
struct Zone {
    origin: Name,
    records: Vec<Record>,
}

impl Zone {
    /// The wildcard that answers for `name`, which does not exist: the one
    /// at its closest encloser.
    fn wildcard_for(&self, name: &Name) -> Option<Name> {
        let exists = |n: &Name| self.records.iter().any(|r| r.name().is_within(n));
        if exists(name) {
            return None;
        }
        let encloser = (self.origin.label_count()..name.label_count())
            .rev()
            .filter_map(|labels| name.suffix(labels))
            .find(|n| exists(n))?;
        let wild = Name::from_labels(std::iter::once(&b"*"[..]).chain(encloser.labels())).ok()?;
        self.records
            .iter()
            .any(|r| r.name() == &wild)
            .then_some(wild)
    }

    /// The RRSIGs covering `owner`'s `rtype` records.
    fn signatures(&self, owner: &Name, rtype: RecordType) -> impl Iterator<Item = &Record> {
        self.records.iter().filter(move |r| {
            r.name() == owner && r.rrsig().is_some_and(|sig| sig.type_covered == rtype)
        })
    }

    /// Every NSEC and NSEC3 record, with its RRSIGs: proof enough for
    /// anything in a small zone.
    fn proofs(&self) -> Vec<Record> {
        let mut proofs = Vec::new();
        for record in &self.records {
            if matches!(record.record_type(), RecordType::NSEC | RecordType::NSEC3) {
                proofs.push(record.clone());
                proofs.extend(
                    self.signatures(record.name(), record.record_type())
                        .cloned(),
                );
            }
        }
        proofs
    }
}

#[derive(Default)]
struct Server {
    zones: Vec<Zone>,
    quirks: Quirks,
}

/// The simulated network, and a log of every query: who was asked what,
/// over TCP or not.
#[derive(Default)]
struct Fake {
    servers: HashMap<IpAddr, Server>,
    log: Mutex<Vec<(IpAddr, String, RecordType, bool)>>,
    /// Exchanges running right now, and the most seen at once.
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
}

impl Fake {
    fn serve(&mut self, address: &str, origin: &str, records: Vec<Record>) -> &mut Self {
        let origin = name(origin);
        let mut records = records;
        if !records.iter().any(|r| r.record_type() == RecordType::SOA) {
            records.push(Record::soa(origin.clone(), 3600, name("ns.invalid."), 300));
        }
        self.servers
            .entry(ip(address))
            .or_default()
            .zones
            .push(Zone { origin, records });
        self
    }

    fn quirks(&mut self, address: &str, quirks: Quirks) -> &mut Self {
        self.servers.entry(ip(address)).or_default().quirks = quirks;
        self
    }

    fn asked(&self) -> Vec<(IpAddr, String, RecordType, bool)> {
        self.log.lock().unwrap().clone()
    }

    fn max_in_flight(&self) -> usize {
        self.max_in_flight.load(Ordering::Relaxed)
    }

    fn answer(&self, server: IpAddr, query: &Query, tcp: bool) -> Option<Response> {
        let server = self.servers.get(&server)?;
        if server.quirks.silent || (tcp && server.quirks.tcp_silent) {
            return None;
        }
        let qname = &query.question.name;
        let qtype = query.question.qtype;
        let zone = server
            .zones
            .iter()
            .filter(|zone| qname.is_within(&zone.origin))
            .max_by_key(|zone| zone.origin.label_count());
        let Some(zone) = zone else {
            return Some(Response::for_query(query, ResponseCode::REFUSED));
        };
        let mut response = Response::for_query(query, ResponseCode::NO_ERROR);
        let poison = server
            .quirks
            .poison
            .iter()
            .map(|(owner, octets)| Record::a(name(owner), 300, Ipv4Addr::from(*octets)));
        // The deepest delegation at or above the name, below the origin.
        let cut = (zone.origin.label_count() + 1..=qname.label_count())
            .rev()
            .filter_map(|labels| qname.suffix(labels))
            .find(|cut| {
                zone.records
                    .iter()
                    .any(|record| record.name() == cut && record.record_type() == RecordType::NS)
                    && !(qtype == RecordType::DS && cut == qname)
            });
        if let Some(cut) = cut {
            let ns: Vec<Record> = zone
                .records
                .iter()
                .filter(|record| record.name() == &cut && record.record_type() == RecordType::NS)
                .cloned()
                .collect();
            let glue = zone.records.iter().filter(|record| {
                record.ip().is_some()
                    && ns
                        .iter()
                        .any(|ns| ns.ns_target().as_ref() == Some(record.name()))
            });
            response.additional = glue.cloned().chain(poison).collect();
            response.authority = ns;
            return Some(Self::finish(server, response, tcp));
        }
        response.authoritative = true;
        let dnssec_ok = query.edns.is_some_and(|edns| edns.dnssec_ok);
        let mut at = qname.clone();
        let mut wildcard = None;
        for _ in 0..8 {
            let mut here: Vec<Record> = zone
                .records
                .iter()
                .filter(|r| r.name() == &at)
                .cloned()
                .collect();
            if here.is_empty()
                && let Some(wild) = zone.wildcard_for(&at)
            {
                here = zone
                    .records
                    .iter()
                    .filter(|r| r.name() == &wild)
                    .cloned()
                    .map(|mut r| {
                        r.set_name(at.clone());
                        r
                    })
                    .collect();
                wildcard = Some(wild);
            }
            let wanted: Vec<Record> = here
                .iter()
                .filter(|r| r.record_type() == qtype)
                .cloned()
                .collect();
            if !wanted.is_empty() {
                response.answers.extend(wanted);
                break;
            }
            match here.iter().find(|r| r.record_type() == RecordType::CNAME) {
                Some(cname) => {
                    response.answers.push(cname.clone());
                    at = cname.cname_target().unwrap();
                    if !at.is_within(&zone.origin) {
                        break;
                    }
                }
                None => break,
            }
        }
        if dnssec_ok {
            let mut sigs = Vec::new();
            for record in &response.answers {
                let owner = match &wildcard {
                    Some(wild) if record.name() == qname => wild,
                    _ => record.name(),
                };
                for sig in zone.signatures(owner, record.record_type()) {
                    let mut sig = sig.clone();
                    sig.set_name(record.name().clone());
                    if !sigs.contains(&sig) {
                        sigs.push(sig);
                    }
                }
            }
            response.answers.extend(sigs);
            if wildcard.is_some() {
                response.authority.extend(zone.proofs());
            }
        }
        // Addresses for name servers in an answer, as priming expects.
        let targets: Vec<Name> = response
            .answers
            .iter()
            .filter_map(Record::ns_target)
            .collect();
        response.additional.extend(
            zone.records
                .iter()
                .filter(|r| r.ip().is_some() && targets.contains(r.name()))
                .cloned(),
        );
        if response.answers.is_empty() {
            let exists = zone.records.iter().any(|r| r.name() == qname);
            let below = zone
                .records
                .iter()
                .any(|r| r.name().is_within(qname) && r.name() != qname);
            if !exists && wildcard.is_none() && (!below || server.quirks.denies_empty_non_terminals)
            {
                response.rcode = ResponseCode::NX_DOMAIN;
            }
            response.authority.extend(
                zone.records
                    .iter()
                    .filter(|r| r.record_type() == RecordType::SOA)
                    .cloned(),
            );
            if dnssec_ok {
                response
                    .authority
                    .extend(zone.signatures(&zone.origin, RecordType::SOA).cloned());
                response.authority.extend(zone.proofs());
            }
        } else {
            response.answers.extend(poison);
        }
        Some(Self::finish(server, response, tcp))
    }

    fn finish(server: &Server, mut response: Response, tcp: bool) -> Response {
        if server.quirks.strips {
            for section in [
                &mut response.answers,
                &mut response.authority,
                &mut response.additional,
            ] {
                section.retain(|r| {
                    !matches!(
                        r.record_type(),
                        RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3
                    )
                });
            }
        }
        if server.quirks.tampers {
            for record in &mut response.answers {
                if record.record_type() == RecordType::A {
                    *record = Record::a(
                        record.name().clone(),
                        record.ttl(),
                        Ipv4Addr::new(6, 6, 6, 6),
                    );
                }
            }
        }
        if server.quirks.truncates && !tcp {
            response.answers.clear();
            response.authority.clear();
            response.additional.clear();
            response.truncated = true;
        }
        response
    }
}

impl Network for Fake {
    fn exchange<'a>(&'a self, server: SocketAddr, query: &'a Query, tcp: bool) -> Exchanged<'a> {
        Box::pin(async move {
            struct Running<'a>(&'a AtomicUsize);
            impl Drop for Running<'_> {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::Relaxed);
                }
            }
            let running = self.in_flight.fetch_add(1, Ordering::Relaxed) + 1;
            self.max_in_flight.fetch_max(running, Ordering::Relaxed);
            let _running = Running(&self.in_flight);
            self.log.lock().unwrap().push((
                server.ip(),
                query.question.name.to_string().to_lowercase(),
                query.question.qtype,
                tcp,
            ));
            let quirks = self
                .servers
                .get(&server.ip())
                .map(|s| s.quirks)
                .unwrap_or_default();
            match self.answer(server.ip(), query, tcp) {
                Some(_)
                    if quirks.lowercases
                        && query.question.name.to_string()
                            != query.question.name.to_string().to_lowercase() =>
                {
                    // What the socket exchange reports for a case-only
                    // mismatch.
                    Err(ExchangeError::CaseMismatch)
                }
                Some(response) => Ok(response),
                None => std::future::pending().await,
            }
        })
    }
}

/// The simulated internet:
///
/// - the root at 10.0.0.1, delegating `com` and `net`;
/// - `com` at 10.0.1.1, delegating `example.com` (with glue) and
///   `other.com` (served by `ns.provider.net`: no glue);
/// - `net` at 10.0.2.1, delegating `provider.net`;
/// - `example.com` at 10.0.3.1 (and a silent 10.0.3.2);
/// - `provider.net` and `other.com` at 10.0.5.1.
fn internet() -> Fake {
    let mut fake = Fake::default();
    fake.serve(
        "10.0.0.1",
        ".",
        vec![
            Record::ns(Name::root(), 518_400, name("a.root.test.")),
            Record::a(name("a.root.test."), 518_400, Ipv4Addr::new(10, 0, 0, 1)),
            Record::ns(name("com."), 172_800, name("ns.com.")),
            Record::a(name("ns.com."), 172_800, Ipv4Addr::new(10, 0, 1, 1)),
            Record::ns(name("net."), 172_800, name("ns.net.")),
            Record::a(name("ns.net."), 172_800, Ipv4Addr::new(10, 0, 2, 1)),
        ],
    )
    .serve(
        "10.0.1.1",
        "com.",
        vec![
            Record::ns(name("example.com."), 172_800, name("ns2.example.com.")),
            Record::ns(name("example.com."), 172_800, name("ns1.example.com.")),
            Record::a(
                name("ns1.example.com."),
                172_800,
                Ipv4Addr::new(10, 0, 3, 1),
            ),
            Record::a(
                name("ns2.example.com."),
                172_800,
                Ipv4Addr::new(10, 0, 3, 2),
            ),
            Record::ns(name("other.com."), 172_800, name("ns.provider.net.")),
        ],
    )
    .serve(
        "10.0.2.1",
        "net.",
        vec![
            Record::ns(name("provider.net."), 172_800, name("ns.provider.net.")),
            Record::a(
                name("ns.provider.net."),
                172_800,
                Ipv4Addr::new(10, 0, 5, 1),
            ),
        ],
    )
    .serve(
        "10.0.3.1",
        "example.com.",
        vec![
            Record::a(name("www.example.com."), 300, Ipv4Addr::new(192, 0, 2, 1)),
            Record::cname(name("alias.example.com."), 300, name("www.example.com.")),
            Record::cname(name("out.example.com."), 300, name("www.other.com.")),
            Record::a(name("a.b.c.example.com."), 300, Ipv4Addr::new(192, 0, 2, 9)),
            Record::cname(name("loop1.example.com."), 300, name("loop2.example.com.")),
            Record::cname(name("loop2.example.com."), 300, name("loop1.example.com.")),
        ],
    )
    .quirks(
        "10.0.3.2",
        Quirks {
            silent: true,
            ..Quirks::default()
        },
    )
    .serve(
        "10.0.5.1",
        "provider.net.",
        vec![Record::a(
            name("ns.provider.net."),
            300,
            Ipv4Addr::new(10, 0, 5, 1),
        )],
    )
    .serve(
        "10.0.5.1",
        "other.com.",
        vec![Record::a(
            name("www.other.com."),
            300,
            Ipv4Addr::new(192, 0, 2, 2),
        )],
    );
    fake
}

/// Recursion in the unsigned simulated internet: no validation.
fn config() -> RecursorConfig {
    RecursorConfig {
        roots: Some(vec![ip("10.0.0.1")]),
        total_timeout: Duration::from_secs(3),
        ipv6: false,
        dnssec: false,
        ..RecursorConfig::default()
    }
}

fn recursor(fake: Fake, config: RecursorConfig) -> (Recursor, Arc<Fake>) {
    let fake = Arc::new(fake);
    let network: Arc<dyn Network> = fake.clone();
    (Recursor::with_network(config, network), fake)
}

fn query(qname: &str, qtype: RecordType) -> Query {
    Query {
        id: 7,
        recursion_desired: true,
        checking_disabled: false,
        authentic_data: false,
        question: Question {
            name: name(qname),
            qtype,
            qclass: RecordClass::IN,
        },
        edns: Some(Edns::ours()),
    }
}

fn addresses(response: &Response) -> Vec<IpAddr> {
    response.answers.iter().filter_map(Record::ip).collect()
}

#[tokio::test]
async fn loopback_and_local_addresses_are_never_queried() {
    // Glue of 127.0.0.1 would make goethite query itself. The fake serves a
    // good answer there so a query to it could not be mistaken for a
    // failure.
    let mut fake = Fake::default();
    fake.serve(
        "10.0.0.1",
        ".",
        vec![
            Record::ns(name("example."), 172_800, name("ns.example.")),
            Record::a(name("ns.example."), 172_800, Ipv4Addr::LOCALHOST),
        ],
    )
    .serve(
        "127.0.0.1",
        "example.",
        vec![Record::a(
            name("www.example."),
            300,
            Ipv4Addr::new(192, 0, 2, 1),
        )],
    );
    let (node, fake) = recursor(fake, config());
    let (response, _) = node.resolve(&query("www.example.", RecordType::A)).await;
    assert_eq!(response.rcode, ResponseCode::SERV_FAIL);
    assert!(
        fake.asked()
            .iter()
            .all(|(address, ..)| *address != ip("127.0.0.1")),
        "loopback glue is never queried"
    );

    // The node's own address from the config is refused too.
    let mut fake = Fake::default();
    fake.serve(
        "10.0.0.1",
        ".",
        vec![
            Record::ns(name("example."), 172_800, name("ns.example.")),
            Record::a(name("ns.example."), 172_800, Ipv4Addr::new(10, 0, 3, 1)),
        ],
    )
    .serve(
        "10.0.3.1",
        "example.",
        vec![Record::a(
            name("www.example."),
            300,
            Ipv4Addr::new(192, 0, 2, 1),
        )],
    );
    let mut config = config();
    config.local_addresses = vec![ip("10.0.3.1")];
    let (node, fake) = recursor(fake, config);
    let (response, _) = node.resolve(&query("www.example.", RecordType::A)).await;
    assert_eq!(response.rcode, ResponseCode::SERV_FAIL);
    assert!(
        fake.asked()
            .iter()
            .all(|(address, ..)| *address != ip("10.0.3.1")),
        "the node's own address is never queried"
    );
}

/// A root server that truncates every UDP answer and never answers the TCP
/// retry: every query to it stalls until its timeout.
fn stalled_root() -> Fake {
    let mut fake = Fake::default();
    fake.serve(
        "10.0.0.1",
        ".",
        vec![
            Record::ns(Name::root(), 172_800, name("a.root.")),
            Record::a(name("a.root."), 172_800, Ipv4Addr::new(10, 0, 0, 1)),
        ],
    )
    .quirks(
        "10.0.0.1",
        Quirks {
            truncates: true,
            tcp_silent: true,
            ..Quirks::default()
        },
    );
    fake
}

#[tokio::test]
async fn fetches_to_one_server_are_capped() {
    let mut config = config();
    config.total_timeout = Duration::from_millis(500);
    let (recursor, fake) = recursor(stalled_root(), config);
    let recursor = Arc::new(recursor);
    let mut tasks = Vec::new();
    for i in 0..64 {
        let recursor = Arc::clone(&recursor);
        tasks.push(tokio::spawn(async move {
            recursor
                .resolve(&query(&format!("n{i}.example."), RecordType::A))
                .await
        }));
    }
    for task in tasks {
        let (response, _) = task.await.unwrap();
        assert_eq!(response.rcode, ResponseCode::SERV_FAIL);
    }
    let peak = fake.max_in_flight();
    assert!(peak > 0);
    assert!(
        peak <= usize::try_from(MAX_FETCHES_PER_SERVER).unwrap(),
        "a stalling server held {peak} exchanges at once"
    );
}

#[tokio::test]
async fn tcp_fallback_waits_the_server_timeout_not_the_whole_budget() {
    let mut fake = Fake::default();
    fake.serve(
        "10.0.9.9",
        "example.",
        vec![Record::a(
            name("www.example."),
            300,
            Ipv4Addr::new(192, 0, 2, 1),
        )],
    )
    .quirks(
        "10.0.9.9",
        Quirks {
            truncates: true,
            tcp_silent: true,
            ..Quirks::default()
        },
    );
    let (recursor, _) = recursor(fake, config());
    let mut budget = Budget::new(Duration::from_secs(10));
    let started = std::time::Instant::now();
    let result = recursor
        .query_unspanned(
            &name("example."),
            SocketAddr::new(ip("10.0.9.9"), 53),
            &name("www.example."),
            RecordType::A,
            &mut budget,
        )
        .await;
    assert!(result.is_err());
    assert!(
        started.elapsed() < Duration::from_millis(2_500),
        "TCP waited the whole budget: {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn resolves_from_the_root_down_showing_each_server_little() {
    let (recursor, fake) = recursor(internet(), config());
    let (response, server) = recursor
        .resolve(&query("www.example.com.", RecordType::A))
        .await;
    assert_eq!(response.rcode, ResponseCode::NO_ERROR);
    assert!(response.recursion_available && !response.authoritative);
    assert_eq!(addresses(&response), [ip("192.0.2.1")]);
    assert_eq!(server, Some(SocketAddr::new(ip("10.0.3.1"), 53)));
    let asked = fake.asked();
    // Primed first, then: the root sees `com.`, com sees `example.com.`.
    assert_eq!(
        asked[0],
        (ip("10.0.0.1"), ".".into(), RecordType::NS, false)
    );
    assert!(
        asked
            .iter()
            .filter(|(server, ..)| *server == ip("10.0.0.1"))
            .all(|(_, name, ..)| name == "." || name == "com."),
        "the root saw only `com.`: {asked:?}"
    );
    assert!(asked.contains(&(ip("10.0.1.1"), "example.com.".into(), RecordType::A, false)));
    assert!(asked.contains(&(
        ip("10.0.3.1"),
        "www.example.com.".into(),
        RecordType::A,
        false
    )));

    // Known now: straight to example.com's server.
    let before = fake.asked().len();
    let (again, _) = recursor
        .resolve(&query("alias.example.com.", RecordType::A))
        .await;
    assert_eq!(addresses(&again), [ip("192.0.2.1")]);
    assert_eq!(again.answers[0].record_type(), RecordType::CNAME);
    assert!(
        fake.asked()[before..]
            .iter()
            .all(|(server, ..)| *server == ip("10.0.3.1"))
    );
}

#[tokio::test]
async fn follows_cnames_into_zones_without_glue() {
    let (recursor, fake) = recursor(internet(), config());
    let (response, server) = recursor
        .resolve(&query("out.example.com.", RecordType::A))
        .await;
    assert_eq!(response.rcode, ResponseCode::NO_ERROR);
    assert_eq!(response.answers[0].record_type(), RecordType::CNAME);
    assert_eq!(addresses(&response), [ip("192.0.2.2")]);
    assert_eq!(server, Some(SocketAddr::new(ip("10.0.5.1"), 53)));
    // other.com's server had to be found through net.
    assert!(
        fake.asked()
            .iter()
            .any(|(server, name, qtype, _)| *server == ip("10.0.5.1")
                && name == "ns.provider.net."
                && *qtype == RecordType::A)
    );
}

#[tokio::test]
async fn negative_answers_carry_the_soa() {
    let (recursor, _) = recursor(internet(), config());
    let (nx, _) = recursor
        .resolve(&query("nope.example.com.", RecordType::A))
        .await;
    assert_eq!(nx.rcode, ResponseCode::NX_DOMAIN);
    assert_eq!(nx.authority[0].record_type(), RecordType::SOA);
    assert_eq!(nx.authority[0].name(), &name("example.com."));
    let (nodata, _) = recursor
        .resolve(&query("www.example.com.", RecordType::AAAA))
        .await;
    assert_eq!(nodata.rcode, ResponseCode::NO_ERROR);
    assert_eq!(nodata.answers, []);
    assert_eq!(nodata.authority[0].record_type(), RecordType::SOA);
}

#[tokio::test]
async fn empty_non_terminals_even_when_denied() {
    for deny in [false, true] {
        let mut fake = internet();
        fake.quirks(
            "10.0.3.1",
            Quirks {
                denies_empty_non_terminals: deny,
                ..Quirks::default()
            },
        );
        let (recursor, _) = recursor(fake, config());
        let (response, _) = recursor
            .resolve(&query("a.b.c.example.com.", RecordType::A))
            .await;
        assert_eq!(addresses(&response), [ip("192.0.2.9")], "denies: {deny}");
    }
}

#[tokio::test]
async fn out_of_bailiwick_records_are_never_believed() {
    let mut fake = internet();
    // The com server offers an address for a name server under net, and
    // example.com's server one for www.other.com.
    fake.quirks(
        "10.0.1.1",
        Quirks {
            poison: &[("ns.provider.net.", [10, 6, 6, 6])],
            ..Quirks::default()
        },
    )
    .quirks(
        "10.0.3.1",
        Quirks {
            poison: &[("www.other.com.", [6, 6, 6, 6])],
            ..Quirks::default()
        },
    );
    let (recursor, fake) = recursor(fake, config());
    let (response, _) = recursor
        .resolve(&query("out.example.com.", RecordType::A))
        .await;
    assert_eq!(addresses(&response), [ip("192.0.2.2")]);
    assert!(
        fake.asked()
            .iter()
            .all(|(server, ..)| *server != ip("10.6.6.6")),
        "never asked the poisoned address"
    );
}

#[tokio::test]
async fn silent_and_truncating_servers_and_lost_case() {
    let mut fake = internet();
    fake.quirks(
        "10.0.1.1",
        Quirks {
            truncates: true,
            ..Quirks::default()
        },
    )
    .quirks(
        "10.0.0.1",
        Quirks {
            lowercases: true,
            ..Quirks::default()
        },
    );
    // The root is shown the whole name: `com.` alone comes out all
    // lowercase from 0x20 one time in eight.
    let (recursor, fake) = recursor(
        fake,
        RecursorConfig {
            qname_minimisation: false,
            ..config()
        },
    );
    let (response, _) = recursor
        .resolve(&query("www.example.com.", RecordType::A))
        .await;
    assert_eq!(addresses(&response), [ip("192.0.2.1")]);
    let asked = fake.asked();
    assert!(
        asked
            .iter()
            .any(|(server, .., tcp)| *server == ip("10.0.1.1") && *tcp)
    );
    assert!(!recursor.infra.keeps_case(ip("10.0.0.1")));
    // The silent example.com server may have been tried, and is now last.
    let stats = recursor.stats();
    assert!(stats.tcp >= 1 && stats.zones >= 3, "{stats:?}");
}

#[tokio::test]
async fn loops_and_dead_ends_fail_in_time() {
    let (recursor, _) = recursor(internet(), config());
    let (looped, server) = recursor
        .resolve(&query("loop1.example.com.", RecordType::A))
        .await;
    assert_eq!(looped.rcode, ResponseCode::SERV_FAIL);
    assert_eq!(server, None);

    let mut silent = internet();
    silent.quirks(
        "10.0.0.1",
        Quirks {
            silent: true,
            ..Quirks::default()
        },
    );
    let started = tokio::time::Instant::now();
    let (recursor, _) = recursor_with_timeout(silent, Duration::from_millis(600));
    let (failed, _) = recursor
        .resolve(&query("www.example.com.", RecordType::A))
        .await;
    assert_eq!(failed.rcode, ResponseCode::SERV_FAIL);
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(recursor.stats().failures >= 1);
}

fn recursor_with_timeout(fake: Fake, total: Duration) -> (Recursor, Arc<Fake>) {
    recursor(
        fake,
        RecursorConfig {
            total_timeout: total,
            ..config()
        },
    )
}

#[tokio::test]
async fn without_minimisation_the_full_name_goes_everywhere() {
    let (recursor, fake) = recursor(
        internet(),
        RecursorConfig {
            qname_minimisation: false,
            ..config()
        },
    );
    let (response, _) = recursor
        .resolve(&query("www.example.com.", RecordType::A))
        .await;
    assert_eq!(addresses(&response), [ip("192.0.2.1")]);
    assert!(fake.asked().contains(&(
        ip("10.0.0.1"),
        "www.example.com.".into(),
        RecordType::A,
        false
    )));
}

#[tokio::test]
async fn ds_comes_from_the_parent() {
    let (recursor, fake) = recursor(internet(), config());
    recursor
        .resolve(&query("www.example.com.", RecordType::A))
        .await;
    let before = fake.asked().len();
    let (response, server) = recursor
        .resolve(&query("example.com.", RecordType::DS))
        .await;
    assert_eq!(response.rcode, ResponseCode::NO_ERROR);
    assert_eq!(
        server,
        Some(SocketAddr::new(ip("10.0.1.1"), 53)),
        "the com server"
    );
    assert!(
        fake.asked()[before..]
            .iter()
            .all(|(server, ..)| *server == ip("10.0.1.1"))
    );
}

#[test]
fn minimisation_spreads_long_names() {
    // RFC 9156, section 2.3: 18 labels from the root take 1, 1, 1, 1, 2,
    // 2, 2, 2, 3, 3 labels at a time.
    let long: Name = (1..=18)
        .map(|i| format!("l{i}"))
        .collect::<Vec<_>>()
        .join(".")
        .parse()
        .unwrap();
    let mut exposed = 0;
    let mut steps = Vec::new();
    for step in 0..10 {
        let Some(child) = super::next_child(&long, exposed, step) else {
            steps.push(18 - exposed);
            break;
        };
        steps.push(child.label_count() - exposed);
        exposed = child.label_count();
    }
    assert_eq!(steps, [1, 1, 1, 1, 2, 2, 2, 2, 3, 3]);
    // An underscore label shows the rest at once.
    let srv: Name = "_25._tcp.mail.example.org.".parse().unwrap();
    assert_eq!(
        super::next_child(&srv, 2, 0).unwrap(),
        "mail.example.org.".parse().unwrap()
    );
    assert_eq!(super::next_child(&srv, 3, 1), None);
}

mod signed;
