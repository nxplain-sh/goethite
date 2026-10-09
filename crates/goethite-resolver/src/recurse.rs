//! Recursive resolution: finding answers from the root servers down,
//! instead of asking an upstream resolver.
//!
//! A name is looked up by asking the servers of the closest known zone cut,
//! following referrals down (with QNAME minimisation, RFC 9156, in its
//! relaxed form) until a server answers, then following CNAMEs to the end.
//! What servers say is believed only within their bailiwick
//! ([`classify`]). Exchanges use the same defenses as forwarding: a fresh
//! random source port and ID for every query, 0x20 case randomization
//! (dropped for a server that does not keep case), the question matched
//! exactly, and TCP when an answer is truncated.
//!
//! Everything is bounded: [`MAX_SENT`] queries and the configured time for
//! one client query, all lookups included; [`MAX_REFERRALS`] referrals for
//! one name; name server address lookups nested [`MAX_DEPTH`] deep; the
//! CNAME chain; exchanges in flight; and the infrastructure tables.
//!
//! Answers are validated with DNSSEC (RFC 4033 to 4035, RFC 5155) unless
//! that is turned off or the client sets CD: secure ones get the AD bit,
//! bogus ones become SERVFAIL. See `validate`.

mod classify;
mod dnssec;
mod hints;
mod infra;
mod special;
#[cfg(test)]
mod tests;
mod validate;

use std::collections::HashSet;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

#[doc(hidden)]
pub use classify::{Kind, MAX_NAME_SERVERS, classify};
use goethite_proto::{
    DnsCodec, Edns, HickoryCodec, Name, Query, Question, Record, RecordClass, RecordType, Response,
    ResponseCode,
};
use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout};
use tracing::{debug, warn};

use crate::exchange::{self, ExchangeError, OnCaseMismatch};
use crate::{MAX_CNAME_CHAIN, restore_question_case};
use dnssec::Security;
use infra::Infra;
use validate::Validation;

/// The most queries sent for one client query, every lookup included.
pub const MAX_SENT: u32 = 64;

/// The most referrals followed while looking up one name.
pub const MAX_REFERRALS: usize = 32;

/// How deep name server address lookups may nest.
pub const MAX_DEPTH: u8 = 4;

/// QNAME minimisation: the most minimised queries for one name, and how
/// many of them expose one label each (RFC 9156, section 2.3).
const MAX_MINIMISE_COUNT: usize = 10;
const MINIMISE_ONE_LAB: usize = 4;

/// The most name servers of one zone whose addresses are looked up.
const MAX_NS_LOOKUPS: usize = 4;

/// The most addresses tried for one question to one zone.
const MAX_ADDRESSES: usize = 12;

/// How often priming may be tried when it fails.
const PRIME_RETRY: Duration = Duration::from_secs(60);

/// Recursion settings.
#[derive(Clone, Debug)]
pub struct RecursorConfig {
    /// QNAME minimisation (RFC 9156): show each server only as much of the
    /// name as it needs.
    pub qname_minimisation: bool,
    /// Whether to ask servers over IPv6 too.
    pub ipv6: bool,
    /// How long resolving one client query may take.
    pub total_timeout: Duration,
    /// The most queries to authoritative servers in flight at once.
    pub max_in_flight: usize,
    /// The most entries in each infrastructure table.
    pub infra_entries: usize,
    /// The port servers are asked on: 53, except in tests.
    pub port: u16,
    /// Root server addresses to start from instead of IANA's root hints,
    /// for tests.
    pub roots: Option<Vec<IpAddr>>,
    /// DNSSEC validation.
    pub dnssec: bool,
    /// DS records for the root zone to trust instead of IANA's trust
    /// anchors, for tests.
    pub anchors: Option<Vec<Record>>,
}

impl Default for RecursorConfig {
    fn default() -> Self {
        Self {
            qname_minimisation: true,
            ipv6: true,
            total_timeout: Duration::from_secs(6),
            max_in_flight: 1_024,
            infra_entries: 20_000,
            port: 53,
            roots: None,
            dnssec: true,
            anchors: None,
        }
    }
}

/// Counters and sizes, for status and metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecursorStats {
    /// Queries sent to authoritative servers.
    pub sent: u64,
    /// Of them, over TCP.
    pub tcp: u64,
    /// Queries no server answered in time.
    pub timeouts: u64,
    /// Client queries that could not be resolved (SERVFAIL), bogus ones
    /// included.
    pub failures: u64,
    /// Answers DNSSEC proved authentic.
    pub secure: u64,
    /// Answers from unsigned zones.
    pub insecure: u64,
    /// Answers whose signatures or proofs failed: SERVFAIL.
    pub bogus: u64,
    /// Zone cuts known.
    pub zones: usize,
    /// Servers with statistics.
    pub servers: usize,
}

/// A boxed exchange.
pub(crate) type Exchanged<'a> =
    Pin<Box<dyn Future<Output = Result<Response, ExchangeError>> + Send + 'a>>;

/// How queries reach servers: sockets, or a simulation in tests.
pub(crate) trait Network: Send + Sync + 'static {
    /// Sends `query` to `server`, over TCP if `tcp`, and returns the
    /// response that answers it.
    fn exchange<'a>(&'a self, server: SocketAddr, query: &'a Query, tcp: bool) -> Exchanged<'a>;
}

/// The real network.
struct Sockets;

impl Network for Sockets {
    fn exchange<'a>(&'a self, server: SocketAddr, query: &'a Query, tcp: bool) -> Exchanged<'a> {
        Box::pin(async move {
            let mut wire = Vec::new();
            HickoryCodec.encode_query(query, &mut wire)?;
            if tcp {
                exchange::tcp(server, &wire, query).await
            } else {
                exchange::udp(server, &wire, query, OnCaseMismatch::Report).await
            }
        })
    }
}

/// Why a lookup failed.
#[derive(Debug, thiserror::Error)]
enum RecurseError {
    #[error("out of time")]
    Deadline,
    #[error("too many queries")]
    Budget,
    #[error("too many referrals")]
    Referrals,
    #[error("no server answered")]
    NoServer,
    #[error("the CNAME chain is too long or loops")]
    Chain,
}

impl RecurseError {
    /// Whether the whole resolution must stop.
    fn is_fatal(&self) -> bool {
        matches!(self, Self::Deadline | Self::Budget)
    }
}

/// What one client query may still spend.
struct Budget {
    sent: u32,
    deadline: Instant,
}

impl Budget {
    fn new(time: Duration) -> Self {
        let now = Instant::now();
        Self {
            sent: 0,
            deadline: now.checked_add(time).unwrap_or(now),
        }
    }

    /// Counts a query; the time left for it.
    fn spend(&mut self) -> Result<Duration, RecurseError> {
        if self.sent >= MAX_SENT {
            return Err(RecurseError::Budget);
        }
        self.sent = self.sent.saturating_add(1);
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(RecurseError::Deadline);
        }
        Ok(left)
    }
}

/// What looking up one name found: one zone's servers' answer.
struct Found {
    /// The name and type asked.
    name: Name,
    qtype: RecordType,
    rcode: ResponseCode,
    records: Vec<Record>,
    /// Where a CNAME chain continues.
    next: Option<Name>,
    soa: Option<Record>,
    server: SocketAddr,
    /// The zone whose servers answered.
    zone: Name,
    /// The response's RRSIGs, NSEC and NSEC3 records and DNAMEs within
    /// that zone, when validating.
    evidence: Vec<Record>,
}

/// Resolves names from the root servers down.
pub struct Recursor {
    config: RecursorConfig,
    infra: Infra,
    /// The root servers to start from, by name.
    roots: Vec<(Name, Arc<[IpAddr]>)>,
    root_names: Arc<[Name]>,
    /// The root zone's trust anchors.
    anchors: Vec<Record>,
    network: Arc<dyn Network>,
    in_flight: Semaphore,
    /// When priming was last tried.
    primed: Mutex<Option<Instant>>,
    sent: AtomicU64,
    tcp: AtomicU64,
    timeouts: AtomicU64,
    failures: AtomicU64,
    secure: AtomicU64,
    insecure: AtomicU64,
    bogus: AtomicU64,
}

impl std::fmt::Debug for Recursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recursor")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Recursor {
    /// A recursor that asks servers over the network.
    pub fn new(config: RecursorConfig) -> Self {
        Self::with_network(config, Arc::new(Sockets))
    }

    pub(crate) fn with_network(config: RecursorConfig, network: Arc<dyn Network>) -> Self {
        let roots: Vec<(Name, Arc<[IpAddr]>)> = match &config.roots {
            Some(ips) => ips
                .iter()
                .enumerate()
                .filter_map(|(i, ip)| {
                    let name = format!("root-{i}.hints.invalid.").parse().ok()?;
                    Some((name, Arc::from([*ip])))
                })
                .collect(),
            None => hints::ROOT_SERVERS
                .iter()
                .filter_map(|&(name, v4, v6)| {
                    Some((
                        name.parse().ok()?,
                        Arc::from([IpAddr::V4(v4), IpAddr::V6(v6)]),
                    ))
                })
                .collect(),
        };
        let root_names = roots.iter().map(|(name, _)| name.clone()).collect();
        let anchors = config.anchors.clone().unwrap_or_else(hints::root_anchors);
        Self {
            infra: Infra::new(config.infra_entries),
            anchors,
            in_flight: Semaphore::new(config.max_in_flight.clamp(1, Semaphore::MAX_PERMITS)),
            config,
            roots,
            root_names,
            network,
            primed: Mutex::new(None),
            sent: AtomicU64::new(0),
            tcp: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            secure: AtomicU64::new(0),
            insecure: AtomicU64::new(0),
            bogus: AtomicU64::new(0),
        }
    }

    /// The settings it runs with.
    pub fn config(&self) -> &RecursorConfig {
        &self.config
    }

    /// Counters and table sizes.
    pub fn stats(&self) -> RecursorStats {
        let (zones, servers) = self.infra.sizes();
        RecursorStats {
            sent: self.sent.load(Ordering::Relaxed),
            tcp: self.tcp.load(Ordering::Relaxed),
            timeouts: self.timeouts.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            secure: self.secure.load(Ordering::Relaxed),
            insecure: self.insecure.load(Ordering::Relaxed),
            bogus: self.bogus.load(Ordering::Relaxed),
            zones,
            servers,
        }
    }

    /// goethite's own answer for a special-use name, which is never asked
    /// about on the internet.
    pub fn special(query: &Query) -> Option<Response> {
        special::answer(query)
    }

    /// Resolves `query`: the response for the client, and the server that
    /// gave the last answer (`None` for SERVFAIL). Validated with DNSSEC
    /// unless that is off or the client sets CD: AD if secure, SERVFAIL if
    /// bogus. A client that sets DO gets the signatures and proofs too.
    pub async fn resolve(&self, query: &Query) -> (Response, Option<SocketAddr>) {
        let mut budget = Budget::new(self.config.total_timeout);
        let question = &query.question;
        let validate = self.config.dnssec && !query.checking_disabled;
        let resolved = async {
            let mut segments = self
                .chase(&question.name, question.qtype, &mut budget, 0)
                .await?;
            let security = if validate {
                let mut validation = Validation::new();
                Some(
                    self.validate(&mut segments, &mut budget, &mut validation)
                        .await?,
                )
            } else {
                None
            };
            Ok::<_, RecurseError>((segments, security))
        }
        .await;
        let servfail = || {
            let mut response = Response::for_query(query, ResponseCode::SERV_FAIL);
            response.recursion_available = true;
            (response, None)
        };
        let (segments, security) = match resolved {
            Ok(resolved) => resolved,
            Err(err) => {
                self.failures.fetch_add(1, Ordering::Relaxed);
                debug!(name = %question.name, qtype = %question.qtype, %err, "cannot resolve");
                return servfail();
            }
        };
        match security {
            Some(Security::Secure) => self.secure.fetch_add(1, Ordering::Relaxed),
            Some(Security::Insecure) => self.insecure.fetch_add(1, Ordering::Relaxed),
            Some(Security::Bogus) => {
                self.bogus.fetch_add(1, Ordering::Relaxed);
                self.failures.fetch_add(1, Ordering::Relaxed);
                debug!(name = %question.name, qtype = %question.qtype, "DNSSEC validation failed");
                return servfail();
            }
            None => 0,
        };
        let Some(last) = segments.last() else {
            return servfail();
        };
        let mut response = Response::for_query(query, last.rcode);
        response.recursion_available = true;
        response.authentic_data = security == Some(Security::Secure);
        let server = last.server;
        let dnssec_ok = query.edns.is_some_and(|edns| edns.dnssec_ok);
        (response.answers, response.authority) = sections(segments, dnssec_ok);
        restore_question_case(&mut response, &question.name);
        (response, Some(server))
    }

    /// `name`'s records of `qtype`, following CNAMEs to the end: the answer
    /// of each zone on the way, the last one's at the end.
    async fn chase(
        &self,
        name: &Name,
        qtype: RecordType,
        budget: &mut Budget,
        depth: u8,
    ) -> Result<Vec<Found>, RecurseError> {
        let mut segments = Vec::new();
        let mut seen = HashSet::new();
        let mut at = name.clone();
        for _ in 0..=MAX_CNAME_CHAIN {
            if !seen.insert(at.clone()) {
                return Err(RecurseError::Chain);
            }
            let found = self.lookup(&at, qtype, budget, depth).await?;
            let next = found.next.clone();
            segments.push(found);
            match next {
                Some(next) => at = next,
                None => return Ok(segments),
            }
        }
        Err(RecurseError::Chain)
    }

    /// Looks up one name, from the closest known zone cut down.
    async fn lookup(
        &self,
        name: &Name,
        qtype: RecordType,
        budget: &mut Budget,
        depth: u8,
    ) -> Result<Found, RecurseError> {
        // A DS record is held by the parent of its zone.
        let anchor = if qtype == RecordType::DS {
            name.parent().unwrap_or_else(Name::root)
        } else {
            name.clone()
        };
        let (mut zone, mut servers) = self.start(&anchor).await;
        let mut exposed = zone.label_count();
        let mut minimise = self.config.qname_minimisation && qtype != RecordType::DS;
        let mut steps = 0;
        for _ in 0..MAX_REFERRALS {
            let child = if minimise && steps < MAX_MINIMISE_COUNT {
                next_child(name, exposed, steps)
            } else {
                None
            };
            let minimised = child.is_some();
            let (ask_name, ask_type) = match child {
                Some(child) => {
                    steps = steps.saturating_add(1);
                    (child, RecordType::A)
                }
                None => (name.clone(), qtype),
            };
            let (kind, server, response) = match self
                .ask_with_response(&zone, &servers, &ask_name, ask_type, budget, depth)
                .await
            {
                Ok(asked) => asked,
                Err(err) if minimised && !err.is_fatal() => {
                    // Relaxed: some servers cannot answer for names that
                    // are not delegated; ask the whole name instead.
                    debug!(name = %ask_name, %err, "minimised query failed; asking the full name");
                    minimise = false;
                    continue;
                }
                Err(err) => return Err(err),
            };
            match kind {
                Kind::Referral {
                    zone: cut,
                    servers: next,
                    ttl,
                    glue,
                } => {
                    let now = Instant::now();
                    self.learn_glue(glue, now);
                    self.infra.delegate(cut.clone(), next.clone(), ttl, now);
                    exposed = cut.label_count();
                    zone = cut;
                    servers = next.into();
                }
                Kind::Answer { .. } | Kind::NoData { .. } if minimised => {
                    // No zone cut there: show the servers one more label.
                    exposed = ask_name.label_count();
                }
                Kind::NxDomain { .. } if minimised => {
                    // Not trusted for the name below it (no RFC 8020 cut):
                    // some servers deny empty non-terminals.
                    minimise = false;
                }
                Kind::Answer { .. } | Kind::NoData { .. } | Kind::NxDomain { .. } => {
                    let (rcode, records, next, soa) = match kind {
                        Kind::Answer { records, next } => {
                            (ResponseCode::NO_ERROR, records, next, None)
                        }
                        Kind::NoData { soa } => (ResponseCode::NO_ERROR, Vec::new(), None, soa),
                        _ => (ResponseCode::NX_DOMAIN, Vec::new(), None, kind_soa(kind)),
                    };
                    let evidence = if self.config.dnssec {
                        dnssec::evidence(&zone, response.answers.iter().chain(&response.authority))
                    } else {
                        Vec::new()
                    };
                    return Ok(Found {
                        name: name.clone(),
                        qtype,
                        rcode,
                        records,
                        next,
                        soa,
                        server,
                        zone,
                        evidence,
                    });
                }
                Kind::Lame | Kind::Failed(_) => return Err(RecurseError::NoServer),
            }
        }
        Err(RecurseError::Referrals)
    }

    /// Remembers glue addresses from a referral, by name server.
    fn learn_glue(&self, glue: Vec<(Name, IpAddr, u32)>, now: Instant) {
        let mut by_server: Vec<(Name, Vec<IpAddr>, u32)> = Vec::new();
        for (server, ip, ttl) in glue {
            match by_server.iter_mut().find(|(name, _, _)| *name == server) {
                Some((_, ips, min_ttl)) => {
                    ips.push(ip);
                    *min_ttl = (*min_ttl).min(ttl);
                }
                None => by_server.push((server, vec![ip], ttl)),
            }
        }
        for (server, ips, ttl) in by_server {
            self.infra.set_addresses(server, ips, ttl, now);
        }
    }

    /// The zone to start looking up `name` at, and its name servers: the
    /// closest known cut, or the root.
    async fn start(&self, name: &Name) -> (Name, Arc<[Name]>) {
        if let Some((zone, delegation)) = self.infra.closest(name, Instant::now()) {
            return (zone, delegation.servers);
        }
        self.prime().await;
        match self.infra.closest(name, Instant::now()) {
            Some((zone, delegation)) => (zone, delegation.servers),
            None => (Name::root(), Arc::clone(&self.root_names)),
        }
    }

    /// Asks the root servers who they are (RFC 8109), unless that was tried
    /// recently; until it works, the hints are used.
    async fn prime(&self) {
        let now = Instant::now();
        {
            // Claimed under a short lock: whoever comes meanwhile uses the
            // hints rather than waiting.
            let mut primed = self.primed.lock().unwrap_or_else(PoisonError::into_inner);
            if primed.is_some_and(|at| now.saturating_duration_since(at) < PRIME_RETRY)
                || self.infra.closest(&Name::root(), now).is_some()
            {
                return;
            }
            *primed = Some(now);
        }
        let mut budget = Budget::new(self.config.total_timeout);
        let root = Name::root();
        let roots = Arc::clone(&self.root_names);
        let Ok((Kind::Answer { records, .. }, _, response)) = self
            .ask_with_response(&root, &roots, &root, RecordType::NS, &mut budget, 0)
            .await
        else {
            warn!("cannot prime the root servers; using the built-in hints");
            return;
        };
        let servers: Vec<Name> = records
            .iter()
            .filter_map(Record::ns_target)
            .take(MAX_NAME_SERVERS)
            .collect();
        let ttl = records.iter().map(Record::ttl).min().unwrap_or(0);
        let glue: Vec<(Name, IpAddr, u32)> = response
            .additional
            .iter()
            .filter(|record| record.class() == RecordClass::IN && servers.contains(record.name()))
            .filter_map(|record| Some((record.name().clone(), record.ip()?, record.ttl())))
            .collect();
        // Without addresses the root servers could not be reached: keep
        // the hints.
        if !servers.is_empty() && !glue.is_empty() {
            self.learn_glue(glue, now);
            self.infra.delegate(root, servers, ttl, now);
        }
    }

    /// The known addresses of name server `name`: learned, or the hints.
    fn known_addresses(&self, name: &Name, now: Instant) -> Option<Arc<[IpAddr]>> {
        self.infra.addresses(name, now).or_else(|| {
            self.roots
                .iter()
                .find(|(root, _)| root == name)
                .map(|(_, ips)| Arc::clone(ips))
        })
    }

    /// Asks `zone`'s servers about `name`, one after another, until one
    /// gives a usable response; looks up name server addresses as needed.
    async fn ask_with_response(
        &self,
        zone: &Name,
        servers: &[Name],
        name: &Name,
        qtype: RecordType,
        budget: &mut Budget,
        depth: u8,
    ) -> Result<(Kind, SocketAddr, Response), RecurseError> {
        let mut tried: HashSet<IpAddr> = HashSet::new();
        let mut looked_up = 0;
        loop {
            let now = Instant::now();
            let mut ips: Vec<IpAddr> = servers
                .iter()
                .filter_map(|server| self.known_addresses(server, now))
                .flat_map(|ips| ips.iter().copied().collect::<Vec<_>>())
                .filter(|ip| (ip.is_ipv4() || self.config.ipv6) && !tried.contains(ip))
                .collect();
            ips.sort_unstable();
            ips.dedup();
            self.infra.ranked(&mut ips, now);
            for ip in ips {
                if tried.len() >= MAX_ADDRESSES {
                    return Err(RecurseError::NoServer);
                }
                tried.insert(ip);
                let server = SocketAddr::new(ip, self.config.port);
                let response = match self.query(server, name, qtype, budget).await {
                    Ok(response) => response,
                    Err(err) if err.is_fatal() => return Err(err),
                    Err(_) => continue,
                };
                match classify(&response, zone, name, qtype) {
                    Kind::Lame | Kind::Failed(_) => {
                        debug!(%server, %zone, %name, "lame or failing server");
                        self.infra.failed(ip, Instant::now());
                    }
                    kind => return Ok((kind, server, response)),
                }
            }
            // Every known address failed: look up a name server whose
            // addresses are not known yet.
            if looked_up >= MAX_NS_LOOKUPS || depth >= MAX_DEPTH {
                return Err(RecurseError::NoServer);
            }
            let unknown = servers
                .iter()
                .find(|server| self.known_addresses(server, Instant::now()).is_none());
            let Some(unknown) = unknown else {
                return Err(RecurseError::NoServer);
            };
            looked_up = looked_up.saturating_add(1);
            self.find_addresses(unknown, budget, depth.saturating_add(1))
                .await?;
        }
    }

    /// Looks up name server `name`'s addresses and remembers them, or that
    /// it has none.
    async fn find_addresses(
        &self,
        name: &Name,
        budget: &mut Budget,
        depth: u8,
    ) -> Result<(), RecurseError> {
        let mut ips = Vec::new();
        let mut ttl = u32::MAX;
        let types: &[RecordType] = if self.config.ipv6 {
            &[RecordType::A, RecordType::AAAA]
        } else {
            &[RecordType::A]
        };
        for &qtype in types {
            // Boxed: lookups nest.
            match Box::pin(self.chase(name, qtype, budget, depth)).await {
                Ok(segments) => {
                    for record in segments.iter().flat_map(|found| &found.records) {
                        if record.record_type() == qtype
                            && let Some(ip) = record.ip()
                        {
                            ips.push(ip);
                            ttl = ttl.min(record.ttl());
                        }
                    }
                }
                Err(err) if err.is_fatal() => return Err(err),
                Err(err) => debug!(server = %name, %err, "cannot find a name server's addresses"),
            }
        }
        let ttl = if ips.is_empty() { 0 } else { ttl };
        self.infra
            .set_addresses(name.clone(), ips, ttl, Instant::now());
        Ok(())
    }

    /// Sends one query to `server`: over TCP if the answer is truncated,
    /// again without 0x20 if the server does not keep case.
    async fn query(
        &self,
        server: SocketAddr,
        name: &Name,
        qtype: RecordType,
        budget: &mut Budget,
    ) -> Result<Response, RecurseError> {
        let ip = server.ip();
        let mut randomize = self.infra.keeps_case(ip);
        let mut tcp = false;
        loop {
            let left = budget.spend()?;
            let outgoing = outgoing(name, qtype, randomize, self.config.dnssec);
            let wait = if tcp {
                left
            } else {
                self.infra.attempt_timeout(ip).min(left)
            };
            let started = Instant::now();
            let result = timeout(wait, async {
                let _permit = self.in_flight.acquire().await;
                self.sent.fetch_add(1, Ordering::Relaxed);
                if tcp {
                    self.tcp.fetch_add(1, Ordering::Relaxed);
                }
                self.network.exchange(server, &outgoing, tcp).await
            })
            .await;
            match result {
                Ok(Ok(response)) if response.truncated && !tcp => {
                    debug!(%server, "truncated answer, retrying over TCP");
                    tcp = true;
                }
                Ok(Ok(mut response)) => {
                    self.infra.answered(ip, started.elapsed());
                    if randomize {
                        // Names compressed against the question carry its
                        // random case: give them back their own.
                        let sections = [
                            &mut response.answers,
                            &mut response.authority,
                            &mut response.additional,
                        ];
                        for record in sections.into_iter().flatten() {
                            record.restore_case(&outgoing.question.name, name);
                        }
                    }
                    return Ok(response);
                }
                Ok(Err(ExchangeError::CaseMismatch)) if randomize => {
                    debug!(%server, "server does not keep case; asking without 0x20");
                    self.infra.ignores_case(ip);
                    randomize = false;
                }
                Ok(Err(err)) => {
                    debug!(%server, %err, "exchange failed");
                    self.infra.failed(ip, Instant::now());
                    return Err(RecurseError::NoServer);
                }
                Err(_) => {
                    self.timeouts.fetch_add(1, Ordering::Relaxed);
                    self.infra.failed(ip, Instant::now());
                    return Err(if budget.deadline <= Instant::now() {
                        RecurseError::Deadline
                    } else {
                        RecurseError::NoServer
                    });
                }
            }
        }
    }
}

/// Runs every DNSSEC check on `response` as if from a server of `zone`
/// asked about `name` / `qtype`, signed or not, keys taken from the
/// response itself: for fuzzing, which checks that nothing panics and the
/// work stays bounded. Returns how many records were kept as evidence and
/// how many signature checks were spent.
#[doc(hidden)]
pub fn check_dnssec(
    response: &Response,
    zone: &Name,
    name: &Name,
    qtype: RecordType,
) -> (usize, u32) {
    use dnssec::{Checks, MAX_CHECKS};

    let records: Vec<Record> = response
        .answers
        .iter()
        .chain(&response.authority)
        .chain(&response.additional)
        .cloned()
        .collect();
    let evidence = dnssec::evidence(zone, response.answers.iter().chain(&response.authority));
    let keys = dnssec::usable_keys(&records);
    let mut checks = Checks::new(MAX_CHECKS);
    let now = 1_800_000_000;
    for rrset in dnssec::rrsets(&response.answers) {
        let Some(first) = rrset.first() else {
            continue;
        };
        if let Some(signer) = dnssec::signer(&evidence, first.name(), first.record_type(), zone) {
            let _ = dnssec::verify_rrset(&rrset, &evidence, &signer, &keys, now, &mut checks);
        }
    }
    let ds: Vec<Record> = records
        .iter()
        .filter(|r| r.record_type() == RecordType::DS)
        .cloned()
        .collect();
    let _ = dnssec::keys_from_ds(zone, &ds, &records, now, &mut checks);
    let _ = dnssec::verified_proofs(&evidence, zone, &keys, now, &mut checks);
    let proofs: Vec<Record> = evidence
        .iter()
        .filter(|r| matches!(r.record_type(), RecordType::NSEC | RecordType::NSEC3))
        .cloned()
        .collect();
    let _ = dnssec::nsec_nxdomain(name, &proofs);
    let _ = dnssec::nsec_nodata(name, qtype, &proofs);
    let _ = dnssec::nsec_wildcard(name, &proofs);
    let _ = dnssec::nsec3_nxdomain(zone, name, &proofs);
    let _ = dnssec::nsec3_nodata(zone, name, qtype, &proofs);
    let _ = dnssec::nsec3_wildcard(zone, name, zone, &proofs);
    let _ = dnssec::ds_denial(zone, name, &proofs);
    for cname in response
        .answers
        .iter()
        .filter(|r| r.record_type() == RecordType::CNAME)
    {
        for dname in evidence
            .iter()
            .filter(|r| r.record_type() == RecordType::DNAME)
        {
            let _ = dnssec::synthesized(cname, dname);
        }
    }
    (evidence.len(), MAX_CHECKS.saturating_sub(checks.left()))
}

/// The next name to show the servers under QNAME minimisation, after
/// `exposed` of `name`'s labels and `steps` minimised queries: one label
/// more for the first few, then the rest spread over the remaining
/// queries; all of it at once from an underscore label on. `None` once the
/// whole name would be shown.
fn next_child(name: &Name, exposed: usize, steps: usize) -> Option<Name> {
    let total = name.label_count();
    let hidden = total.checked_sub(exposed).filter(|&hidden| hidden > 1)?;
    let add = if steps < MINIMISE_ONE_LAB {
        1
    } else {
        let left = MAX_MINIMISE_COUNT.saturating_sub(steps).max(1);
        hidden.checked_div(left).unwrap_or(hidden).max(1)
    };
    let shown = exposed.saturating_add(add).min(total);
    let child = name.suffix(shown)?;
    let underscore = child
        .labels()
        .next()
        .is_some_and(|label| label.first() == Some(&b'_'));
    (shown < total && !underscore).then_some(child)
}

/// The query sent to an authoritative server: a fresh random ID, no
/// recursion desired, the name in random case if `randomize`, and DO set
/// when validating, for the signatures and proofs.
fn outgoing(name: &Name, qtype: RecordType, randomize: bool, dnssec_ok: bool) -> Query {
    let name = if randomize {
        name.with_random_case(rand::random::<bool>)
    } else {
        name.clone()
    };
    Query {
        id: rand::random(),
        recursion_desired: false,
        checking_disabled: false,
        authentic_data: false,
        question: Question {
            name,
            qtype,
            qclass: RecordClass::IN,
        },
        edns: Some(Edns {
            dnssec_ok,
            ..Edns::ours()
        }),
    }
}

fn kind_soa(kind: Kind) -> Option<Record> {
    match kind {
        Kind::NoData { soa } | Kind::NxDomain { soa } => soa,
        _ => None,
    }
}

/// The answer and authority sections for the client: every zone's
/// records and the last one's SOA; for a client that sets DO, also the
/// RRSIGs covering them, the DNAMEs CNAMEs were synthesized from, and the
/// NSEC and NSEC3 proofs, as far as the servers sent them.
fn sections(segments: Vec<Found>, dnssec_ok: bool) -> (Vec<Record>, Vec<Record>) {
    let mut answers = Vec::new();
    let mut authority = Vec::new();
    let mut soa = Vec::new();
    for segment in segments {
        let evidence = &segment.evidence;
        let mut signed = Vec::new();
        if dnssec_ok {
            for rrset in dnssec::rrsets(&segment.records) {
                let Some(first) = rrset.first() else {
                    continue;
                };
                if first.record_type() == RecordType::CNAME
                    && let Some(dname) = evidence.iter().find(|r| {
                        r.record_type() == RecordType::DNAME && dnssec::synthesized(first, r)
                    })
                {
                    signed.push(dname.clone());
                    signed.extend(signatures(evidence, dname));
                }
                signed.extend(signatures(evidence, first));
            }
            let proofs = evidence
                .iter()
                .filter(|r| matches!(r.record_type(), RecordType::NSEC | RecordType::NSEC3));
            for proof in proofs.take(dnssec::MAX_PROOFS) {
                authority.push(proof.clone());
                authority.extend(signatures(evidence, proof));
            }
        }
        soa.clear();
        if let Some(record) = &segment.soa {
            soa.push(record.clone());
            if dnssec_ok {
                soa.extend(signatures(evidence, record));
            }
        }
        answers.extend(segment.records);
        answers.extend(signed);
    }
    soa.extend(authority);
    (answers, soa)
}

/// The RRSIGs in `evidence` covering `record`'s RRset, with its TTL.
fn signatures(evidence: &[Record], record: &Record) -> Vec<Record> {
    dnssec::covering(evidence, record.name(), record.record_type())
        .take(dnssec::MAX_SIGS_PER_RRSET)
        .map(|(sig, _)| {
            let mut sig = sig.clone();
            sig.set_ttl(sig.ttl().min(record.ttl()));
            sig
        })
        .collect()
}
