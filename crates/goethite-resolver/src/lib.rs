//! Query resolution for goethite.
//!
//! The [`Resolver`] runs the resolution pipeline for one query: query-type
//! policy, client identification and its group's policy, local records, the
//! filter check, safe search, the cache, forwarding to upstream resolvers,
//! and CNAME uncloaking. Each answer comes with a [`Resolution`] saying how
//! it came about. Later phases add recursion with DNSSEC validation.

#![forbid(unsafe_code)]

mod blocking;
mod cache;
mod cidr;
mod exchange;
mod forward;
mod guard;
mod policy;
mod rebinding;
pub mod recurse;
mod safe_search;
mod services;
mod tls;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use goethite_filter::{Action, Match, Sources, Verdict};
use tracing::{debug, error};

use goethite_proto::{
    Edns, Name, NameError, Query, Question, Record, RecordClass, RecordType, Response, ResponseCode,
};

pub use blocking::BlockResponse;
pub use cache::{Cache, CacheConfig, CacheStats, MAX_CACHED_RECORDS, MAX_CNAME_CHAIN, MAX_ENTRIES};
pub use cidr::{Cidr, CidrError};
pub use forward::{
    Forwarder, ForwarderConfig, ForwarderError, MAX_UPSTREAMS, Transport, UpstreamConfig,
    UpstreamStatus,
};
pub use guard::FailMode;
pub use policy::{
    ClientPolicy, GroupPolicy, MAX_CLIENT_ID_LEN, MAX_SCHEDULES, Policy, PolicyError, PolicyParts,
    PolicyState, ScheduledServices, ScheduledSources, is_client_id,
};
pub use rebinding::{DEFAULT_PRIVATE_DOMAINS, RebindingProtection, is_private};
pub use recurse::{Recursor, RecursorConfig, RecursorStats};
pub use services::{
    MAX_SERVICE_ID_LEN, MAX_SERVICES, ServiceError, ServiceFilter, ServiceMask, ServiceRules,
    is_service_id,
};
pub use tls::{TlsError, TlsRoots, tls_client_config};

/// The name every build answers itself, to check that the server is alive.
/// Every name below it is goethite's own too: answered locally (NXDOMAIN
/// unless it is a built-in record), never forwarded, never filtered. The
/// DNS leak test's names are there.
pub const TEST_NAME: &str = "goethite.test.";

/// The address [`TEST_NAME`] resolves to.
pub const TEST_ADDR: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 53);

/// Time to live of the built-in test record, in seconds.
pub const TEST_TTL: u32 = 60;

/// Time to live of the CNAME that sends a search host to its safe endpoint.
const SAFE_SEARCH_TTL: u32 = 60;

/// The name `goethite vrrp` checks the server with, once a second. It is
/// answered like [`TEST_NAME`], and the binary leaves it out of the query
/// log and the statistics.
pub const HEALTH_NAME: &str = "health.goethite.test.";

/// The built-in record `goethite.test. 60 IN A 127.0.0.53`.
///
/// # Errors
///
/// Never in practice; [`TEST_NAME`] is a valid name. The `Result` keeps name
/// parsing panic-free.
pub fn test_record() -> Result<Record, NameError> {
    Ok(Record::a(TEST_NAME.parse::<Name>()?, TEST_TTL, TEST_ADDR))
}

/// The built-in record `health.goethite.test. 0 IN A 127.0.0.53`: never
/// cached, so every check reaches the server.
///
/// # Errors
///
/// Never in practice; [`HEALTH_NAME`] is a valid name.
pub fn health_record() -> Result<Record, NameError> {
    Ok(Record::a(HEALTH_NAME.parse::<Name>()?, 0, TEST_ADDR))
}

/// Gives records whose owner is the question name the client's own case,
/// rather than the randomized case used upstream or another client's case.
pub(crate) fn restore_question_case(response: &mut Response, name: &Name) {
    let sections = [
        &mut response.answers,
        &mut response.authority,
        &mut response.additional,
    ];
    for record in sections.into_iter().flatten() {
        if record.name() == name && !record.name().eq_exact(name) {
            record.set_name(name.clone());
        }
    }
}

/// How an answer came about, for the query log and metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// From goethite's own records.
    Local,
    /// Refused or rejected by policy: a zone transfer, a meta type, a class
    /// other than `IN`, or no upstream configured.
    Rejected,
    /// Blocked by the filter, possibly through a CNAME;
    /// [`Resolution::filter`] says by what.
    Blocked,
    /// A search host sent to its safe endpoint.
    SafeSearch,
    /// From the cache.
    Cached,
    /// From the upstream with this index.
    Upstream(usize),
    /// Resolved from the authoritative servers; this one answered last.
    Recursive(std::net::SocketAddr),
    /// No upstream answered in time: SERVFAIL.
    Failed,
}

/// The filter rule that applied to a query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterHit {
    /// A block, or an exception that kept the name from being blocked.
    pub action: Action,
    /// The deciding rule.
    pub matched: Match,
    /// The ID of the rule's source, such as a list ID.
    pub source: Option<Arc<str>>,
    /// For a block found by CNAME uncloaking, the CNAME target that matched.
    pub cname: Option<Name>,
}

impl FilterHit {
    /// The rule in AdGuard syntax, for a query for `name`.
    pub fn rule_text(&self, name: &Name) -> String {
        self.matched
            .rule_text(self.cname.as_ref().unwrap_or(name), self.action)
    }
}

/// An answer and how it came about.
#[derive(Clone, Debug)]
pub struct Resolution {
    /// The response for the client.
    pub response: Response,
    /// How it came about.
    pub outcome: Outcome,
    /// The filter rule that applied, if one did.
    pub filter: Option<FilterHit>,
    /// The known client that asked, by ID.
    pub client: Option<Arc<str>>,
    /// The asking client's group, by ID.
    pub group: Option<Arc<str>>,
    /// Whether the asking client's queries are filtered: its group filters,
    /// and protection is on and not paused.
    pub filtering: bool,
}

/// What applies to the client asking a query.
struct Asker {
    policy: Option<Arc<Policy>>,
    client: Option<Arc<str>>,
    group: Option<Arc<str>>,
    filtering: bool,
    safe_search: bool,
    sources: Sources,
    services: ServiceMask,
}

/// Answers queries.
pub struct Resolver {
    local: Vec<Record>,
    /// [`TEST_NAME`]: names below it are answered locally.
    own: Option<Name>,
    policy: Option<Arc<PolicyState>>,
    rebinding: Option<RebindingProtection>,
    cache: Option<Cache>,
    forwarder: Option<Forwarder>,
    recursor: Option<Recursor>,
    fail_mode: FailMode,
    filter_failures: AtomicU64,
}

impl Resolver {
    /// A resolver that answers authoritatively for the names in `local` and
    /// refuses everything else.
    pub fn new(local: Vec<Record>) -> Self {
        Self {
            local,
            own: TEST_NAME.parse().ok(),
            policy: None,
            rebinding: None,
            cache: None,
            forwarder: None,
            recursor: None,
            fail_mode: FailMode::Open,
            filter_failures: AtomicU64::new(0),
        }
    }

    /// What to do with a query when filtering it fails (open by default).
    #[must_use]
    pub fn with_fail_mode(mut self, mode: FailMode) -> Self {
        self.fail_mode = mode;
        self
    }

    /// How many times filtering a query failed. Anything above zero is a
    /// bug worth reporting.
    pub fn filter_failures(&self) -> u64 {
        self.filter_failures.load(Ordering::Relaxed)
    }

    /// The filter's verdict on `name`, or `None` if checking failed.
    fn check(policy: &Policy, name: &Name, sources: Sources) -> Option<Verdict> {
        guard::guarded(|| policy.filter().check(name, sources))
    }

    /// Counts a failed filter check on `query`. Returns the answer in
    /// closed mode (SERVFAIL); in open mode the query goes on unfiltered.
    fn filter_failed(&self, query: &Query) -> Option<(Response, Outcome, Option<FilterHit>)> {
        let count = self
            .filter_failures
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        if guard::worth_logging(count) {
            error!(
                failures = count,
                mode = ?self.fail_mode,
                name = %query.question.name,
                "filtering a query failed, which is a bug; please report it"
            );
        }
        match self.fail_mode {
            FailMode::Open => None,
            FailMode::Closed => Some((
                Response::for_query(query, ResponseCode::SERV_FAIL),
                Outcome::Failed,
                None,
            )),
        }
    }

    /// Filters and identifies clients by `policy`. The caller keeps its own
    /// handle to swap in new policies, set the active schedules and pause.
    #[must_use]
    pub fn with_policy(mut self, policy: Arc<PolicyState>) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Removes private addresses from forwarded answers for public names.
    #[must_use]
    pub fn with_rebinding_protection(mut self, protection: RebindingProtection) -> Self {
        self.rebinding = Some(protection);
        self
    }

    /// Answers forwarded queries from `cache` while they are fresh.
    #[must_use]
    pub fn with_cache(mut self, cache: Cache) -> Self {
        self.cache = Some(cache);
        self
    }

    /// The cache, if one is configured.
    pub fn cache(&self) -> Option<&Cache> {
        self.cache.as_ref()
    }

    /// Forwards everything that is not a local name to `forwarder`.
    #[must_use]
    pub fn with_forwarder(mut self, forwarder: Forwarder) -> Self {
        self.forwarder = Some(forwarder);
        self
    }

    /// The forwarder, if one is configured.
    pub fn forwarder(&self) -> Option<&Forwarder> {
        self.forwarder.as_ref()
    }

    /// Resolves everything that is not a local name from the root servers
    /// down with `recursor`, instead of forwarding.
    #[must_use]
    pub fn with_recursor(mut self, recursor: Recursor) -> Self {
        self.recursor = Some(recursor);
        self
    }

    /// The recursor, if recursion is on.
    pub fn recursor(&self) -> Option<&Recursor> {
        self.recursor.as_ref()
    }

    /// Whether queries are resolved at all: forwarded or recursively.
    fn resolves(&self) -> bool {
        self.forwarder.is_some() || self.recursor.is_some()
    }

    /// Answers `query` from `client`.
    ///
    /// - zone transfers (`AXFR`, `IXFR`): `REFUSED`, since none are offered
    ///   (RFC 5936);
    /// - meta-types and obsolete query types that have no place in a question
    ///   (`OPT`, `TKEY`, `TSIG`, `MAILA`, `MAILB`, 128 to 248): `FORMERR`, as
    ///   Unbound answers them (RFC 6895);
    /// - classes other than `IN` (e.g. `CH` server-identification probes):
    ///   `REFUSED`, never forwarded;
    /// - a name with local records: those records of the asked type,
    ///   authoritatively, or an empty `NOERROR` (NODATA) if there are none;
    ///   any other name under [`TEST_NAME`] (such as the DNS leak test's):
    ///   `NXDOMAIN`, authoritatively, never forwarded or filtered;
    /// - a name the filter blocks for the client's group: the configured
    ///   block response, even if an answer is cached;
    /// - a search host, when the group has safe search on: a CNAME to the
    ///   engine's safe endpoint and that endpoint's records;
    /// - a fresh cached answer, with TTLs counted down;
    /// - anything else: forwarded upstream or resolved recursively, with
    ///   private addresses removed for public names if rebinding protection
    ///   is on, and cached if cacheable; or `REFUSED` with neither. With
    ///   recursion, special-use names (`localhost`, `invalid`, private
    ///   reverse zones…) are answered without asking anyone.
    ///
    /// An answer whose CNAME chain leads to a name the filter blocks is
    /// blocked too (CNAME uncloaking), unless an exception matched the name
    /// asked for.
    pub async fn resolve(&self, query: &Query, client: IpAddr) -> Resolution {
        self.resolve_with_id(query, client, None).await
    }

    /// Answers `query` from `client`, as [`Resolver::resolve`] does, for a
    /// client that also gave a client ID (over an encrypted transport). A
    /// known ID identifies the client before its address does.
    pub async fn resolve_with_id(
        &self,
        query: &Query,
        client: IpAddr,
        client_id: Option<&str>,
    ) -> Resolution {
        let asker = self.asker(client, client_id);
        let (mut response, outcome, filter) = self.answer(query, &asker).await;
        response.recursion_available = self.resolves();
        // AD only for a client that shows it understands it, with AD or DO
        // (RFC 6840, 5.7 and 5.8).
        response.authentic_data &=
            query.authentic_data || query.edns.is_some_and(|edns| edns.dnssec_ok);
        Resolution {
            response,
            outcome,
            filter,
            client: asker.client,
            group: asker.group,
            filtering: asker.filtering,
        }
    }

    /// Whether a known client uses the client ID `id`.
    pub fn knows_client_id(&self, id: &str) -> bool {
        self.policy
            .as_ref()
            .is_some_and(|state| state.policy().client_with_id(id).is_some())
    }

    fn asker(&self, client: IpAddr, client_id: Option<&str>) -> Asker {
        let Some(state) = &self.policy else {
            return Asker {
                policy: None,
                client: None,
                group: None,
                filtering: false,
                safe_search: false,
                sources: Sources::NONE,
                services: ServiceMask::NONE,
            };
        };
        let policy = state.policy();
        let (known, group) = policy.identify(client, client_id);
        let on = policy.protection() && !state.is_paused();
        let asker = Asker {
            client: known.map(|known| Arc::clone(&known.id)),
            group: Some(Arc::clone(&group.id)),
            filtering: on && group.filtering,
            safe_search: on && group.safe_search,
            sources: group.sources_now(state.active_schedules()),
            services: group.services_now(state.active_schedules()),
            policy: None,
        };
        Asker {
            policy: Some(policy),
            ..asker
        }
    }

    async fn answer(&self, query: &Query, asker: &Asker) -> (Response, Outcome, Option<FilterHit>) {
        let question = &query.question;
        let rejected = |rcode| (Response::for_query(query, rcode), Outcome::Rejected, None);
        if matches!(question.qtype, RecordType::AXFR | RecordType::IXFR) {
            return rejected(ResponseCode::REFUSED);
        }
        if is_meta_qtype(question.qtype) {
            return rejected(ResponseCode::FORM_ERR);
        }
        if question.qclass != RecordClass::IN {
            return rejected(ResponseCode::REFUSED);
        }
        if let Some(response) = self.local_answer(query) {
            return (response, Outcome::Local, None);
        }
        let mut exception = None;
        if let (true, Some(policy)) = (asker.filtering, &asker.policy) {
            // A blocked service is the group's own choice: no list's
            // exception undoes it.
            if !asker.services.is_empty() {
                match guard::guarded(|| policy.services().check(&question.name, &asker.services)) {
                    Some(Some((service, matched))) => {
                        debug!(name = %question.name, qtype = %question.qtype, "blocked service");
                        return blocked_service(query, policy, service, matched);
                    }
                    Some(None) => {}
                    None => {
                        if let Some(answer) = self.filter_failed(query) {
                            return answer;
                        }
                    }
                }
            }
            match Self::check(policy, &question.name, asker.sources) {
                Some(Verdict::Blocked(matched)) => {
                    debug!(name = %question.name, qtype = %question.qtype, "blocked");
                    return blocked(query, policy, matched, None);
                }
                Some(Verdict::Allowed(matched)) => {
                    exception = Some(hit(policy, Action::Allow, matched, None));
                }
                Some(Verdict::Pass) => {}
                None => {
                    if let Some(answer) = self.filter_failed(query) {
                        return answer;
                    }
                }
            }
        }
        if !self.resolves() {
            return rejected(ResponseCode::REFUSED);
        }
        if asker.safe_search
            && let Some(target) = safe_search::target(&question.name)
        {
            return (
                self.safe_search(query, target).await,
                Outcome::SafeSearch,
                exception,
            );
        }
        let (response, outcome) = self.cached_or_forwarded(query).await;
        if let (true, None, Some(policy)) = (asker.filtering, &exception, &asker.policy) {
            let targets = response.answers.iter().filter_map(Record::cname_target);
            for target in targets.take(MAX_CNAME_CHAIN) {
                match Self::check(policy, &target, asker.sources) {
                    Some(Verdict::Blocked(matched)) => {
                        debug!(name = %question.name, cname = %target, "blocked through a CNAME");
                        return blocked(query, policy, matched, Some(target));
                    }
                    Some(Verdict::Allowed(_) | Verdict::Pass) => {}
                    None => {
                        if let Some(answer) = self.filter_failed(query) {
                            return answer;
                        }
                    }
                }
            }
        }
        (response, outcome, exception)
    }

    /// The answer from the cache, or else from the upstreams or the
    /// authoritative servers (with rebinding protection applied, then
    /// cached).
    async fn cached_or_forwarded(&self, query: &Query) -> (Response, Outcome) {
        if self.recursor.is_some()
            && let Some(response) = Recursor::special(query)
        {
            return (response, Outcome::Local);
        }
        if let Some(response) = self.cache.as_ref().and_then(|cache| cache.get(query)) {
            return (response, Outcome::Cached);
        }
        let (mut response, outcome) = if let Some(recursor) = &self.recursor {
            let (response, server) = recursor.resolve(query).await;
            (response, server.map_or(Outcome::Failed, Outcome::Recursive))
        } else if let Some(forwarder) = &self.forwarder {
            let (response, upstream) = forwarder.forward_from(query).await;
            (
                response,
                upstream.map_or(Outcome::Failed, Outcome::Upstream),
            )
        } else {
            return (
                Response::for_query(query, ResponseCode::REFUSED),
                Outcome::Rejected,
            );
        };
        if let Some(protection) = &self.rebinding {
            let removed = protection.apply(&query.question.name, &mut response);
            if removed > 0 {
                // No longer what was signed.
                response.authentic_data = false;
                debug!(
                    name = %query.question.name,
                    removed,
                    "rebinding protection removed private addresses"
                );
            }
        }
        if let Some(cache) = &self.cache {
            cache.insert(query, &response);
        }
        (response, outcome)
    }

    /// A CNAME from the asked name to `target`, followed by `target`'s own
    /// answer for the same type.
    async fn safe_search(&self, query: &Query, target: &Name) -> Response {
        let mut inner = query.clone();
        inner.question.name = target.clone();
        let (answer, _) = self.cached_or_forwarded(&inner).await;
        let mut response = Response::for_query(query, answer.rcode);
        response.answers.push(Record::cname(
            query.question.name.clone(),
            SAFE_SEARCH_TTL,
            target.clone(),
        ));
        response.answers.extend(answer.answers);
        response.authority = answer.authority;
        response
    }

    /// The IPv4 and IPv6 addresses of `name`, for goethite's own use (such as
    /// downloading filter lists): local records, the cache, then the
    /// upstreams. The filter is skipped on purpose, since a list may block
    /// the very host it is downloaded from.
    pub async fn lookup_addresses(&self, name: &Name) -> Vec<IpAddr> {
        let mut addresses = Vec::new();
        for qtype in [RecordType::A, RecordType::AAAA] {
            let query = Query {
                id: 0,
                recursion_desired: true,
                checking_disabled: false,
                authentic_data: false,
                question: Question {
                    name: name.clone(),
                    qtype,
                    qclass: RecordClass::IN,
                },
                edns: Some(Edns::ours()),
            };
            let response = if let Some(response) = self.local_answer(&query) {
                response
            } else if self.resolves() || self.cache.is_some() {
                self.cached_or_forwarded(&query).await.0
            } else {
                continue;
            };
            addresses.extend(
                response
                    .answers
                    .iter()
                    .filter(|record| record.record_type() == qtype)
                    .filter_map(Record::ip),
            );
        }
        addresses
    }

    fn local_answer(&self, query: &Query) -> Option<Response> {
        let question = &query.question;
        let mut matching = self
            .local
            .iter()
            .filter(|record| record.name() == &question.name)
            .peekable();
        if matching.peek().is_none() {
            // goethite's own names that do not exist, the leak test's
            // included: never asked of anyone else.
            let own = self
                .own
                .as_ref()
                .is_some_and(|own| question.name.is_within(own));
            if !own {
                return None;
            }
            let mut response = Response::for_query(query, ResponseCode::NX_DOMAIN);
            response.authoritative = true;
            return Some(response);
        }
        let mut response = Response::for_query(query, ResponseCode::NO_ERROR);
        response.authoritative = true;
        response.answers = matching
            .filter(|record| {
                question.qtype == RecordType::ANY || record.record_type() == question.qtype
            })
            .cloned()
            .collect();
        Some(response)
    }
}

/// The block response for `query`, with the rule that decided it.
fn blocked(
    query: &Query,
    policy: &Policy,
    matched: Match,
    cname: Option<Name>,
) -> (Response, Outcome, Option<FilterHit>) {
    let response = blocking::blocked_response(query, policy.block_response(), policy.blocked_ttl());
    let hit = hit(policy, Action::Block, matched, cname);
    (response, Outcome::Blocked, Some(hit))
}

/// The answer to a name a blocked service uses.
fn blocked_service(
    query: &Query,
    policy: &Policy,
    service: usize,
    matched: Match,
) -> (Response, Outcome, Option<FilterHit>) {
    let response = blocking::blocked_response(query, policy.block_response(), policy.blocked_ttl());
    let hit = FilterHit {
        action: Action::Block,
        matched,
        source: policy.services().source_id(service).cloned(),
        cname: None,
    };
    (response, Outcome::Blocked, Some(hit))
}

fn hit(policy: &Policy, action: Action, matched: Match, cname: Option<Name>) -> FilterHit {
    FilterHit {
        action,
        matched,
        source: policy.source_id(matched.source).cloned(),
        cname,
    }
}

/// Types that are not valid in a question: meta-types other than `ANY` and
/// the zone transfers, plus the obsolete mail query types.
fn is_meta_qtype(qtype: RecordType) -> bool {
    matches!(
        qtype,
        RecordType::OPT
            | RecordType::TKEY
            | RecordType::TSIG
            | RecordType::MAILB
            | RecordType::MAILA
    ) || (128..=248).contains(&qtype.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolver() -> Resolver {
        Resolver::new(vec![test_record().unwrap()])
    }

    fn query(name: &str, qtype: RecordType, qclass: RecordClass) -> Query {
        Query {
            id: 42,
            recursion_desired: true,
            checking_disabled: false,
            authentic_data: false,
            question: Question {
                name: name.parse().unwrap(),
                qtype,
                qclass,
            },
            edns: Some(Edns {
                udp_payload_size: 4096,
                dnssec_ok: false,
                padding: false,
            }),
        }
    }

    #[test]
    fn a_failed_filter_check_fails_open_or_closed() {
        let query = query("ads.example.", RecordType::A, RecordClass::IN);
        let open = resolver();
        assert!(
            open.filter_failed(&query).is_none(),
            "open: the query goes on"
        );
        assert_eq!(open.filter_failures(), 1);
        let closed = resolver().with_fail_mode(FailMode::Closed);
        let (response, outcome, hit) = closed.filter_failed(&query).unwrap();
        assert_eq!(response.rcode, ResponseCode::SERV_FAIL);
        assert_eq!((outcome, hit), (Outcome::Failed, None));
        closed.filter_failed(&query);
        assert_eq!(closed.filter_failures(), 2);
    }

    /// Resolves without a runtime: the paths tested here never wait.
    fn resolve(resolver: &Resolver, query: &Query) -> Response {
        let client = IpAddr::from(Ipv4Addr::LOCALHOST);
        let mut future = std::pin::pin!(resolver.resolve(query, client));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        match future.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(resolution) => resolution.response,
            std::task::Poll::Pending => panic!("local resolution should not wait"),
        }
    }

    #[test]
    fn answers_the_test_name() {
        let response = resolve(
            &resolver(),
            &query(TEST_NAME, RecordType::A, RecordClass::IN),
        );
        assert_eq!(response.rcode, ResponseCode::NO_ERROR);
        assert!(response.authoritative);
        assert!(!response.recursion_available);
        assert_eq!(response.id, 42);
        assert_eq!(response.answers, vec![test_record().unwrap()]);
    }

    #[test]
    fn name_matching_ignores_case() {
        let response = resolve(
            &resolver(),
            &query("GoEtHiTe.TeSt", RecordType::A, RecordClass::IN),
        );
        assert_eq!(response.rcode, ResponseCode::NO_ERROR);
        assert_eq!(response.answers.len(), 1);
    }

    #[test]
    fn other_types_of_the_test_name_get_nodata() {
        let response = resolve(
            &resolver(),
            &query(TEST_NAME, RecordType::AAAA, RecordClass::IN),
        );
        assert_eq!(response.rcode, ResponseCode::NO_ERROR);
        assert_eq!(response.answers, vec![]);
    }

    #[test]
    fn zone_transfers_are_refused() {
        for qtype in [RecordType::AXFR, RecordType::IXFR] {
            let response = resolve(&resolver(), &query(TEST_NAME, qtype, RecordClass::IN));
            assert_eq!(response.rcode, ResponseCode::REFUSED, "{qtype}");
            assert!(!response.authoritative);
            assert_eq!(response.answers, vec![]);
        }
    }

    #[test]
    fn meta_types_get_formerr() {
        for qtype in [
            RecordType::OPT,
            RecordType::TKEY,
            RecordType::TSIG,
            RecordType::MAILA,
            RecordType::MAILB,
            RecordType(128),
            RecordType(248),
        ] {
            for name in [TEST_NAME, "example.com."] {
                let response = resolve(&resolver(), &query(name, qtype, RecordClass::IN));
                assert_eq!(response.rcode, ResponseCode::FORM_ERR, "{name} {qtype}");
            }
        }
        // ANY (255) and ordinary types above the meta range are not meta-types.
        let any = resolve(
            &resolver(),
            &query(TEST_NAME, RecordType::ANY, RecordClass::IN),
        );
        assert_eq!(any.rcode, ResponseCode::NO_ERROR);
        assert_eq!(any.answers.len(), 1);
        let caa = resolve(
            &resolver(),
            &query(TEST_NAME, RecordType(257), RecordClass::IN),
        );
        assert_eq!(caa.rcode, ResponseCode::NO_ERROR);
    }

    #[test]
    fn without_a_forwarder_everything_else_is_refused() {
        for (name, qclass) in [
            ("example.com.", RecordClass::IN),
            ("test.", RecordClass::IN),
            (TEST_NAME, RecordClass::CH),
        ] {
            let response = resolve(&resolver(), &query(name, RecordType::A, qclass));
            assert_eq!(response.rcode, ResponseCode::REFUSED, "{name} {qclass}");
            assert_eq!(response.answers, vec![]);
            assert!(!response.authoritative);
        }
        // Names below goethite.test are goethite's own: they do not exist.
        let own = resolve(
            &resolver(),
            &query("sub.goethite.test.", RecordType::A, RecordClass::IN),
        );
        assert_eq!(own.rcode, ResponseCode::NX_DOMAIN);
        assert!(own.authoritative);
    }
}
