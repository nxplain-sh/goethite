//! Forwarding queries to upstream resolvers.
//!
//! Upstreams are reached over plain DNS (UDP or TCP), DNS over TLS or DNS over
//! HTTPS. Plain exchanges use defenses against off-path spoofing: a fresh UDP
//! socket with an OS-chosen random source port, connected to the upstream so
//! that datagrams from other addresses are never seen; a random transaction
//! ID; and optionally 0x20 case randomization of the query name. Over every
//! transport, a response is only accepted if its ID, opcode and question (in
//! exactly the sent case) match.

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use goethite_proto::{
    DnsCodec, Edns, HickoryCodec, MAX_UDP_PAYLOAD, Query, Question, Response, ResponseCode,
};
use hyper::Uri;
use rustls::pki_types::ServerName;
use tokio::time::{Instant, timeout};
use tracing::{debug, warn};

use crate::exchange::{self, ExchangeError, OnCaseMismatch};
use crate::restore_question_case;
use crate::tls::{DohClient, DotClient, TlsError, TlsRoots, client_config};

/// The most upstream resolvers one forwarder accepts.
pub const MAX_UPSTREAMS: usize = 16;

/// Failed exchanges in a row before an upstream is tried last for a while.
const FAILURES_BEFORE_DOWN: u32 = 3;

/// How long an upstream that keeps failing is tried after the healthy ones.
const DOWN_FOR: Duration = Duration::from_secs(30);

/// How an upstream is reached.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Transport {
    /// Plain DNS over UDP, retried over TCP when the answer is truncated.
    Udp,
    /// Plain DNS over TCP only.
    Tcp,
    /// DNS over TLS (RFC 7858). The certificate must be valid for
    /// `server_name`.
    Tls {
        /// The name the certificate must be valid for, e.g. `dns.quad9.net`.
        server_name: String,
    },
    /// DNS over HTTPS (RFC 8484): queries are sent to `url` as HTTP/2 POST requests. The
    /// certificate must be valid for the URL's host.
    Https {
        /// The query URL, e.g. `https://dns.quad9.net/dns-query`.
        url: String,
    },
}

/// One upstream resolver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamConfig {
    /// Address and port of the upstream.
    pub address: SocketAddr,
    /// How it is reached.
    pub transport: Transport,
    /// Randomize the case of query names (0x20) and require the upstream to
    /// echo it exactly. Turn off only for an upstream that does not preserve
    /// case.
    pub randomize_case: bool,
}

impl UpstreamConfig {
    /// A UDP upstream with case randomization on.
    pub fn udp(address: SocketAddr) -> Self {
        Self {
            address,
            transport: Transport::Udp,
            randomize_case: true,
        }
    }

    /// A DNS-over-TLS upstream whose certificate is valid for `server_name`.
    pub fn tls(address: SocketAddr, server_name: impl Into<String>) -> Self {
        Self {
            address,
            transport: Transport::Tls {
                server_name: server_name.into(),
            },
            randomize_case: true,
        }
    }

    /// A DNS-over-HTTPS upstream at `address`, queried at `url`.
    pub fn https(address: SocketAddr, url: impl Into<String>) -> Self {
        Self {
            address,
            transport: Transport::Https { url: url.into() },
            randomize_case: true,
        }
    }
}

/// Forwarding settings.
#[derive(Clone, Debug)]
pub struct ForwarderConfig {
    /// Upstreams in order of preference; failover goes down the list.
    pub upstreams: Vec<UpstreamConfig>,
    /// How long one exchange with one upstream may take.
    pub attempt_timeout: Duration,
    /// How long forwarding one query may take in total, across failover.
    pub total_timeout: Duration,
    /// Certificate authorities that DoT and DoH upstreams must chain to.
    pub tls_roots: TlsRoots,
}

impl ForwarderConfig {
    /// Settings for `upstreams` with default timeouts and the bundled roots.
    pub fn new(upstreams: Vec<UpstreamConfig>) -> Self {
        Self {
            upstreams,
            attempt_timeout: Duration::from_secs(2),
            total_timeout: Duration::from_secs(4),
            tls_roots: TlsRoots::Bundled,
        }
    }
}

/// Why a forwarder could not be built.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ForwarderError {
    /// No upstream was configured.
    #[error("no upstream resolvers configured")]
    NoUpstreams,
    /// More upstreams than [`MAX_UPSTREAMS`] were configured.
    #[error("at most {MAX_UPSTREAMS} upstream resolvers are supported, got {0}")]
    TooManyUpstreams(usize),
    /// A DoT server name is not a valid DNS name or IP address.
    #[error("invalid TLS server name {0:?}")]
    InvalidServerName(String),
    /// A DoH URL is not an `https://` URL with a host.
    #[error("invalid DoH URL {0:?}: it must be an https:// URL with a host")]
    InvalidUrl(String),
    /// TLS could not be set up.
    #[error(transparent)]
    Tls(#[from] TlsError),
}

/// Sends queries to upstream resolvers with failover.
pub struct Forwarder {
    upstreams: Vec<Upstream>,
    attempt_timeout: Duration,
    total_timeout: Duration,
    codec: HickoryCodec,
}

/// An upstream and how it is doing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamStatus {
    /// How it is configured.
    pub config: UpstreamConfig,
    /// False while it is skipped after repeated failures.
    pub healthy: bool,
    /// Failures since its last answer.
    pub consecutive_failures: u32,
}

struct Upstream {
    config: UpstreamConfig,
    health: Mutex<Health>,
    connection: Connection,
}

/// Per-upstream connection state.
enum Connection {
    /// Plain DNS: a fresh socket per exchange.
    Plain,
    /// DNS over TLS, with reused connections.
    Tls(DotClient),
    /// DNS over HTTPS, multiplexed over one HTTP/2 connection.
    Https(DohClient),
}

impl Connection {
    fn new(transport: &Transport, roots: &TlsRoots) -> Result<Self, ForwarderError> {
        Ok(match transport {
            Transport::Udp | Transport::Tcp => Self::Plain,
            Transport::Tls { server_name } => {
                let name = ServerName::try_from(server_name.clone())
                    .map_err(|_| ForwarderError::InvalidServerName(server_name.clone()))?;
                Self::Tls(DotClient::new(client_config(roots, &[])?, name))
            }
            Transport::Https { url } => {
                let invalid = || ForwarderError::InvalidUrl(url.clone());
                let uri: Uri = url.parse().map_err(|_| invalid())?;
                if uri.scheme_str() != Some("https") {
                    return Err(invalid());
                }
                let host = uri.host().ok_or_else(invalid)?;
                // IPv6 hosts come bracketed in URLs.
                let host = host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_owned();
                let name = ServerName::try_from(host).map_err(|_| invalid())?;
                Self::Https(DohClient::new(client_config(roots, &[b"h2"])?, name, uri))
            }
        })
    }
}

#[derive(Default)]
struct Health {
    consecutive_failures: u32,
    down_until: Option<Instant>,
}

impl Upstream {
    fn is_down(&self, now: Instant) -> bool {
        self.health
            .lock()
            .is_ok_and(|health| health.down_until.is_some_and(|until| now < until))
    }

    fn succeeded(&self) {
        if let Ok(mut health) = self.health.lock() {
            *health = Health::default();
        }
    }

    fn failed(&self) {
        if let Ok(mut health) = self.health.lock() {
            health.consecutive_failures = health.consecutive_failures.saturating_add(1);
            if health.consecutive_failures >= FAILURES_BEFORE_DOWN {
                health.down_until = Instant::now().checked_add(DOWN_FOR);
            }
        }
    }
}

impl Forwarder {
    /// A forwarder for the configured upstreams.
    ///
    /// # Errors
    ///
    /// Returns [`ForwarderError`] if there are no upstreams or more than
    /// [`MAX_UPSTREAMS`].
    pub fn new(config: ForwarderConfig) -> Result<Self, ForwarderError> {
        if config.upstreams.is_empty() {
            return Err(ForwarderError::NoUpstreams);
        }
        if config.upstreams.len() > MAX_UPSTREAMS {
            return Err(ForwarderError::TooManyUpstreams(config.upstreams.len()));
        }
        let upstreams = config
            .upstreams
            .into_iter()
            .map(|upstream| {
                Ok(Upstream {
                    connection: Connection::new(&upstream.transport, &config.tls_roots)?,
                    config: upstream,
                    health: Mutex::default(),
                })
            })
            .collect::<Result<_, ForwarderError>>()?;
        Ok(Self {
            upstreams,
            attempt_timeout: config.attempt_timeout,
            total_timeout: config.total_timeout,
            codec: HickoryCodec,
        })
    }

    /// Forwards `query` and returns the response for the client.
    ///
    /// Upstreams are tried in order, healthy ones first. An answer other than
    /// NOERROR or NXDOMAIN moves on to the next upstream. If none gives a
    /// usable answer in time, the result is SERVFAIL.
    pub async fn forward(&self, query: &Query) -> Response {
        self.forward_from(query).await.0
    }

    /// Like [`Forwarder::forward`], also returning the index of the upstream
    /// that answered, or `None` for SERVFAIL.
    pub async fn forward_from(&self, query: &Query) -> (Response, Option<usize>) {
        let start = Instant::now();
        let deadline = start.checked_add(self.total_timeout).unwrap_or(start);
        for (index, upstream) in self.in_order(start) {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let address = upstream.config.address;
            let attempt = timeout(
                left.min(self.attempt_timeout),
                self.exchange(upstream, query),
            );
            match attempt.await {
                Ok(Ok(response))
                    if matches!(
                        response.rcode,
                        ResponseCode::NO_ERROR | ResponseCode::NX_DOMAIN
                    ) =>
                {
                    upstream.succeeded();
                    return (to_client(query, response), Some(index));
                }
                Ok(Ok(response)) => {
                    debug!(%address, rcode = %response.rcode, "upstream could not answer");
                    upstream.failed();
                }
                Ok(Err(err)) => {
                    debug!(%address, %err, "upstream exchange failed");
                    upstream.failed();
                }
                Err(_) => {
                    debug!(%address, "upstream timed out");
                    upstream.failed();
                }
            }
        }
        warn!(
            name = %query.question.name,
            qtype = %query.question.qtype,
            "no upstream answered"
        );
        let mut response = Response::for_query(query, ResponseCode::SERV_FAIL);
        response.recursion_available = true;
        (response, None)
    }

    /// Healthy upstreams first, then those that keep failing, each group in
    /// configured order, with their index.
    fn in_order(&self, now: Instant) -> impl Iterator<Item = (usize, &Upstream)> {
        let all = self.upstreams.iter().enumerate();
        let healthy = all.clone().filter(move |(_, u)| !u.is_down(now));
        let down = all.filter(move |(_, u)| u.is_down(now));
        healthy.chain(down)
    }

    /// The upstreams, in configured order, and how they are doing.
    pub fn upstreams(&self) -> Vec<UpstreamStatus> {
        let now = Instant::now();
        self.upstreams
            .iter()
            .map(|upstream| UpstreamStatus {
                config: upstream.config.clone(),
                healthy: !upstream.is_down(now),
                consecutive_failures: upstream
                    .health
                    .lock()
                    .map_or(0, |health| health.consecutive_failures),
            })
            .collect()
    }

    async fn exchange(
        &self,
        upstream: &Upstream,
        query: &Query,
    ) -> Result<Response, ExchangeError> {
        let mut outgoing = upstream_query(query, upstream.config.randomize_case);
        if matches!(upstream.connection, Connection::Https(_)) {
            // RFC 8484 4.1: DoH clients use ID 0, which keeps responses
            // cacheable by HTTP caches.
            outgoing.id = 0;
        }
        if matches!(
            upstream.connection,
            Connection::Tls(_) | Connection::Https(_)
        ) {
            // RFC 8467: over encryption, pad the query (to 128 bytes) so its
            // length says less about the name; the upstream pads its answer.
            if let Some(edns) = outgoing.edns.as_mut() {
                edns.padding = true;
            }
        }
        let mut wire = Vec::new();
        self.codec.encode_query(&outgoing, &mut wire)?;
        let address = upstream.config.address;
        match (&upstream.connection, &upstream.config.transport) {
            (Connection::Tls(client), _) => {
                let reply = client.exchange(address, &wire).await?;
                exchange::accept(&reply, &outgoing)
            }
            (Connection::Https(client), _) => {
                let reply = client.exchange(address, &wire).await?;
                exchange::accept(&reply, &outgoing)
            }
            (Connection::Plain, Transport::Udp) => {
                let response =
                    exchange::udp(address, &wire, &outgoing, OnCaseMismatch::Ignore).await?;
                if response.truncated {
                    debug!(%address, "truncated answer, retrying over TCP");
                    exchange::tcp(address, &wire, &outgoing).await
                } else {
                    Ok(response)
                }
            }
            (Connection::Plain, _) => exchange::tcp(address, &wire, &outgoing).await,
        }
    }
}

/// The query goethite sends upstream on behalf of `query`: a fresh random ID,
/// the name in random case if enabled, recursion desired, and the client's
/// `CD` and `DO` bits.
fn upstream_query(query: &Query, randomize_case: bool) -> Query {
    let name = if randomize_case {
        query.question.name.with_random_case(rand::random::<bool>)
    } else {
        query.question.name.clone()
    };
    Query {
        id: rand::random(),
        recursion_desired: true,
        checking_disabled: query.checking_disabled,
        authentic_data: false,
        question: Question {
            name,
            qtype: query.question.qtype,
            qclass: query.question.qclass,
        },
        edns: Some(Edns {
            udp_payload_size: MAX_UDP_PAYLOAD,
            dnssec_ok: query.edns.is_some_and(|edns| edns.dnssec_ok),
            padding: false,
        }),
    }
}

/// Rewrites an upstream response for the client: the client's ID, question
/// and flags, goethite's EDNS parameters, and owner names that repeat the
/// question in the client's own case rather than the randomized one.
fn to_client(query: &Query, upstream: Response) -> Response {
    // An extended code cannot be sent to a client that did not use EDNS.
    let rcode = if upstream.rcode.0 > 0x0f && query.edns.is_none() {
        ResponseCode::SERV_FAIL
    } else {
        upstream.rcode
    };
    let mut response = Response::for_query(query, rcode);
    response.recursion_available = true;
    response.answers = upstream.answers;
    response.authority = upstream.authority;
    response.additional = upstream.additional;
    restore_question_case(&mut response, &query.question.name);
    response
}
