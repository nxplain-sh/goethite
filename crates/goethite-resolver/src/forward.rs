//! Forwarding queries to upstream resolvers over plain DNS.
//!
//! Every exchange uses defenses against off-path spoofing: a fresh UDP socket
//! with an OS-chosen random source port, connected to the upstream so that
//! datagrams from other addresses are never seen; a random transaction ID; and
//! optionally 0x20 case randomization of the query name. A response is only
//! accepted if its ID, opcode and question (in exactly the sent case) match.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;

use goethite_proto::{
    DnsCodec, Edns, EncodeError, HickoryCodec, MAX_UDP_PAYLOAD, Opcode, Query, Question, Response,
    ResponseCode, ResponseError,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Instant, timeout};
use tracing::{debug, warn};

/// The most upstream resolvers one forwarder accepts.
pub const MAX_UPSTREAMS: usize = 16;

/// UDP responses larger than this are dropped. goethite advertises
/// [`MAX_UDP_PAYLOAD`], so honest upstreams stay well below it.
const MAX_UDP_RESPONSE_LEN: usize = 4096;

/// Failed exchanges in a row before an upstream is tried last for a while.
const FAILURES_BEFORE_DOWN: u32 = 3;

/// How long an upstream that keeps failing is tried after the healthy ones.
const DOWN_FOR: Duration = Duration::from_secs(30);

/// How an upstream is reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Transport {
    /// Plain DNS over UDP, retried over TCP when the answer is truncated.
    Udp,
    /// Plain DNS over TCP only.
    Tcp,
}

/// One upstream resolver.
#[derive(Clone, Debug)]
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
}

impl ForwarderConfig {
    /// Settings for `upstreams` with default timeouts.
    pub fn new(upstreams: Vec<UpstreamConfig>) -> Self {
        Self {
            upstreams,
            attempt_timeout: Duration::from_secs(2),
            total_timeout: Duration::from_secs(4),
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
}

/// Why one exchange with one upstream failed.
#[derive(Debug, thiserror::Error)]
enum ExchangeError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Encode(#[from] EncodeError),
    #[error(transparent)]
    Decode(#[from] ResponseError),
    #[error("response does not match the query")]
    Mismatch,
}

/// Sends queries to upstream resolvers with failover.
pub struct Forwarder {
    upstreams: Vec<Upstream>,
    attempt_timeout: Duration,
    total_timeout: Duration,
    codec: HickoryCodec,
}

struct Upstream {
    config: UpstreamConfig,
    health: Mutex<Health>,
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
        Ok(Self {
            upstreams: config
                .upstreams
                .into_iter()
                .map(|config| Upstream {
                    config,
                    health: Mutex::default(),
                })
                .collect(),
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
        let start = Instant::now();
        let deadline = start.checked_add(self.total_timeout).unwrap_or(start);
        for upstream in self.in_order(start) {
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
                    return to_client(query, response);
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
        response
    }

    /// Healthy upstreams first, then those that keep failing, each group in
    /// configured order.
    fn in_order(&self, now: Instant) -> impl Iterator<Item = &Upstream> {
        let healthy = self.upstreams.iter().filter(move |u| !u.is_down(now));
        let down = self.upstreams.iter().filter(move |u| u.is_down(now));
        healthy.chain(down)
    }

    async fn exchange(
        &self,
        upstream: &Upstream,
        query: &Query,
    ) -> Result<Response, ExchangeError> {
        let outgoing = upstream_query(query, upstream.config.randomize_case);
        let mut wire = Vec::new();
        self.codec.encode_query(&outgoing, &mut wire)?;
        let address = upstream.config.address;
        match upstream.config.transport {
            Transport::Udp => {
                let response = self.exchange_udp(address, &wire, &outgoing).await?;
                if response.truncated {
                    debug!(%address, "truncated answer, retrying over TCP");
                    self.exchange_tcp(address, &wire, &outgoing).await
                } else {
                    Ok(response)
                }
            }
            Transport::Tcp => self.exchange_tcp(address, &wire, &outgoing).await,
        }
    }

    async fn exchange_udp(
        &self,
        address: SocketAddr,
        wire: &[u8],
        sent: &Query,
    ) -> Result<Response, ExchangeError> {
        let local = if address.is_ipv4() {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        };
        // Port 0: the OS picks a random ephemeral port for every exchange.
        let socket = UdpSocket::bind(local).await?;
        // Connected: datagrams from any other address are never delivered.
        socket.connect(address).await?;
        socket.send(wire).await?;

        // One spare byte tells an oversized datagram from one that fits exactly.
        let mut buf = vec![0_u8; MAX_UDP_RESPONSE_LEN + 1];
        loop {
            // The caller's timeout bounds this loop.
            let len = socket.recv(&mut buf).await?;
            let Some(packet) = buf.get(..len).filter(|_| len <= MAX_UDP_RESPONSE_LEN) else {
                debug!(%address, "ignoring an oversized response");
                continue;
            };
            match self.codec.decode_response(packet) {
                Ok(response) if answers(&response, sent) => return Ok(response),
                Ok(_) => debug!(%address, "ignoring a response that does not match the query"),
                Err(err) => debug!(%address, %err, "ignoring a malformed response"),
            }
        }
    }

    async fn exchange_tcp(
        &self,
        address: SocketAddr,
        wire: &[u8],
        sent: &Query,
    ) -> Result<Response, ExchangeError> {
        let len = u16::try_from(wire.len()).map_err(|_| io::Error::other("query too large"))?;
        let mut frame = Vec::with_capacity(wire.len().saturating_add(2));
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(wire);

        let mut stream = TcpStream::connect(address).await?;
        stream.set_nodelay(true)?;
        stream.write_all(&frame).await?;
        let mut prefix = [0_u8; 2];
        stream.read_exact(&mut prefix).await?;
        let mut buf = vec![0_u8; usize::from(u16::from_be_bytes(prefix))];
        stream.read_exact(&mut buf).await?;
        let response = self.codec.decode_response(&buf)?;
        if answers(&response, sent) {
            Ok(response)
        } else {
            Err(ExchangeError::Mismatch)
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
        }),
    }
}

/// Whether `response` answers `sent`: same ID, a standard query, and the same
/// question in exactly the same case.
fn answers(response: &Response, sent: &Query) -> bool {
    response.id == sent.id
        && response.opcode == Opcode::QUERY
        && response
            .question
            .as_ref()
            .is_some_and(|question| question.matches_exactly(&sent.question))
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
    let sections = [
        &mut response.answers,
        &mut response.authority,
        &mut response.additional,
    ];
    for record in sections.into_iter().flatten() {
        if record.name() == &query.question.name {
            record.set_name(query.question.name.clone());
        }
    }
    response
}
