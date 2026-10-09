//! DNS listeners for goethite.
//!
//! Serves DNS over UDP and TCP (RFC 7766 length-prefixed framing) on one or
//! more addresses, with several `SO_REUSEPORT` UDP sockets per address on
//! Linux (see [`Listeners`]), and DNS over TLS (RFC 7858), DNS over HTTPS
//! (RFC 8484) and DNS over QUIC (RFC 9250) on addresses of their own. Every UDP query is resolved in its
//! own task, so a slow upstream never holds up other clients. Every limit is
//! explicit: datagram size, queries in flight, the UDP query rate per client
//! network, concurrent connections in total and per client, TLS handshake
//! time, how long a connection may sit idle, and how long shutdown waits
//! for queries in progress.
//!
//! Over TLS, HTTPS and QUIC a client can name itself with a client ID, in
//! the server name (`<id>.<server name>`) or the DNS over HTTPS path
//! (`/dns-query/<id>`); see [`doh`].

#![forbid(unsafe_code)]

mod bind;
pub mod doh;
pub mod doq;
mod https;
mod limits;
pub mod odoh;
mod quic;
mod stream;

use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use goethite_proto::{
    DnsCodec, HickoryCodec, MAX_UDP_PAYLOAD, MIN_UDP_PAYLOAD, Query, Response, ResponseCode,
};
use goethite_resolver::{Outcome, Resolution, Resolver};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, trace, warn};

pub use crate::bind::{Listeners, MAX_LISTEN_ADDRESSES, MAX_UDP_SOCKETS, default_udp_sockets};
use crate::limits::{ClientConnections, Decision, RateLimiter};
pub use crate::limits::{MAX_RATE_LIMIT_EXEMPTIONS, MAX_RATE_LIMITED_CLIENTS, RateLimitConfig};
use crate::stream::Kind;

/// The largest UDP query accepted; larger datagrams are dropped.
pub const MAX_UDP_QUERY_LEN: usize = 4096;

/// How long to pause accepting after an `accept` error such as running out
/// of file descriptors, instead of spinning.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// Listener settings.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Addresses to serve UDP and TCP on, at most [`MAX_LISTEN_ADDRESSES`].
    pub listen: Vec<SocketAddr>,
    /// UDP sockets per listen address on Linux, from 1 to
    /// [`MAX_UDP_SOCKETS`]; other platforms always use one.
    pub udp_sockets: usize,
    /// Most UDP queries being resolved at once, over all sockets; more are
    /// dropped, as an overloaded resolver should. Values above tokio's
    /// semaphore limit are clamped.
    pub max_inflight_udp_queries: usize,
    /// Rate limiting of UDP queries per client network.
    pub rate_limit: RateLimitConfig,
    /// Most TCP connections served at once, over all listeners (TCP, DNS
    /// over TLS and DNS over HTTPS); more are closed on accept. Values above
    /// tokio's semaphore limit (`usize::MAX >> 3`) are clamped.
    pub max_tcp_connections: usize,
    /// Most TCP connections served at once for one client (an IPv4 address
    /// or an IPv6 /64), over all listeners; more are closed on accept.
    pub max_tcp_connections_per_client: usize,
    /// How long a TCP connection may wait for, or take to send, a query.
    pub tcp_idle_timeout: Duration,
    /// Addresses to serve DNS over TLS on, usually port 853; at most
    /// [`MAX_LISTEN_ADDRESSES`]. Needs [`Server::with_tls`].
    pub dot: Vec<SocketAddr>,
    /// Addresses to serve DNS over HTTPS on, usually port 443; at most
    /// [`MAX_LISTEN_ADDRESSES`]. Needs [`Server::with_tls`].
    pub doh: Vec<SocketAddr>,
    /// Addresses to serve DNS over QUIC on, usually UDP port 853; at most
    /// [`MAX_LISTEN_ADDRESSES`]. Needs [`Server::with_tls`].
    pub doq: Vec<SocketAddr>,
    /// The name clients reach DNS over TLS and HTTPS by, such as
    /// `dns.example`: a server name one label below it, such as
    /// `anna-phone.dns.example`, carries a client ID. Without it, client IDs
    /// come from the DNS over HTTPS path only.
    pub server_name: Option<String>,
    /// How long a DNS over TLS, HTTPS or QUIC connection may go without a
    /// query.
    pub tls_idle_timeout: Duration,
    /// Whether DNS over TLS, HTTPS and QUIC answer only queries that carry
    /// a known client ID; others get `REFUSED`. For serving them beyond the
    /// local network. UDP and TCP are not affected.
    pub require_client_id: bool,
    /// Whether the DNS over HTTPS listeners are also an Oblivious DoH
    /// target (RFC 9230), with keys of their own ([`odoh::OdohKeys`]).
    pub odoh: bool,
    /// How long shutdown waits for queries in progress before abandoning them.
    pub shutdown_grace: Duration,
    /// Listen addresses that may not be on this host yet, such as a
    /// floating IP the peer holds: bound with `IP_FREEBIND` (Linux), and
    /// answered on once the address arrives. Other addresses must exist.
    pub freebind: Vec<IpAddr>,
}

impl ServerConfig {
    /// Settings for `listen` with default limits.
    pub fn new(listen: Vec<SocketAddr>) -> Self {
        Self {
            listen,
            udp_sockets: default_udp_sockets(),
            max_inflight_udp_queries: 2048,
            rate_limit: RateLimitConfig::default(),
            max_tcp_connections: 256,
            max_tcp_connections_per_client: 16,
            tcp_idle_timeout: Duration::from_secs(10),
            dot: Vec::new(),
            doh: Vec::new(),
            doq: Vec::new(),
            server_name: None,
            tls_idle_timeout: Duration::from_secs(30),
            require_client_id: false,
            odoh: false,
            shutdown_grace: Duration::from_secs(5),
            freebind: Vec::new(),
        }
    }
}

/// A DNS transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// DNS over UDP.
    Udp,
    /// DNS over TCP.
    Tcp,
    /// DNS over TLS (RFC 7858).
    Tls,
    /// DNS over HTTPS (RFC 8484).
    Https,
    /// DNS over QUIC (RFC 9250).
    Quic,
    /// Oblivious DNS over HTTPS (RFC 9230), through a proxy.
    Oblivious,
}

impl Transport {
    /// Every transport, in the order [`ByTransport`] counts them.
    pub const ALL: [Self; 6] = [
        Self::Udp,
        Self::Tcp,
        Self::Tls,
        Self::Https,
        Self::Quic,
        Self::Oblivious,
    ];

    fn index(self) -> usize {
        match self {
            Self::Udp => 0,
            Self::Tcp => 1,
            Self::Tls => 2,
            Self::Https => 3,
            Self::Quic => 4,
            Self::Oblivious => 5,
        }
    }

    /// Whether it is DNS over TLS, HTTPS or QUIC, or Oblivious DoH.
    pub fn is_encrypted(self) -> bool {
        matches!(self, Self::Tls | Self::Https | Self::Quic | Self::Oblivious)
    }

    /// Whether answers are padded with EDNS (RFC 7830) when the query was:
    /// over TLS, HTTPS and QUIC. Plain DNS is readable anyway, and Oblivious
    /// DoH pads in its own encryption layer (RFC 9230 6.2).
    pub fn pads(self) -> bool {
        matches!(self, Self::Tls | Self::Https | Self::Quic)
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Tls => "tls",
            Self::Https => "https",
            Self::Quic => "quic",
            Self::Oblivious => "odoh",
        })
    }
}

/// Errors that stop the server.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ServerError {
    /// A socket could not be bound.
    #[error("cannot bind {transport} socket on {addr}")]
    Bind {
        /// Which socket.
        transport: Transport,
        /// The address it was bound to.
        addr: SocketAddr,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// A listener stopped before shutdown was requested.
    #[error("a listener stopped unexpectedly")]
    ListenerStopped,
    /// No listen address was configured.
    #[error("no listen addresses configured")]
    NoListenAddresses,
    /// More than [`MAX_LISTEN_ADDRESSES`] listen addresses were configured.
    #[error("at most {MAX_LISTEN_ADDRESSES} listen addresses are supported, got {0}")]
    TooManyListenAddresses(usize),
    /// A bound socket could not be handed to the async runtime.
    #[error("cannot register a socket with the async runtime")]
    Register(#[source] io::Error),
    /// DNS over TLS, HTTPS or QUIC addresses are configured, but no
    /// certificate.
    #[error("DNS over TLS, HTTPS and QUIC need a certificate")]
    NoCertificate,
    /// The TLS settings cannot serve QUIC, which needs TLS 1.3.
    #[error("the TLS settings do not support DNS over QUIC (TLS 1.3)")]
    Quic,
    /// The Oblivious DoH keys cannot be made.
    #[error("cannot make Oblivious DoH keys: {0}")]
    Odoh(#[from] odoh::OdohError),
}

/// Receives every answered query, for the query log and statistics.
pub trait QueryObserver: Send + Sync {
    /// Called after a query was resolved, before the response is sent. It
    /// runs on the query's task, so it must not block or wait.
    fn observe(&self, event: &QueryEvent<'_>);
}

/// One answered query.
#[derive(Clone, Copy, Debug)]
pub struct QueryEvent<'a> {
    /// When the query arrived.
    pub time: SystemTime,
    /// Who sent it.
    pub peer: SocketAddr,
    /// How it arrived.
    pub transport: Transport,
    /// The query.
    pub query: &'a Query,
    /// The answer and how it came about.
    pub resolution: &'a Resolution,
    /// How long resolving took.
    pub elapsed: Duration,
}

/// A counter per transport.
#[derive(Debug, Default)]
pub struct ByTransport([AtomicU64; Transport::ALL.len()]);

impl ByTransport {
    /// The count for `transport`.
    pub fn get(&self, transport: Transport) -> u64 {
        self.0
            .get(transport.index())
            .map_or(0, |counter| counter.load(Ordering::Relaxed))
    }

    /// Adds one to the count for `transport`.
    pub fn count(&self, transport: Transport) {
        if let Some(counter) = self.0.get(transport.index()) {
            ServerStats::count(counter);
        }
    }
}

/// Counts of queries and connections the listeners turned away, for
/// metrics.
#[derive(Debug, Default)]
pub struct ServerStats {
    /// Queries over the rate limit: dropped over UDP (or answered with a
    /// truncated response), refused over the other transports.
    pub rate_limited: ByTransport,
    /// Queries and connections refused by the access lists: UDP queries
    /// dropped, TCP, DNS over TLS, HTTPS and QUIC connections closed before
    /// their handshake, and queries refused once a client ID showed the
    /// client may not use goethite.
    pub access_refused: ByTransport,
    /// Truncated answers sent to rate-limited clients.
    pub rate_limit_slips: AtomicU64,
    /// UDP queries dropped because too many were in flight.
    pub udp_overloaded: AtomicU64,
    /// UDP datagrams too large to be a query.
    pub udp_oversized: AtomicU64,
    /// TCP connections closed because all slots were taken.
    pub tcp_refused: AtomicU64,
    /// TCP connections closed because their client had too many.
    pub tcp_refused_per_client: AtomicU64,
    /// DNS over TLS, HTTPS and QUIC connections whose TLS handshake failed
    /// or took too long.
    pub tls_handshake_failures: AtomicU64,
    /// DNS over HTTPS requests answered with an HTTP error, such as a wrong
    /// path or a body that is not a DNS message.
    pub https_rejected: AtomicU64,
}

impl ServerStats {
    fn count(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// The sockets of one listen address, registered with tokio.
struct Address {
    udp: Vec<UdpSocket>,
    tcp: TcpListener,
}

/// Bound sockets, ready to serve.
pub struct Server {
    addresses: Vec<Address>,
    dot: Vec<TcpListener>,
    doh: Vec<TcpListener>,
    /// Registered with tokio once the TLS settings are known, in `run`.
    doq: Vec<std::net::UdpSocket>,
    tls: Option<Arc<rustls::ServerConfig>>,
    engine: Arc<Engine>,
    config: ServerConfig,
    stats: Arc<ServerStats>,
}

impl fmt::Debug for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
            .field("config", &self.config)
            .field("tls", &self.tls.is_some())
            .finish_non_exhaustive()
    }
}

impl Server {
    /// Binds the sockets for `config` (see [`Listeners::bind`]) and prepares
    /// to serve them. The resolver is shared, e.g. with the filter list
    /// updater.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Bind`] if a socket cannot be bound, or another
    /// [`ServerError`] for an unusable configuration.
    ///
    /// # Panics
    ///
    /// Outside a tokio runtime with I/O enabled, as tokio does.
    pub fn bind(config: ServerConfig, resolver: Arc<Resolver>) -> Result<Self, ServerError> {
        let listeners = Listeners::bind(&config)?;
        Self::new(listeners, config, resolver)
    }

    /// Prepares to serve sockets bound earlier, for example before the
    /// process dropped its privileges.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Register`] if a socket cannot be registered.
    ///
    /// # Panics
    ///
    /// Outside a tokio runtime with I/O enabled, as tokio does.
    pub fn new(
        listeners: Listeners,
        config: ServerConfig,
        resolver: Arc<Resolver>,
    ) -> Result<Self, ServerError> {
        let addresses = listeners
            .addresses
            .into_iter()
            .map(|bound| {
                Ok(Address {
                    udp: bound
                        .udp
                        .into_iter()
                        .map(UdpSocket::from_std)
                        .collect::<io::Result<_>>()?,
                    tcp: TcpListener::from_std(bound.tcp)?,
                })
            })
            .collect::<io::Result<_>>()
            .map_err(ServerError::Register)?;
        let register = |listeners: Vec<std::net::TcpListener>| {
            listeners
                .into_iter()
                .map(TcpListener::from_std)
                .collect::<io::Result<Vec<_>>>()
                .map_err(ServerError::Register)
        };
        let dot = register(listeners.dot)?;
        let doh = register(listeners.doh)?;
        let doq = listeners.doq;
        let stats = Arc::<ServerStats>::default();
        let engine = Arc::new(Engine {
            codec: Box::new(HickoryCodec),
            resolver,
            observer: None,
            require_client_id: config.require_client_id,
            rate_limiter: RateLimiter::new(&config.rate_limit),
            stats: Arc::clone(&stats),
        });
        Ok(Self {
            addresses,
            dot,
            doh,
            doq,
            tls: None,
            engine,
            config,
            stats,
        })
    }

    /// Serves DNS over TLS, HTTPS and QUIC with `tls`: its certificates,
    /// versions and session settings. Each listener sets its own ALPN
    /// protocols (`dot`; `h2` and `http/1.1`; `doq`).
    #[must_use]
    pub fn with_tls(mut self, tls: Arc<rustls::ServerConfig>) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Counts of what the listeners turned away.
    pub fn stats(&self) -> Arc<ServerStats> {
        Arc::clone(&self.stats)
    }

    /// Reports every answered query to `observer`.
    #[must_use]
    pub fn with_observer(mut self, observer: Arc<dyn QueryObserver>) -> Self {
        if let Some(engine) = Arc::get_mut(&mut self.engine) {
            engine.observer = Some(observer);
        }
        self
    }

    /// The address of each listen address's UDP sockets.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error if an address is unavailable.
    pub fn udp_local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.addresses
            .iter()
            .filter_map(|address| address.udp.first())
            .map(UdpSocket::local_addr)
            .collect()
    }

    /// The address of each TCP listener.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error if an address is unavailable.
    pub fn tcp_local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.addresses
            .iter()
            .map(|address| address.tcp.local_addr())
            .collect()
    }

    /// The address of each DNS over TLS listener.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error if an address is unavailable.
    pub fn dot_local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.dot.iter().map(TcpListener::local_addr).collect()
    }

    /// The address of each DNS over HTTPS listener.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error if an address is unavailable.
    pub fn doh_local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.doh.iter().map(TcpListener::local_addr).collect()
    }

    /// The address of each DNS over QUIC socket.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error if an address is unavailable.
    pub fn doq_local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.doq
            .iter()
            .map(std::net::UdpSocket::local_addr)
            .collect()
    }

    /// Serves until `shutdown` completes, then stops accepting new work,
    /// waits up to [`ServerConfig::shutdown_grace`] for queries in progress
    /// and returns.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::ListenerStopped`] if a listener ended before
    /// `shutdown` completed, [`ServerError::NoCertificate`] for DNS over
    /// TLS, HTTPS or QUIC listeners without [`Server::with_tls`], and
    /// [`ServerError::Quic`] or [`ServerError::Register`] if a DNS over QUIC
    /// endpoint cannot be set up.
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> Result<(), ServerError> {
        let config = &self.config;
        let encrypted = Encrypted::prepare(
            self.dot,
            self.doh,
            self.doq,
            self.tls.as_deref(),
            config.tls_idle_timeout,
        )?;
        // Keys only for a target that can be reached.
        let odoh = if config.odoh && encrypted.serves_https() {
            Some(Arc::new(odoh::OdohKeys::new()?))
        } else {
            None
        };
        let shared = Arc::new(Shared {
            engine: self.engine,
            odoh: odoh.clone(),
            udp_slots: Arc::new(Semaphore::new(
                config.max_inflight_udp_queries.min(Semaphore::MAX_PERMITS),
            )),
            // `Semaphore::new` panics above its limit, so a huge setting is clamped.
            tcp_slots: Arc::new(Semaphore::new(
                config.max_tcp_connections.min(Semaphore::MAX_PERMITS),
            )),
            tcp_clients: ClientConnections::new(config.max_tcp_connections_per_client),
            config: config.clone(),
            stats: self.stats,
        });
        if shared.engine.rate_limiter.is_none() {
            info!("rate limiting is turned off");
        }

        let (stop_tx, stop_rx) = watch::channel(false);
        let mut listeners = JoinSet::new();
        for address in self.addresses {
            info!(
                udp = %DisplayAddr(address.udp.first().map_or_else(
                    || Err(io::ErrorKind::NotFound.into()),
                    UdpSocket::local_addr,
                )),
                udp_sockets = address.udp.len(),
                tcp = %DisplayAddr(address.tcp.local_addr()),
                "listening"
            );
            for socket in address.udp {
                listeners.spawn(serve_udp(socket, Arc::clone(&shared), stop_rx.clone()));
            }
            listeners.spawn(stream::serve(
                address.tcp,
                Kind::Tcp,
                Arc::clone(&shared),
                stop_rx.clone(),
            ));
        }
        encrypted.spawn(&shared, &stop_rx, &mut listeners);
        if let Some(keys) = odoh {
            info!("Oblivious DoH target on the DNS over HTTPS listeners");
            listeners.spawn(rotate_odoh_keys(keys, stop_rx.clone()));
        }
        drop(stop_rx);

        let stopped_early = tokio::select! {
            () = shutdown => {
                info!("shutting down");
                false
            }
            joined = listeners.join_next() => {
                if let Some(Err(err)) = joined {
                    error!(%err, "a listener failed, shutting down");
                } else {
                    error!("a listener stopped unexpectedly, shutting down");
                }
                true
            }
        };
        stop_tx.send_replace(true);
        while let Some(joined) = listeners.join_next().await {
            if let Err(err) = joined {
                error!(%err, "listener task failed");
            }
        }
        info!("stopped");

        if stopped_early {
            Err(ServerError::ListenerStopped)
        } else {
            Ok(())
        }
    }
}

/// The DNS over TLS, HTTPS and QUIC listeners, ready to serve.
struct Encrypted {
    streams: Vec<(TcpListener, Kind, &'static str)>,
    quic: Vec<quinn::Endpoint>,
}

impl Encrypted {
    /// Sets the listeners up with `tls`, each with its ALPN protocols.
    fn prepare(
        dot: Vec<TcpListener>,
        doh: Vec<TcpListener>,
        doq: Vec<std::net::UdpSocket>,
        tls: Option<&rustls::ServerConfig>,
        idle: Duration,
    ) -> Result<Self, ServerError> {
        if dot.is_empty() && doh.is_empty() && doq.is_empty() {
            return Ok(Self {
                streams: Vec::new(),
                quic: Vec::new(),
            });
        }
        let tls = tls.ok_or(ServerError::NoCertificate)?;
        let acceptor = |alpn: &[&[u8]]| {
            let mut tls = tls.clone();
            tls.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
            TlsAcceptor::from(Arc::new(tls))
        };
        let over_tls = Kind::Tls(acceptor(&[b"dot"]));
        let over_https = Kind::Https(acceptor(&[b"h2", b"http/1.1"]));
        let streams = dot
            .into_iter()
            .map(|listener| (listener, over_tls.clone(), "DNS over TLS"))
            .chain(
                doh.into_iter()
                    .map(|listener| (listener, over_https.clone(), "DNS over HTTPS")),
            )
            .collect();
        let quic = doq
            .into_iter()
            .map(|socket| quic::endpoint(socket, tls, idle))
            .collect::<Result<_, _>>()?;
        Ok(Self { streams, quic })
    }

    /// Whether there are DNS over HTTPS listeners.
    fn serves_https(&self) -> bool {
        self.streams
            .iter()
            .any(|(_, kind, _)| matches!(kind, Kind::Https(_)))
    }

    /// Serves every listener in `listeners`.
    fn spawn(
        self,
        shared: &Arc<Shared>,
        stop: &watch::Receiver<bool>,
        listeners: &mut JoinSet<()>,
    ) {
        for (listener, kind, name) in self.streams {
            info!(address = %DisplayAddr(listener.local_addr()), "{name} listening");
            listeners.spawn(stream::serve(
                listener,
                kind,
                Arc::clone(shared),
                stop.clone(),
            ));
        }
        for endpoint in self.quic {
            info!(address = %DisplayAddr(endpoint.local_addr()), "DNS over QUIC listening");
            listeners.spawn(quic::serve(endpoint, Arc::clone(shared), stop.clone()));
        }
    }
}

/// Formats a `local_addr()` result for a log line.
struct DisplayAddr(io::Result<SocketAddr>);

impl fmt::Display for DisplayAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Ok(addr) => addr.fmt(f),
            Err(err) => write!(f, "<unknown: {err}>"),
        }
    }
}

/// Completes once shutdown has been requested (or the sender is gone).
async fn stopped(stop: &mut watch::Receiver<bool>) {
    // Discard the borrowed value so no lock guard outlives this call.
    let _ = stop.wait_for(|stop| *stop).await;
}

/// State shared by every listener.
struct Shared {
    engine: Arc<Engine>,
    /// The Oblivious DoH keys, if the HTTPS listeners are a target.
    odoh: Option<Arc<odoh::OdohKeys>>,
    config: ServerConfig,
    udp_slots: Arc<Semaphore>,
    tcp_slots: Arc<Semaphore>,
    tcp_clients: Arc<ClientConnections>,
    stats: Arc<ServerStats>,
}

/// Decodes, resolves and encodes; shared by every listener.
struct Engine {
    codec: Box<dyn DnsCodec>,
    resolver: Arc<Resolver>,
    observer: Option<Arc<dyn QueryObserver>>,
    /// See [`ServerConfig::require_client_id`].
    require_client_id: bool,
    /// One limiter for every transport, so a client's queries count
    /// together; `None` when rate limiting is off.
    rate_limiter: Option<RateLimiter>,
    stats: Arc<ServerStats>,
}

/// A response [`Engine::answer`] encoded.
#[derive(Clone, Copy, Debug)]
struct Answered {
    /// The shortest time to live of its records, if it has any.
    min_ttl: Option<u32>,
}

impl Engine {
    /// Answers the message in `wire` from `peer`, which named itself
    /// `client_id` (if it did), encoding the response into `out`.
    ///
    /// Returns `None` if nothing must be sent (the message was dropped).
    async fn answer(
        &self,
        wire: &[u8],
        transport: Transport,
        peer: SocketAddr,
        client_id: Option<&str>,
        out: &mut Vec<u8>,
    ) -> Option<Answered> {
        let (response, udp_limit) = match self.codec.decode_query(wire) {
            // Over the rate limit: refused, and not logged, so a flood does
            // not fill the query log.
            Ok(query) if self.over_rate_limit(transport, peer) => (
                Response::for_query(&query, ResponseCode::REFUSED),
                query.max_udp_response_len(),
            ),
            Ok(query) => {
                let time = SystemTime::now();
                let start = Instant::now();
                let admitted = self.resolver.admits(peer.ip(), client_id);
                if !admitted {
                    self.stats.access_refused.count(transport);
                }
                let resolution = if !admitted || self.refuses(transport, client_id) {
                    Resolution {
                        response: Response::for_query(&query, ResponseCode::REFUSED),
                        outcome: Outcome::Rejected,
                        filter: None,
                        client: None,
                        group: None,
                        filtering: false,
                    }
                } else {
                    self.resolver
                        .resolve_with_id(&query, peer.ip(), client_id)
                        .await
                };
                trace!(
                    %peer,
                    %transport,
                    id = query.id,
                    name = %query.question.name,
                    qtype = %query.question.qtype,
                    rcode = %resolution.response.rcode,
                    "answered query"
                );
                if let Some(observer) = &self.observer {
                    observer.observe(&QueryEvent {
                        time,
                        peer,
                        transport,
                        query: &query,
                        resolution: &resolution,
                        elapsed: start.elapsed(),
                    });
                }
                let mut response = resolution.response;
                if transport.pads() && query.edns.is_some_and(|edns| edns.padding) {
                    // RFC 7830 4: a padded query gets a padded answer.
                    if let Some(edns) = response.edns.as_mut() {
                        edns.padding = true;
                    }
                }
                (response, query.max_udp_response_len())
            }
            Err(err) => {
                let Some(response) = err.response() else {
                    debug!(%peer, %transport, len = wire.len(), %err, "dropped message");
                    return None;
                };
                debug!(%peer, %transport, %err, rcode = %response.rcode, "rejected query");
                (response, usize::from(MIN_UDP_PAYLOAD))
            }
        };

        let max_len = match transport {
            Transport::Udp => udp_limit,
            Transport::Tcp | Transport::Tls | Transport::Https | Transport::Quic => {
                usize::from(u16::MAX)
            }
            Transport::Oblivious => odoh::MAX_RESPONSE_LEN,
        };
        let min_ttl = response
            .answers
            .iter()
            .chain(&response.authority)
            .map(goethite_proto::Record::ttl)
            .min();
        match self.codec.encode_response(&response, max_len, out) {
            Ok(()) => Some(Answered { min_ttl }),
            Err(err) => {
                warn!(%peer, %transport, %err, "cannot encode response");
                None
            }
        }
    }

    /// Whether a query from `peer` over `transport` is over the rate limit,
    /// which counts it. UDP queries are checked before they are decoded, in
    /// [`serve_udp`], and Oblivious DoH queries come from a proxy, so only
    /// the other transports are checked here.
    fn over_rate_limit(&self, transport: Transport, peer: SocketAddr) -> bool {
        if matches!(transport, Transport::Udp | Transport::Oblivious) {
            return false;
        }
        let Some(limiter) = &self.rate_limiter else {
            return false;
        };
        let (Decision::Limited { first, .. }, network) = limiter.check(peer.ip(), Instant::now())
        else {
            return false;
        };
        if first {
            debug!(%peer, %network, %transport, "client is over the rate limit");
        }
        self.stats.rate_limited.count(transport);
        true
    }

    /// Whether a query must be refused for lack of a known client ID.
    fn refuses(&self, transport: Transport, client_id: Option<&str>) -> bool {
        transport.is_encrypted()
            && self.require_client_id
            && !client_id.is_some_and(|id| self.resolver.knows_client_id(id))
    }

    /// Encodes an empty, truncated response to the query in `wire` into
    /// `out`, telling a rate-limited client to retry over TCP. It is no
    /// bigger than the query. Returns `false` if the query cannot be decoded.
    fn truncated(&self, wire: &[u8], out: &mut Vec<u8>) -> bool {
        let Ok(query) = self.codec.decode_query(wire) else {
            return false;
        };
        let mut response = Response::for_query(&query, ResponseCode::NO_ERROR);
        response.truncated = true;
        self.codec
            .encode_response(&response, usize::from(MIN_UDP_PAYLOAD), out)
            .is_ok()
    }
}

/// Replaces the Oblivious DoH keys every [`odoh::ROTATION`] until `stop`.
async fn rotate_odoh_keys(keys: Arc<odoh::OdohKeys>, mut stop: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            () = tokio::time::sleep(odoh::ROTATION) => {
                match keys.rotate() {
                    Ok(()) => info!("new Oblivious DoH key"),
                    Err(err) => error!(%err, "cannot rotate the Oblivious DoH key; keeping the current one"),
                }
            }
            () = stopped(&mut stop) => return,
        }
    }
}

async fn serve_udp(socket: UdpSocket, shared: Arc<Shared>, mut stop: watch::Receiver<bool>) {
    let socket = Arc::new(socket);
    let mut inflight = JoinSet::new();
    let mut slip = Vec::with_capacity(usize::from(MIN_UDP_PAYLOAD));
    // One spare byte tells an oversized datagram from one that fits exactly.
    let mut buf = vec![0_u8; MAX_UDP_QUERY_LEN + 1];
    loop {
        let (len, peer) = tokio::select! {
            biased;
            () = stopped(&mut stop) => break,
            Some(joined) = inflight.join_next(), if !inflight.is_empty() => {
                if let Err(err) = joined {
                    error!(%err, "udp query task failed");
                }
                continue;
            }
            received = socket.recv_from(&mut buf) => match received {
                Ok(received) => received,
                Err(err) => {
                    debug!(%err, "udp receive failed");
                    continue;
                }
            },
        };
        let Some(wire) = buf.get(..len).filter(|_| len <= MAX_UDP_QUERY_LEN) else {
            debug!(%peer, "dropped oversized udp datagram");
            ServerStats::count(&shared.stats.udp_oversized);
            continue;
        };
        // Dropped without an answer, so a forged source address gets nothing.
        if !shared.engine.resolver.admits(peer.ip(), None) {
            trace!(%peer, "access lists refuse the client, dropping");
            shared.stats.access_refused.count(Transport::Udp);
            continue;
        }
        if let Some(limiter) = &shared.engine.rate_limiter
            && let (Decision::Limited { slip: send, first }, network) =
                limiter.check(peer.ip(), Instant::now())
        {
            if first {
                debug!(%peer, %network, "client is over the udp rate limit");
            }
            shared.stats.rate_limited.count(Transport::Udp);
            slip.clear();
            // Sent without waiting: if the socket is busy, dropping is fine.
            if send && shared.engine.truncated(wire, &mut slip) {
                let _ = socket.try_send_to(&slip, peer);
                ServerStats::count(&shared.stats.rate_limit_slips);
            }
            continue;
        }
        let Ok(permit) = Arc::clone(&shared.udp_slots).try_acquire_owned() else {
            debug!(%peer, "too many udp queries in flight, dropping");
            ServerStats::count(&shared.stats.udp_overloaded);
            continue;
        };
        let wire = wire.to_vec();
        let socket = Arc::clone(&socket);
        let engine = Arc::clone(&shared.engine);
        inflight.spawn(async move {
            let _permit = permit;
            let mut out = Vec::with_capacity(usize::from(MAX_UDP_PAYLOAD));
            if engine
                .answer(&wire, Transport::Udp, peer, None, &mut out)
                .await
                .is_some()
                && let Err(err) = socket.send_to(&out, peer).await
            {
                debug!(%peer, %err, "udp send failed");
            }
        });
    }
    drain("udp queries", inflight, shared.config.shutdown_grace).await;
}

/// Waits up to `grace` for `tasks` to finish, then aborts the rest.
async fn drain(what: &str, mut tasks: JoinSet<()>, grace: Duration) {
    let finish = async { while tasks.join_next().await.is_some() {} };
    if timeout(grace, finish).await.is_err() {
        debug!(
            remaining = tasks.len(),
            "abandoning {what} after the grace period"
        );
        tasks.shutdown().await;
    }
}
