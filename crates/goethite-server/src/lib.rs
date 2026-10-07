//! DNS listeners for goethite.
//!
//! Serves DNS over UDP and TCP (RFC 7766 length-prefixed framing) on one or
//! more addresses, with several `SO_REUSEPORT` UDP sockets per address on
//! Linux (see [`Listeners`]). Every UDP query is resolved in its own task, so
//! a slow upstream never holds up other clients. Every limit is explicit:
//! datagram size, queries in flight, the UDP query rate per client network,
//! concurrent TCP connections in total and per client, how long a TCP
//! connection may sit idle, and how long shutdown waits for queries in
//! progress. Later phases add DoT, DoH and DoQ listeners.

mod bind;
mod limits;

use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use goethite_proto::{
    DnsCodec, HickoryCodec, MAX_UDP_PAYLOAD, MIN_UDP_PAYLOAD, Query, Response, ResponseCode,
};
use goethite_resolver::{Resolution, Resolver};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, error, info, trace, warn};

pub use crate::bind::{Listeners, MAX_LISTEN_ADDRESSES, MAX_UDP_SOCKETS, default_udp_sockets};
use crate::limits::{ClientConnections, ClientSlot, Decision, RateLimiter};
pub use crate::limits::{MAX_RATE_LIMITED_CLIENTS, RateLimitConfig};

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
    /// Most TCP connections served at once, over all listeners; more are
    /// closed on accept. Values above tokio's semaphore limit
    /// (`usize::MAX >> 3`) are clamped.
    pub max_tcp_connections: usize,
    /// Most TCP connections served at once for one client (an IPv4 address
    /// or an IPv6 /64); more are closed on accept.
    pub max_tcp_connections_per_client: usize,
    /// How long a TCP connection may wait for, or take to send, a query.
    pub tcp_idle_timeout: Duration,
    /// How long shutdown waits for queries in progress before abandoning them.
    pub shutdown_grace: Duration,
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
            shutdown_grace: Duration::from_secs(5),
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
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
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

/// The sockets of one listen address, registered with tokio.
struct Address {
    udp: Vec<UdpSocket>,
    tcp: TcpListener,
}

/// Bound UDP and TCP sockets, ready to serve.
pub struct Server {
    addresses: Vec<Address>,
    engine: Arc<Engine>,
    config: ServerConfig,
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
        let engine = Arc::new(Engine {
            codec: Box::new(HickoryCodec),
            resolver,
            observer: None,
        });
        Ok(Self {
            addresses,
            engine,
            config,
        })
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

    /// Serves until `shutdown` completes, then stops accepting new work,
    /// waits up to [`ServerConfig::shutdown_grace`] for queries in progress
    /// and returns.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::ListenerStopped`] if a listener ended before
    /// `shutdown` completed.
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> Result<(), ServerError> {
        let config = &self.config;
        let shared = Arc::new(Shared {
            engine: self.engine,
            udp_slots: Arc::new(Semaphore::new(
                config.max_inflight_udp_queries.min(Semaphore::MAX_PERMITS),
            )),
            rate_limiter: RateLimiter::new(&config.rate_limit),
            // `Semaphore::new` panics above its limit, so a huge setting is clamped.
            tcp_slots: Arc::new(Semaphore::new(
                config.max_tcp_connections.min(Semaphore::MAX_PERMITS),
            )),
            tcp_clients: ClientConnections::new(config.max_tcp_connections_per_client),
            config: config.clone(),
        });
        if shared.rate_limiter.is_none() {
            info!("udp rate limiting is turned off");
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
            listeners.spawn(serve_tcp(address.tcp, Arc::clone(&shared), stop_rx.clone()));
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
    config: ServerConfig,
    udp_slots: Arc<Semaphore>,
    rate_limiter: Option<RateLimiter>,
    tcp_slots: Arc<Semaphore>,
    tcp_clients: Arc<ClientConnections>,
}

/// Decodes, resolves and encodes; shared by every listener.
struct Engine {
    codec: Box<dyn DnsCodec>,
    resolver: Arc<Resolver>,
    observer: Option<Arc<dyn QueryObserver>>,
}

impl Engine {
    /// Answers the message in `wire`, encoding the response into `out`.
    ///
    /// Returns `false` if nothing must be sent (the message was dropped).
    async fn answer(
        &self,
        wire: &[u8],
        transport: Transport,
        peer: SocketAddr,
        out: &mut Vec<u8>,
    ) -> bool {
        let (response, udp_limit) = match self.codec.decode_query(wire) {
            Ok(query) => {
                let time = SystemTime::now();
                let start = Instant::now();
                let resolution = self.resolver.resolve(&query, peer.ip()).await;
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
                (resolution.response, query.max_udp_response_len())
            }
            Err(err) => {
                let Some(response) = err.response() else {
                    debug!(%peer, %transport, len = wire.len(), %err, "dropped message");
                    return false;
                };
                debug!(%peer, %transport, %err, rcode = %response.rcode, "rejected query");
                (response, usize::from(MIN_UDP_PAYLOAD))
            }
        };

        let max_len = match transport {
            Transport::Udp => udp_limit,
            Transport::Tcp => usize::from(u16::MAX),
        };
        match self.codec.encode_response(&response, max_len, out) {
            Ok(()) => true,
            Err(err) => {
                warn!(%peer, %transport, %err, "cannot encode response");
                false
            }
        }
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
            continue;
        };
        if let Some(limiter) = &shared.rate_limiter
            && let (Decision::Limited { slip: send, first }, network) =
                limiter.check(peer.ip(), Instant::now())
        {
            if first {
                debug!(%peer, %network, "client is over the udp rate limit");
            }
            slip.clear();
            // Sent without waiting: if the socket is busy, dropping is fine.
            if send && shared.engine.truncated(wire, &mut slip) {
                let _ = socket.try_send_to(&slip, peer);
            }
            continue;
        }
        let Ok(permit) = Arc::clone(&shared.udp_slots).try_acquire_owned() else {
            debug!(%peer, "too many udp queries in flight, dropping");
            continue;
        };
        let wire = wire.to_vec();
        let socket = Arc::clone(&socket);
        let engine = Arc::clone(&shared.engine);
        inflight.spawn(async move {
            let _permit = permit;
            let mut out = Vec::with_capacity(usize::from(MAX_UDP_PAYLOAD));
            if engine.answer(&wire, Transport::Udp, peer, &mut out).await
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

async fn serve_tcp(listener: TcpListener, shared: Arc<Shared>, mut stop: watch::Receiver<bool>) {
    let mut connections = JoinSet::new();
    let connection_stop = stop.clone();
    loop {
        tokio::select! {
            biased;
            () = stopped(&mut stop) => break,
            Some(joined) = connections.join_next(), if !connections.is_empty() => {
                if let Err(err) = joined {
                    error!(%err, "tcp connection task failed");
                }
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        debug!(%err, "tcp accept failed");
                        tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                        continue;
                    }
                };
                let Ok(permit) = Arc::clone(&shared.tcp_slots).try_acquire_owned() else {
                    debug!(%peer, "tcp connection limit reached, closing connection");
                    continue;
                };
                let Some(client) = shared.tcp_clients.try_acquire(peer.ip()) else {
                    debug!(%peer, "per-client tcp connection limit reached, closing connection");
                    continue;
                };
                connections.spawn(serve_tcp_connection(
                    stream,
                    peer,
                    Arc::clone(&shared.engine),
                    shared.config.tcp_idle_timeout,
                    connection_stop.clone(),
                    (permit, client),
                ));
            }
        }
    }

    drop(listener);
    drain("tcp connections", connections, shared.config.shutdown_grace).await;
}

async fn serve_tcp_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    engine: Arc<Engine>,
    idle_timeout: Duration,
    mut stop: watch::Receiver<bool>,
    _slots: (OwnedSemaphorePermit, ClientSlot),
) {
    if let Err(err) = stream.set_nodelay(true) {
        debug!(%peer, %err, "cannot disable Nagle's algorithm");
    }
    let mut prefix = [0_u8; 2];
    let mut query = Vec::new();
    let mut response = Vec::new();
    let mut frame = Vec::new();
    loop {
        // Between queries: stop on shutdown, idle timeout or end of stream.
        let read = tokio::select! {
            biased;
            () = stopped(&mut stop) => break,
            read = timeout(idle_timeout, stream.read_exact(&mut prefix)) => read,
        };
        match read {
            Ok(Ok(_)) => {}
            Ok(Err(err)) => {
                if err.kind() != io::ErrorKind::UnexpectedEof {
                    debug!(%peer, %err, "tcp read failed");
                }
                break;
            }
            Err(_) => {
                trace!(%peer, "closing idle tcp connection");
                break;
            }
        }

        // The length prefix bounds the message to 65,535 bytes.
        query.resize(usize::from(u16::from_be_bytes(prefix)), 0);
        match timeout(idle_timeout, stream.read_exact(&mut query)).await {
            Ok(Ok(_)) => {}
            Ok(Err(err)) => {
                debug!(%peer, %err, "tcp read failed");
                break;
            }
            Err(_) => {
                debug!(%peer, "tcp query not received in time");
                break;
            }
        }

        // A dropped message means the peer is not speaking DNS: hang up.
        if !engine
            .answer(&query, Transport::Tcp, peer, &mut response)
            .await
        {
            break;
        }
        let Ok(len) = u16::try_from(response.len()) else {
            break;
        };
        frame.clear();
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&response);
        match timeout(idle_timeout, stream.write_all(&frame)).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                debug!(%peer, %err, "tcp write failed");
                break;
            }
            Err(_) => {
                debug!(%peer, "tcp response not sent in time");
                break;
            }
        }
    }
}
