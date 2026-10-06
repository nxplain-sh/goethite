//! DNS listeners for goethite.
//!
//! Serves DNS over UDP and TCP (RFC 7766 length-prefixed framing) on one
//! address. Every limit is explicit: datagram size, concurrent TCP
//! connections, how long a TCP connection may sit idle, and how long shutdown
//! waits for in-flight TCP queries. Later phases add DoT, DoH and DoQ, and
//! per-core `SO_REUSEPORT` sockets.

use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use goethite_proto::{DnsCodec, HickoryCodec, MAX_UDP_PAYLOAD, MIN_UDP_PAYLOAD};
use goethite_resolver::Resolver;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, error, info, trace, warn};

/// The largest UDP query accepted; larger datagrams are dropped.
pub const MAX_UDP_QUERY_LEN: usize = 4096;

/// How long to pause accepting after an `accept` error such as running out
/// of file descriptors, instead of spinning.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// Listener settings.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Address for both the UDP socket and the TCP listener.
    pub listen: SocketAddr,
    /// Most TCP connections served at once; more are closed on accept.
    pub max_tcp_connections: usize,
    /// How long a TCP connection may wait for, or take to send, a query.
    pub tcp_idle_timeout: Duration,
    /// How long shutdown waits for in-flight TCP queries before closing them.
    pub shutdown_grace: Duration,
}

impl ServerConfig {
    /// Settings for `listen` with default limits.
    pub fn new(listen: SocketAddr) -> Self {
        Self {
            listen,
            max_tcp_connections: 256,
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
}

/// Bound UDP and TCP sockets, ready to serve.
pub struct Server {
    udp: UdpSocket,
    tcp: TcpListener,
    engine: Arc<Engine>,
    config: ServerConfig,
}

impl Server {
    /// Binds the UDP socket and TCP listener on `config.listen`.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Bind`] if either socket cannot be bound.
    pub async fn bind(config: ServerConfig, resolver: Resolver) -> Result<Self, ServerError> {
        let addr = config.listen;
        let udp = UdpSocket::bind(addr)
            .await
            .map_err(|source| ServerError::Bind {
                transport: Transport::Udp,
                addr,
                source,
            })?;
        let tcp = TcpListener::bind(addr)
            .await
            .map_err(|source| ServerError::Bind {
                transport: Transport::Tcp,
                addr,
                source,
            })?;
        let engine = Arc::new(Engine {
            codec: Box::new(HickoryCodec),
            resolver,
        });
        Ok(Self {
            udp,
            tcp,
            engine,
            config,
        })
    }

    /// The address the UDP socket is bound to.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error if the address is unavailable.
    pub fn udp_local_addr(&self) -> io::Result<SocketAddr> {
        self.udp.local_addr()
    }

    /// The address the TCP listener is bound to.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error if the address is unavailable.
    pub fn tcp_local_addr(&self) -> io::Result<SocketAddr> {
        self.tcp.local_addr()
    }

    /// Serves until `shutdown` completes, then stops accepting new work,
    /// waits up to [`ServerConfig::shutdown_grace`] for in-flight TCP queries
    /// and returns.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::ListenerStopped`] if a listener ended before
    /// `shutdown` completed.
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> Result<(), ServerError> {
        info!(
            udp = %DisplayAddr(self.udp.local_addr()),
            tcp = %DisplayAddr(self.tcp.local_addr()),
            "listening"
        );

        let (stop_tx, stop_rx) = watch::channel(false);
        let mut listeners = JoinSet::new();
        listeners.spawn(serve_udp(
            self.udp,
            Arc::clone(&self.engine),
            stop_rx.clone(),
        ));
        listeners.spawn(serve_tcp(self.tcp, self.engine, self.config, stop_rx));

        let stopped_early = tokio::select! {
            () = shutdown => {
                info!("shutting down");
                false
            }
            _ = listeners.join_next() => {
                error!("a listener stopped unexpectedly, shutting down");
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

/// Decodes, resolves and encodes; shared by every listener.
struct Engine {
    codec: Box<dyn DnsCodec>,
    resolver: Resolver,
}

impl Engine {
    /// Answers the message in `wire`, encoding the response into `out`.
    ///
    /// Returns `false` if nothing must be sent (the message was dropped).
    fn answer(
        &self,
        wire: &[u8],
        transport: Transport,
        peer: SocketAddr,
        out: &mut Vec<u8>,
    ) -> bool {
        let (response, udp_limit) = match self.codec.decode_query(wire) {
            Ok(query) => {
                let response = self.resolver.resolve(&query);
                trace!(
                    %peer,
                    %transport,
                    id = query.id,
                    name = %query.question.name,
                    qtype = %query.question.qtype,
                    rcode = %response.rcode,
                    "answered query"
                );
                (response, query.max_udp_response_len())
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
}

async fn serve_udp(socket: UdpSocket, engine: Arc<Engine>, mut stop: watch::Receiver<bool>) {
    // One spare byte tells an oversized datagram from one that fits exactly.
    let mut buf = vec![0_u8; MAX_UDP_QUERY_LEN + 1];
    let mut out = Vec::with_capacity(usize::from(MAX_UDP_PAYLOAD));
    loop {
        let (len, peer) = tokio::select! {
            biased;
            () = stopped(&mut stop) => break,
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
        if engine.answer(wire, Transport::Udp, peer, &mut out)
            && let Err(err) = socket.send_to(&out, peer).await
        {
            debug!(%peer, %err, "udp send failed");
        }
    }
}

async fn serve_tcp(
    listener: TcpListener,
    engine: Arc<Engine>,
    config: ServerConfig,
    mut stop: watch::Receiver<bool>,
) {
    let slots = Arc::new(Semaphore::new(config.max_tcp_connections));
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
                let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                    debug!(%peer, "tcp connection limit reached, closing connection");
                    continue;
                };
                connections.spawn(serve_tcp_connection(
                    stream,
                    peer,
                    Arc::clone(&engine),
                    config.tcp_idle_timeout,
                    connection_stop.clone(),
                    permit,
                ));
            }
        }
    }

    drop(listener);
    let drain = async { while connections.join_next().await.is_some() {} };
    if timeout(config.shutdown_grace, drain).await.is_err() {
        debug!(
            remaining = connections.len(),
            "closing tcp connections after the grace period"
        );
        connections.shutdown().await;
    }
}

async fn serve_tcp_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    engine: Arc<Engine>,
    idle_timeout: Duration,
    mut stop: watch::Receiver<bool>,
    _permit: OwnedSemaphorePermit,
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
        if !engine.answer(&query, Transport::Tcp, peer, &mut response) {
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
