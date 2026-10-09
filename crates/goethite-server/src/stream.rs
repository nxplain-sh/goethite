//! Connection-oriented listeners: DNS over TCP, DNS over TLS and DNS over
//! HTTPS.
//!
//! All three share the connection limits: [`crate::ServerConfig::max_tcp_connections`]
//! in total and [`crate::ServerConfig::max_tcp_connections_per_client`] per
//! client count every TCP connection, encrypted or not. TLS handshakes are
//! bounded in time, and so is every read and write. A client the access
//! lists refuse is closed on accept, before it takes a slot or a handshake;
//! one that may still be allowed by its client ID is decided per query.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use goethite_proto::MIN_UDP_PAYLOAD;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, watch};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tracing::{debug, error, trace};

use crate::limits::ClientSlot;
use crate::{
    ACCEPT_ERROR_BACKOFF, Engine, ServerStats, Shared, Transport, doh, drain, https, stopped,
};

/// How long a TLS handshake may take.
pub(crate) const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long closing a TLS connection cleanly may take.
const TLS_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

/// What a stream listener serves.
#[derive(Clone)]
pub(crate) enum Kind {
    /// DNS over TCP.
    Tcp,
    /// DNS over TLS.
    Tls(TlsAcceptor),
    /// DNS over HTTPS.
    Https(TlsAcceptor),
}

impl Kind {
    fn transport(&self) -> Transport {
        match self {
            Self::Tcp => Transport::Tcp,
            Self::Tls(_) => Transport::Tls,
            Self::Https(_) => Transport::Https,
        }
    }
}

/// The slots a connection holds while it is served.
pub(crate) type Slots = (OwnedSemaphorePermit, ClientSlot);

/// Accepts connections on `listener` until shutdown, serving each in its
/// own task.
pub(crate) async fn serve(
    listener: TcpListener,
    kind: Kind,
    shared: Arc<Shared>,
    mut stop: watch::Receiver<bool>,
) {
    let transport = kind.transport();
    let mut connections = JoinSet::new();
    let connection_stop = stop.clone();
    loop {
        tokio::select! {
            biased;
            () = stopped(&mut stop) => break,
            Some(joined) = connections.join_next(), if !connections.is_empty() => {
                if let Err(err) = joined {
                    error!(%err, %transport, "connection task failed");
                }
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        debug!(%err, %transport, "accept failed");
                        tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                        continue;
                    }
                };
                if !admits(&kind, peer, &shared) {
                    trace!(%peer, %transport, "access lists refuse the client, closing connection");
                    shared.stats.access_refused.count(transport);
                    continue;
                }
                let Ok(permit) = Arc::clone(&shared.tcp_slots).try_acquire_owned() else {
                    debug!(%peer, %transport, "connection limit reached, closing connection");
                    ServerStats::count(&shared.stats.tcp_refused);
                    continue;
                };
                let Some(client) = shared.tcp_clients.try_acquire(peer.ip()) else {
                    debug!(%peer, %transport, "per-client connection limit reached, closing connection");
                    ServerStats::count(&shared.stats.tcp_refused_per_client);
                    continue;
                };
                if let Err(err) = stream.set_nodelay(true) {
                    debug!(%peer, %err, "cannot disable Nagle's algorithm");
                }
                connections.spawn(connection(
                    stream,
                    peer,
                    kind.clone(),
                    Arc::clone(&shared),
                    connection_stop.clone(),
                    (permit, client),
                ));
            }
        }
    }

    drop(listener);
    drain(
        &format!("{transport} connections"),
        connections,
        shared.config.shutdown_grace,
    )
    .await;
}

/// Whether the access lists let a connection from `peer` in: over TCP the
/// address decides; over TLS and HTTPS, a client ID may still allow it.
fn admits(kind: &Kind, peer: SocketAddr, shared: &Shared) -> bool {
    let resolver = &shared.engine.resolver;
    match kind {
        Kind::Tcp => resolver.admits(peer.ip(), None),
        Kind::Tls(_) | Kind::Https(_) => resolver.may_admit(peer.ip()),
    }
}

/// Serves one accepted connection.
async fn connection(
    stream: TcpStream,
    peer: SocketAddr,
    kind: Kind,
    shared: Arc<Shared>,
    stop: watch::Receiver<bool>,
    slots: Slots,
) {
    let config = &shared.config;
    match kind {
        Kind::Tcp => {
            let mut stream = stream;
            let served = Served {
                engine: &shared.engine,
                transport: Transport::Tcp,
                peer,
                client_id: None,
                idle_timeout: config.tcp_idle_timeout,
            };
            serve_messages(&mut stream, &served, stop).await;
        }
        Kind::Tls(acceptor) => {
            let Some((mut stream, client_id)) = handshake(&acceptor, stream, peer, &shared).await
            else {
                return;
            };
            let served = Served {
                engine: &shared.engine,
                transport: Transport::Tls,
                peer,
                client_id: client_id.as_deref(),
                idle_timeout: config.tls_idle_timeout,
            };
            serve_messages(&mut stream, &served, stop).await;
            // close_notify, so the client knows nothing was cut off.
            let _ = timeout(TLS_CLOSE_TIMEOUT, stream.shutdown()).await;
        }
        Kind::Https(acceptor) => {
            let Some((stream, client_id)) = handshake(&acceptor, stream, peer, &shared).await
            else {
                return;
            };
            https::serve_connection(stream, peer, client_id, &shared, stop).await;
        }
    }
    drop(slots);
}

/// Completes the TLS handshake in time, and reads the client ID from the
/// server name the client asked for.
async fn handshake(
    acceptor: &TlsAcceptor,
    stream: TcpStream,
    peer: SocketAddr,
    shared: &Shared,
) -> Option<(TlsStream<TcpStream>, Option<String>)> {
    match timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
        Ok(Ok(stream)) => {
            let client_id = match (&shared.config.server_name, stream.get_ref().1.server_name()) {
                (Some(ours), Some(asked)) => doh::client_id_from_server_name(asked, ours),
                _ => None,
            };
            Some((stream, client_id))
        }
        Ok(Err(err)) => {
            debug!(%peer, %err, "TLS handshake failed");
            ServerStats::count(&shared.stats.tls_handshake_failures);
            None
        }
        Err(_) => {
            debug!(%peer, "TLS handshake not finished in time");
            ServerStats::count(&shared.stats.tls_handshake_failures);
            None
        }
    }
}

/// Who a connection's queries come from, and how.
struct Served<'a> {
    engine: &'a Engine,
    transport: Transport,
    peer: SocketAddr,
    client_id: Option<&'a str>,
    idle_timeout: Duration,
}

/// Answers length-prefixed DNS messages (RFC 7766, RFC 7858) on `stream`,
/// one after the other, until the client hangs up, sends something that is
/// not DNS, stays idle too long, or shutdown.
async fn serve_messages<S>(stream: &mut S, served: &Served<'_>, mut stop: watch::Receiver<bool>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Served {
        engine,
        transport,
        peer,
        client_id,
        idle_timeout,
    } = *served;
    let mut prefix = [0_u8; 2];
    let mut query = Vec::new();
    let mut response = Vec::with_capacity(usize::from(MIN_UDP_PAYLOAD));
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
                    debug!(%peer, %transport, %err, "read failed");
                }
                break;
            }
            Err(_) => {
                trace!(%peer, %transport, "closing idle connection");
                break;
            }
        }

        // The length prefix bounds the message to 65,535 bytes.
        query.resize(usize::from(u16::from_be_bytes(prefix)), 0);
        match timeout(idle_timeout, stream.read_exact(&mut query)).await {
            Ok(Ok(_)) => {}
            Ok(Err(err)) => {
                debug!(%peer, %transport, %err, "read failed");
                break;
            }
            Err(_) => {
                debug!(%peer, %transport, "query not received in time");
                break;
            }
        }

        // A dropped message means the peer is not speaking DNS: hang up.
        if engine
            .answer(&query, transport, peer, client_id, &mut response)
            .await
            .is_none()
        {
            break;
        }
        let Ok(len) = u16::try_from(response.len()) else {
            break;
        };
        frame.clear();
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&response);
        // TLS buffers what is written until it is flushed.
        let written = async {
            stream.write_all(&frame).await?;
            stream.flush().await
        };
        match timeout(idle_timeout, written).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                debug!(%peer, %transport, %err, "write failed");
                break;
            }
            Err(_) => {
                debug!(%peer, %transport, "response not sent in time");
                break;
            }
        }
    }
}
