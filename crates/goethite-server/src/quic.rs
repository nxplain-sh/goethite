//! DNS over QUIC (RFC 9250): one QUIC endpoint per listen address.
//!
//! - **Address validation first.** A client whose address is not validated
//!   yet gets a Retry, so a connection slot is only ever taken by a peer
//!   that can receive at its address, as with TCP. Without it, spoofed
//!   packets could fill the slots TCP, DNS over TLS and DNS over HTTPS
//!   share.
//! - **The same limits as TCP:** QUIC connections count against
//!   [`crate::ServerConfig::max_tcp_connections`] and the per-client limit.
//!   A connection may have 64 queries open, never a unidirectional stream,
//!   and closes after [`crate::ServerConfig::tls_idle_timeout`] without
//!   traffic. Each stream carries at most one DNS message and must arrive
//!   within the idle timeout.
//! - **No 0-RTT**, so a query cannot be replayed.
//! - **Upgrades.** The new goethite reads the same socket. Each endpoint
//!   makes connection IDs with a random key of its own and ignores packets
//!   for IDs it did not make, so while both read, neither resets the other's
//!   connections; QUIC resends what the other one received. Shutting down,
//!   an endpoint ignores new connections, so their clients try again and
//!   reach whoever serves then, finishes the queries in progress and closes
//!   its connections.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{HandshakeData, QuicServerConfig};
use quinn::{
    Connecting, Connection, Endpoint, EndpointConfig, IdleTimeout, Incoming, RecvStream,
    SendStream, TokioRuntime, TransportConfig, VarInt,
};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, error, trace};

use crate::doq::{self, code};
use crate::stream::{Slots, TLS_HANDSHAKE_TIMEOUT};
use crate::{Engine, ServerError, ServerStats, Shared, Transport, doh, stopped};

/// Queries open at once on one connection.
const MAX_STREAMS: u32 = 64;

/// Bytes a client may have in flight on one connection: a few queries.
const RECEIVE_WINDOW: u32 = 256 * 1024;

/// Bytes of answers buffered for one connection.
const SEND_WINDOW: u64 = 1024 * 1024;

/// Connection attempts waiting to be accepted, over the endpoint.
const MAX_INCOMING: usize = 1024;

/// How long closing frames may take to leave once the endpoint closes.
const CLOSE_GRACE: Duration = Duration::from_secs(1);

/// An endpoint serving DNS over QUIC on `socket`, with the certificate in
/// `tls`. Needs a tokio runtime.
pub(crate) fn endpoint(
    socket: std::net::UdpSocket,
    tls: &rustls::ServerConfig,
    idle: Duration,
) -> Result<Endpoint, ServerError> {
    let mut tls = tls.clone();
    tls.alpn_protocols = vec![doq::ALPN.to_vec()];
    // 0-RTT data could be replayed; DNS over QUIC servers may refuse it.
    tls.max_early_data_size = 0;
    let crypto = QuicServerConfig::try_from(tls).map_err(|_| ServerError::Quic)?;
    let mut transport = TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(VarInt::from_u32(MAX_STREAMS))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .stream_receive_window(VarInt::from_u32(
            u32::try_from(doq::MAX_STREAM_LEN).unwrap_or(u32::MAX),
        ))
        .receive_window(VarInt::from_u32(RECEIVE_WINDOW))
        .send_window(SEND_WINDOW)
        .max_idle_timeout(IdleTimeout::try_from(idle).ok())
        .keep_alive_interval(None)
        .datagram_receive_buffer_size(None);
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server
        .transport_config(Arc::new(transport))
        .max_incoming(MAX_INCOMING);
    Endpoint::new(
        EndpointConfig::default(),
        Some(server),
        socket,
        Arc::new(TokioRuntime),
    )
    .map_err(ServerError::Register)
}

/// Serves DNS over QUIC on `endpoint` until shutdown.
pub(crate) async fn serve(
    endpoint: Endpoint,
    shared: Arc<Shared>,
    mut stop: watch::Receiver<bool>,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = stopped(&mut stop) => break,
            Some(joined) = connections.join_next(), if !connections.is_empty() => {
                if let Err(err) = joined {
                    error!(%err, "DNS over QUIC connection task failed");
                }
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break;
                };
                if let Some((connecting, peer, slots)) = admit(incoming, &shared) {
                    connections.spawn(connection(
                        connecting,
                        peer,
                        Arc::clone(&shared),
                        stop.clone(),
                        slots,
                    ));
                }
            }
        }
    }

    // Connections finish their queries; new ones are left for whoever
    // serves next.
    let finished = timeout(shared.config.shutdown_grace, async {
        while connections.join_next().await.is_some() {}
    });
    let ignore_new = async {
        while let Some(incoming) = endpoint.accept().await {
            incoming.ignore();
        }
    };
    tokio::select! {
        _ = finished => {}
        () = ignore_new => {}
    }
    connections.shutdown().await;
    endpoint.close(VarInt::from_u32(code::NO_ERROR), b"");
    let _ = timeout(CLOSE_GRACE, endpoint.wait_idle()).await;
}

/// A connection attempt to accept, with the slots it holds, or `None` if it
/// was answered with a Retry or refused.
fn admit(incoming: Incoming, shared: &Shared) -> Option<(Connecting, SocketAddr, Slots)> {
    let peer = incoming.remote_address();
    // Ignored, not refused: nothing goes back to an address the access
    // lists refuse, which may not even be the sender's.
    if !shared.engine.resolver.may_admit(peer.ip()) {
        trace!(%peer, "access lists refuse the client, ignoring a DNS over QUIC connection");
        shared.stats.access_refused.count(Transport::Quic);
        incoming.ignore();
        return None;
    }
    if !incoming.remote_address_validated() {
        if incoming.may_retry() {
            if let Err(err) = incoming.retry() {
                err.into_incoming().refuse();
            }
        } else {
            debug!(%peer, "DNS over QUIC address validation failed, refusing");
            incoming.refuse();
        }
        return None;
    }
    let Ok(permit) = Arc::clone(&shared.tcp_slots).try_acquire_owned() else {
        debug!(%peer, "connection limit reached, refusing a DNS over QUIC connection");
        ServerStats::count(&shared.stats.tcp_refused);
        incoming.refuse();
        return None;
    };
    let Some(client) = shared.tcp_clients.try_acquire(peer.ip()) else {
        debug!(%peer, "per-client connection limit reached, refusing a DNS over QUIC connection");
        ServerStats::count(&shared.stats.tcp_refused_per_client);
        incoming.refuse();
        return None;
    };
    match incoming.accept() {
        Ok(connecting) => Some((connecting, peer, (permit, client))),
        Err(err) => {
            debug!(%peer, %err, "cannot accept a DNS over QUIC connection");
            None
        }
    }
}

/// Serves one connection: a task per query stream.
async fn connection(
    connecting: Connecting,
    peer: SocketAddr,
    shared: Arc<Shared>,
    mut stop: watch::Receiver<bool>,
    slots: Slots,
) {
    let connection = match timeout(TLS_HANDSHAKE_TIMEOUT, connecting).await {
        Ok(Ok(connection)) => connection,
        Ok(Err(err)) => {
            debug!(%peer, %err, "DNS over QUIC handshake failed");
            ServerStats::count(&shared.stats.tls_handshake_failures);
            return;
        }
        Err(_) => {
            debug!(%peer, "DNS over QUIC handshake not finished in time");
            ServerStats::count(&shared.stats.tls_handshake_failures);
            return;
        }
    };
    let client_id = client_id(&connection, &shared).map(Arc::<str>::from);
    let idle = shared.config.tls_idle_timeout;
    let mut streams = JoinSet::new();
    let mut close = code::NO_ERROR;
    loop {
        tokio::select! {
            biased;
            () = stopped(&mut stop) => break,
            Some(joined) = streams.join_next(), if !streams.is_empty() => {
                if let Ok(Err(err)) = joined {
                    debug!(%peer, %err, "DNS over QUIC protocol error, closing");
                    close = code::PROTOCOL_ERROR;
                    break;
                }
            }
            accepted = connection.accept_bi() => {
                let (send, recv) = match accepted {
                    Ok(streams) => streams,
                    Err(err) => {
                        trace!(%peer, %err, "DNS over QUIC connection ended");
                        break;
                    }
                };
                streams.spawn(answer(
                    send,
                    recv,
                    Arc::clone(&shared.engine),
                    peer,
                    client_id.clone(),
                    idle,
                ));
            }
        }
    }
    if close == code::NO_ERROR {
        // Queries in progress finish, within the shutdown grace period.
        let _ = timeout(shared.config.shutdown_grace, async {
            while streams.join_next().await.is_some() {}
        })
        .await;
    }
    streams.shutdown().await;
    connection.close(VarInt::from_u32(close), b"");
    drop(slots);
}

/// The client ID in the server name the client asked for, if any.
fn client_id(connection: &Connection, shared: &Shared) -> Option<String> {
    let ours = shared.config.server_name.as_deref()?;
    let asked = connection
        .handshake_data()?
        .downcast::<HandshakeData>()
        .ok()?
        .server_name?;
    doh::client_id_from_server_name(&asked, ours)
}

/// Reads one stream into a single buffer of at most [`doq::MAX_STREAM_LEN`]
/// bytes. Unlike quinn's `read_to_end`, which keeps every chunk until the
/// end, a flood of tiny chunks costs one buffer.
async fn read_stream(recv: &mut RecvStream) -> Result<Vec<u8>, quinn::ReadToEndError> {
    let mut stream = Vec::new();
    loop {
        match recv.read_chunk(usize::MAX, true).await {
            Ok(Some(chunk)) => {
                if stream.len().saturating_add(chunk.bytes.len()) > doq::MAX_STREAM_LEN {
                    return Err(quinn::ReadToEndError::TooLong);
                }
                stream.extend_from_slice(&chunk.bytes);
            }
            Ok(None) => return Ok(stream),
            Err(err) => return Err(err.into()),
        }
    }
}

/// Answers the query on one stream. An error is the client's protocol
/// error, which closes the connection.
async fn answer(
    mut send: SendStream,
    mut recv: RecvStream,
    engine: Arc<Engine>,
    peer: SocketAddr,
    client_id: Option<Arc<str>>,
    idle: Duration,
) -> Result<(), doq::DoqError> {
    let stream = match timeout(idle, read_stream(&mut recv)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(quinn::ReadToEndError::TooLong)) => return Err(doq::DoqError::TooLong),
        Ok(Err(err)) => {
            trace!(%peer, %err, "DNS over QUIC stream ended early");
            return Ok(());
        }
        Err(_) => {
            debug!(%peer, "DNS over QUIC query not received in time");
            let _ = recv.stop(VarInt::from_u32(code::REQUEST_CANCELLED));
            let _ = send.reset(VarInt::from_u32(code::REQUEST_CANCELLED));
            return Ok(());
        }
    };
    let query = doq::query(&stream)?;
    let mut response = Vec::new();
    if engine
        .answer(
            query,
            Transport::Quic,
            peer,
            client_id.as_deref(),
            &mut response,
        )
        .await
        .is_none()
    {
        return Err(doq::DoqError::NotDns);
    }
    let Ok(len) = u16::try_from(response.len()) else {
        let _ = send.reset(VarInt::from_u32(code::INTERNAL_ERROR));
        return Ok(());
    };
    let mut frame = Vec::with_capacity(response.len().saturating_add(2));
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&response);
    match timeout(idle, send.write_all(&frame)).await {
        Ok(Ok(())) => {
            let _ = send.finish();
        }
        Ok(Err(err)) => trace!(%peer, %err, "DNS over QUIC answer not sent"),
        Err(_) => {
            debug!(%peer, "DNS over QUIC answer not sent in time");
            let _ = send.reset(VarInt::from_u32(code::REQUEST_CANCELLED));
        }
    }
    Ok(())
}
