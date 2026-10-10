//! Serving the API over HTTP/1.1 and HTTP/2, optionally with TLS.
//!
//! Listeners are bound with the standard library before the async runtime
//! starts (like the DNS listeners), so a privileged port works and
//! privileges are dropped afterwards. Connections are bounded in number, in
//! how long the TLS handshake and the request headers may take, and in how
//! long shutdown waits for them.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener as StdListener};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, oneshot, watch};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info};

use crate::auth::PeerAddr;
use crate::{Api, router};

/// The most API connections served at once.
pub const MAX_CONNECTIONS: usize = 64;

/// The listen backlog, as the DNS listeners use.
const TCP_BACKLOG: i32 = 1024;

/// The most connections served at once from one peer address.
pub const MAX_CONNECTIONS_PER_PEER: usize = 16;

/// How long the TLS handshake and the request headers may take.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How often a quiet HTTP/2 connection is pinged, and how long the reply
/// may take: a peer that went away is dropped instead of holding a slot.
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long shutdown waits for open connections.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// API sockets, bound but not yet serving.
#[derive(Debug)]
pub struct ApiListeners(Vec<StdListener>);

impl ApiListeners {
    /// Binds a TCP listener on each address.
    ///
    /// # Errors
    ///
    /// The operating system's error, with the address.
    pub fn bind(addresses: &[SocketAddr]) -> io::Result<Self> {
        addresses
            .iter()
            .map(|addr| {
                bind_listener(*addr).map_err(|err| {
                    io::Error::new(err.kind(), format!("cannot bind the API on {addr}: {err}"))
                })
            })
            .collect::<io::Result<_>>()
            .map(Self)
    }

    /// Listeners bound before, by an earlier goethite process or by
    /// systemd. They are made non-blocking.
    ///
    /// # Errors
    ///
    /// If one refuses to become non-blocking.
    pub fn from_listeners(listeners: Vec<StdListener>) -> io::Result<Self> {
        for listener in &listeners {
            listener.set_nonblocking(true)?;
        }
        Ok(Self(listeners))
    }

    /// The bound addresses.
    ///
    /// # Errors
    ///
    /// The operating system's error.
    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.0.iter().map(StdListener::local_addr).collect()
    }
}

/// Binds one TCP listener with `IPV6_V6ONLY`, as the DNS listeners do: a
/// wildcard `[::]` that also holds the IPv4 wildcard makes `0.0.0.0` beside
/// it fail with "address in use", and the docs spell dual-stack that way.
fn bind_listener(addr: SocketAddr) -> io::Result<StdListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    // As the standard library does: restarting must not wait for TIME_WAIT.
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.bind(&SockAddr::from(addr))?;
    socket.listen(TCP_BACKLOG)?;
    Ok(socket.into())
}

/// Serves the API on `listeners` until `shutdown` completes.
///
/// # Errors
///
/// If a listener cannot be registered with the runtime.
///
/// # Panics
///
/// Outside a tokio runtime with I/O enabled, as tokio does.
pub async fn serve(
    listeners: ApiListeners,
    api: Arc<Api>,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    let serving = Serving {
        name: "API",
        router: router(&api),
        tls: api.config.tls.clone(),
        max_connections: MAX_CONNECTIONS,
        first_request_timeout: HANDSHAKE_TIMEOUT,
    };
    serve_router(listeners, serving, shutdown).await
}

/// What a listener serves, and how.
pub struct Serving {
    /// A name for the logs, such as `API`.
    pub name: &'static str,
    /// The routes, with their own limits and headers.
    pub router: axum::Router,
    /// TLS; plain HTTP without it.
    pub tls: Option<Arc<rustls::ServerConfig>>,
    /// The most connections served at once; more are closed at once.
    pub max_connections: usize,
    /// How long a connection may wait for its first request; without one it
    /// is closed, so silent connections cannot hold its slot.
    pub first_request_timeout: Duration,
}

impl std::fmt::Debug for Serving {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Serving")
            .field("name", &self.name)
            .field("tls", &self.tls.is_some())
            .field("max_connections", &self.max_connections)
            .field("first_request_timeout", &self.first_request_timeout)
            .finish_non_exhaustive()
    }
}

/// Serves `serving` on `listeners` until `shutdown` completes, with the same
/// bounds as the API: connection count, handshake and header time, and a
/// grace period on shutdown. The cluster listener uses it too.
///
/// # Errors
///
/// If a listener cannot be registered with the runtime.
///
/// # Panics
///
/// Outside a tokio runtime with I/O enabled, as tokio does.
pub async fn serve_router(
    listeners: ApiListeners,
    serving: Serving,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    let Serving {
        name,
        router,
        tls,
        max_connections,
        first_request_timeout,
    } = serving;
    let tls = tls.map(TlsAcceptor::from);
    let scheme = if tls.is_some() { "https" } else { "http" };
    let slots = Arc::new(Semaphore::new(max_connections));
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut accepting = JoinSet::new();
    for listener in listeners.0 {
        let listener = TcpListener::from_std(listener)?;
        let address = listener.local_addr()?;
        info!(%address, scheme, "{name} listening");
        accepting.spawn(accept(
            name,
            listener,
            router.clone(),
            tls.clone(),
            Arc::clone(&slots),
            first_request_timeout,
            stop_rx.clone(),
        ));
    }
    shutdown.await;
    stop_tx.send_replace(true);
    while accepting.join_next().await.is_some() {}
    Ok(())
}

/// Live connections by peer address, to cap one client.
#[derive(Default)]
struct PeerConnections(Mutex<HashMap<IpAddr, usize>>);

impl PeerConnections {
    /// Counts one connection from `ip`, or refuses when it has too many.
    fn take(self: &Arc<Self>, ip: IpAddr) -> Option<PeerConnection> {
        let mut counts = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let count = counts.entry(ip).or_insert(0);
        if *count >= MAX_CONNECTIONS_PER_PEER {
            return None;
        }
        *count = count.saturating_add(1);
        drop(counts);
        Some(PeerConnection {
            counts: Arc::clone(self),
            ip,
        })
    }
}

/// One counted connection; uncounted when dropped.
struct PeerConnection {
    counts: Arc<PeerConnections>,
    ip: IpAddr,
}

impl Drop for PeerConnection {
    fn drop(&mut self) {
        let mut counts = self.counts.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = counts.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.ip);
            }
        }
    }
}

async fn accept(
    name: &'static str,
    listener: TcpListener,
    router: axum::Router,
    tls: Option<TlsAcceptor>,
    slots: Arc<Semaphore>,
    first_request_timeout: Duration,
    mut stop: watch::Receiver<bool>,
) {
    let peers = Arc::new(PeerConnections::default());
    let mut connections = JoinSet::new();
    loop {
        let accepted = tokio::select! {
            _ = stop.wait_for(|stop| *stop) => break,
            Some(_) = connections.join_next(), if !connections.is_empty() => continue,
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(err) => {
                debug!(%err, "{name} accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            debug!(%peer, "too many {name} connections, closing");
            continue;
        };
        let Some(connection_slot) = peers.take(peer.ip()) else {
            debug!(%peer, "too many {name} connections from one address, closing");
            continue;
        };
        // The first request stops the deadline; until then a connection
        // that sends nothing holds its slot for a short time only.
        let (first_tx, first_rx) = oneshot::channel::<()>();
        let first_tx = Arc::new(Mutex::new(Some(first_tx)));
        let router =
            router
                .clone()
                .layer(axum::Extension(PeerAddr(peer)))
                .layer(axum::middleware::from_fn(
                    move |request: axum::extract::Request, next: axum::middleware::Next| {
                        let first_tx = Arc::clone(&first_tx);
                        async move {
                            if let Some(tx) = first_tx
                                .lock()
                                .unwrap_or_else(PoisonError::into_inner)
                                .take()
                            {
                                let _ = tx.send(());
                            }
                            next.run(request).await
                        }
                    },
                ));
        let tls = tls.clone();
        connections.spawn(async move {
            let _permit = permit;
            let _connection_slot = connection_slot;
            if let Err(err) = connection(stream, tls, router, first_rx, first_request_timeout).await
            {
                debug!(%peer, %err, "{name} connection ended");
            }
        });
    }
    if timeout(SHUTDOWN_GRACE, async {
        while connections.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        connections.shutdown().await;
    }
}

/// The certificate a client presented in the TLS handshake, for routes
/// that serve clients with certificates (the cluster's members).
#[derive(Clone, Debug)]
pub struct PeerCertificate(pub Arc<[u8]>);

async fn connection(
    stream: TcpStream,
    tls: Option<TlsAcceptor>,
    router: axum::Router,
    mut first_request: oneshot::Receiver<()>,
    first_request_timeout: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HANDSHAKE_TIMEOUT);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(KEEP_ALIVE_INTERVAL)
        .keep_alive_timeout(KEEP_ALIVE_TIMEOUT);
    let mut serving = std::pin::pin!(async move {
        match tls {
            Some(acceptor) => {
                let stream = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await??;
                let certificate = stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|chain| chain.first())
                    .map(|cert| PeerCertificate(Arc::from(cert.as_ref())));
                let router = match certificate {
                    Some(certificate) => router.layer(axum::Extension(certificate)),
                    None => router,
                };
                builder
                    .serve_connection(TokioIo::new(stream), TowerToHyperService::new(router))
                    .await
            }
            None => {
                builder
                    .serve_connection(TokioIo::new(stream), TowerToHyperService::new(router))
                    .await
            }
        }
    });
    let first_arrived = tokio::select! {
        result = serving.as_mut() => {
            result?;
            return Ok(());
        }
        () = tokio::time::sleep(first_request_timeout) => false,
        _ = &mut first_request => true,
    };
    if !first_arrived {
        debug!("no request arrived in time; closing the connection");
        return Ok(());
    }
    serving.as_mut().await?;
    Ok(())
}
