//! Serving the API over HTTP/1.1 and HTTP/2, optionally with TLS.
//!
//! Listeners are bound with the standard library before the async runtime
//! starts (like the DNS listeners), so a privileged port works and
//! privileges are dropped afterwards. Connections are bounded in number, in
//! how long the TLS handshake and the request headers may take, and in how
//! long shutdown waits for them.

use std::future::Future;
use std::io;
use std::net::{SocketAddr, TcpListener as StdListener};
use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info};

use crate::auth::PeerAddr;
use crate::{Api, router};

/// The most API connections served at once.
pub const MAX_CONNECTIONS: usize = 64;

/// How long the TLS handshake and the request headers may take.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

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
                let listener = StdListener::bind(addr).map_err(|err| {
                    io::Error::new(err.kind(), format!("cannot bind the API on {addr}: {err}"))
                })?;
                listener.set_nonblocking(true)?;
                Ok(listener)
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
}

impl std::fmt::Debug for Serving {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Serving")
            .field("name", &self.name)
            .field("tls", &self.tls.is_some())
            .field("max_connections", &self.max_connections)
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
            stop_rx.clone(),
        ));
    }
    shutdown.await;
    stop_tx.send_replace(true);
    while accepting.join_next().await.is_some() {}
    Ok(())
}

async fn accept(
    name: &'static str,
    listener: TcpListener,
    router: axum::Router,
    tls: Option<TlsAcceptor>,
    slots: Arc<Semaphore>,
    mut stop: watch::Receiver<bool>,
) {
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
        let service =
            TowerToHyperService::new(router.clone().layer(axum::Extension(PeerAddr(peer))));
        let tls = tls.clone();
        connections.spawn(async move {
            let _permit = permit;
            if let Err(err) = connection(stream, tls, service).await {
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

async fn connection(
    stream: TcpStream,
    tls: Option<TlsAcceptor>,
    service: TowerToHyperService<axum::Router>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HANDSHAKE_TIMEOUT);
    builder.http2().timer(TokioTimer::new());
    match tls {
        Some(acceptor) => {
            let stream = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await??;
            builder
                .serve_connection(TokioIo::new(stream), service)
                .await
        }
        None => {
            builder
                .serve_connection(TokioIo::new(stream), service)
                .await
        }
    }
}
