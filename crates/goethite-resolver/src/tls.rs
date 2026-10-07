//! DNS over TLS (RFC 7858) and DNS over HTTPS (RFC 8484) upstream clients.
//!
//! TLS is rustls with the ring provider, TLS 1.2 and 1.3, and certificates
//! checked against the bundled Mozilla roots (or a given set of CAs) for the
//! configured server name. Connections are reused: DoT keeps a few idle
//! connections per upstream, DoH multiplexes queries over one HTTP/2
//! connection.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::client::conn::http2::SendRequest;
use hyper::header::{ACCEPT, CONTENT_TYPE};
use hyper::{Request, StatusCode, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tracing::debug;

/// Idle DoT connections kept per upstream.
const MAX_IDLE_CONNECTIONS: usize = 4;

/// Idle DoT connections older than this are not reused; servers close idle
/// connections after some seconds (RFC 7858 3.4, RFC 7766 6.2.3).
const IDLE_REUSE_LIMIT: Duration = Duration::from_secs(20);

/// The largest DoH response body accepted: the largest DNS message.
const MAX_DOH_RESPONSE: usize = 65_535;

/// The media type of DNS messages over HTTPS.
const DNS_MESSAGE: &str = "application/dns-message";

/// Which certificate authorities upstream certificates must chain to.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub enum TlsRoots {
    /// The Mozilla root program, compiled into the binary (webpki-roots).
    #[default]
    Bundled,
    /// Only these DER-encoded CA certificates, e.g. a private CA or tests.
    Custom(Vec<Vec<u8>>),
}

/// Why TLS could not be set up.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TlsError {
    /// A custom root certificate could not be used.
    #[error("invalid root certificate: {0}")]
    InvalidRoot(rustls::Error),
    /// The TLS configuration was rejected.
    #[error("invalid TLS configuration: {0}")]
    Config(rustls::Error),
}

/// A TLS client configuration with goethite's settings (rustls, ring, TLS
/// 1.2 and 1.3, `roots`), offering `alpn` if not empty. For other HTTPS
/// clients in goethite, such as the filter list downloader.
///
/// # Errors
///
/// Returns [`TlsError`] if a custom root is invalid.
pub fn tls_client_config(roots: &TlsRoots, alpn: &[&[u8]]) -> Result<Arc<ClientConfig>, TlsError> {
    client_config(roots, alpn)
}

/// Builds the client configuration; `alpn` is offered if not empty.
pub(crate) fn client_config(
    roots: &TlsRoots,
    alpn: &[&[u8]],
) -> Result<Arc<ClientConfig>, TlsError> {
    let mut store = RootCertStore::empty();
    match roots {
        TlsRoots::Bundled => store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        TlsRoots::Custom(certificates) => {
            for der in certificates {
                store
                    .add(CertificateDer::from(der.clone()))
                    .map_err(TlsError::InvalidRoot)?;
            }
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(TlsError::Config)?
        .with_root_certificates(store)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Ok(Arc::new(config))
}

/// Opens a TCP connection to `address` and runs the TLS handshake for
/// `server_name`.
async fn connect_tls(
    connector: &TlsConnector,
    address: SocketAddr,
    server_name: &ServerName<'static>,
) -> io::Result<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(address).await?;
    tcp.set_nodelay(true)?;
    connector.connect(server_name.clone(), tcp).await
}

/// Sends `wire` with RFC 7766 length framing and reads one framed reply.
pub(crate) async fn exchange_framed<S>(stream: &mut S, wire: &[u8]) -> io::Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let len = u16::try_from(wire.len()).map_err(|_| io::Error::other("query too large"))?;
    let mut frame = Vec::with_capacity(wire.len().saturating_add(2));
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(wire);
    stream.write_all(&frame).await?;
    stream.flush().await?;
    let mut prefix = [0_u8; 2];
    stream.read_exact(&mut prefix).await?;
    let mut reply = vec![0_u8; usize::from(u16::from_be_bytes(prefix))];
    stream.read_exact(&mut reply).await?;
    Ok(reply)
}

/// A DoT upstream: connections are reused one query at a time.
pub(crate) struct DotClient {
    connector: TlsConnector,
    server_name: ServerName<'static>,
    idle: Mutex<Vec<(TlsStream<TcpStream>, Instant)>>,
}

impl DotClient {
    pub(crate) fn new(config: Arc<ClientConfig>, server_name: ServerName<'static>) -> Self {
        Self {
            connector: TlsConnector::from(config),
            server_name,
            idle: Mutex::new(Vec::new()),
        }
    }

    /// Exchanges `wire` with the upstream at `address`.
    ///
    /// An idle connection is tried first. The server may have closed it in
    /// the meantime, so if that fails the query is sent once more on a new
    /// connection.
    pub(crate) async fn exchange(&self, address: SocketAddr, wire: &[u8]) -> io::Result<Vec<u8>> {
        if let Some(mut stream) = self.take_idle() {
            match exchange_framed(&mut stream, wire).await {
                Ok(reply) => {
                    self.put_back(stream);
                    return Ok(reply);
                }
                Err(err) => debug!(%address, %err, "reused DoT connection failed, reconnecting"),
            }
        }
        let mut stream = connect_tls(&self.connector, address, &self.server_name).await?;
        let reply = exchange_framed(&mut stream, wire).await?;
        self.put_back(stream);
        Ok(reply)
    }

    fn take_idle(&self) -> Option<TlsStream<TcpStream>> {
        let mut idle = self.idle.lock().ok()?;
        let now = Instant::now();
        while let Some((stream, since)) = idle.pop() {
            if now.saturating_duration_since(since) < IDLE_REUSE_LIMIT {
                return Some(stream);
            }
        }
        None
    }

    fn put_back(&self, stream: TlsStream<TcpStream>) {
        if let Ok(mut idle) = self.idle.lock()
            && idle.len() < MAX_IDLE_CONNECTIONS
        {
            idle.push((stream, Instant::now()));
        }
    }
}

/// Why a DoH exchange failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum DohError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("HTTP/2: {0}")]
    Http(#[from] hyper::Error),
    #[error("the server did not agree to HTTP/2")]
    NoHttp2,
    #[error("HTTP status {0}")]
    Status(StatusCode),
    #[error("unexpected content type")]
    ContentType,
    #[error("response body is unreadable or larger than {MAX_DOH_RESPONSE} bytes")]
    Body,
    #[error("cannot build the request")]
    Request,
}

/// A DoH upstream: queries are multiplexed over one HTTP/2 connection.
pub(crate) struct DohClient {
    connector: TlsConnector,
    server_name: ServerName<'static>,
    uri: Uri,
    sender: Mutex<Option<SendRequest<Full<Bytes>>>>,
}

impl DohClient {
    pub(crate) fn new(
        config: Arc<ClientConfig>,
        server_name: ServerName<'static>,
        uri: Uri,
    ) -> Self {
        Self {
            connector: TlsConnector::from(config),
            server_name,
            uri,
            sender: Mutex::new(None),
        }
    }

    /// POSTs `wire` to the upstream at `address` and returns the response
    /// body. A connection that turns out to be closed is replaced once.
    pub(crate) async fn exchange(
        &self,
        address: SocketAddr,
        wire: &[u8],
    ) -> Result<Vec<u8>, DohError> {
        if let Some(mut sender) = self.open_sender() {
            match self.post(&mut sender, wire).await {
                Err(DohError::Http(err)) => {
                    debug!(%address, %err, "DoH connection failed, reconnecting");
                }
                result => return result,
            }
        }
        let mut sender = self.connect(address).await?;
        self.post(&mut sender, wire).await
    }

    fn open_sender(&self) -> Option<SendRequest<Full<Bytes>>> {
        let guard = self.sender.lock().ok()?;
        guard.as_ref().filter(|sender| !sender.is_closed()).cloned()
    }

    async fn connect(&self, address: SocketAddr) -> Result<SendRequest<Full<Bytes>>, DohError> {
        let stream = connect_tls(&self.connector, address, &self.server_name).await?;
        if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
            return Err(DohError::NoHttp2);
        }
        let (sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
                .await?;
        tokio::spawn(async move {
            if let Err(err) = connection.await {
                debug!(%address, %err, "DoH connection closed");
            }
        });
        if let Ok(mut guard) = self.sender.lock() {
            *guard = Some(sender.clone());
        }
        Ok(sender)
    }

    async fn post(
        &self,
        sender: &mut SendRequest<Full<Bytes>>,
        wire: &[u8],
    ) -> Result<Vec<u8>, DohError> {
        let request = Request::post(self.uri.clone())
            .header(CONTENT_TYPE, DNS_MESSAGE)
            .header(ACCEPT, DNS_MESSAGE)
            .body(Full::new(Bytes::copy_from_slice(wire)))
            .map_err(|_| DohError::Request)?;
        sender.ready().await?;
        let response = sender.send_request(request).await?;
        if response.status() != StatusCode::OK {
            return Err(DohError::Status(response.status()));
        }
        let content_type = response.headers().get(CONTENT_TYPE);
        if !content_type.is_some_and(|value| value.as_bytes().starts_with(DNS_MESSAGE.as_bytes())) {
            return Err(DohError::ContentType);
        }
        let body = Limited::new(response.into_body(), MAX_DOH_RESPONSE)
            .collect()
            .await
            .map_err(|_| DohError::Body)?;
        Ok(body.to_bytes().to_vec())
    }
}
