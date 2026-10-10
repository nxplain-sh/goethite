//! Outgoing HTTP connections, for list downloads and telemetry export.
//!
//! Host names are resolved through goethite's own resolver (skipping the
//! filter), not the system resolver: it may be goethite itself, and the
//! sandbox does not let goethite read `/etc/resolv.conf`. `https://` URLs
//! are connected over TLS with rustls, whose certificate check then
//! authenticates the host whatever the DNS answer was; HTTP/2 is used when
//! the server offers it.

use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use goethite_proto::Name;
use goethite_resolver::Resolver;
use hyper::body::{Body, Incoming};
use hyper::client::conn::{http1, http2};
use hyper::header::{HOST, USER_AGENT};
use hyper::http::request;
use hyper::{Method, Request, Response, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

/// How long connecting to one address may take.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// An open connection to one host, sending requests with bodies of type `B`.
pub(crate) struct Connection<B> {
    sender: Sender<B>,
}

enum Sender<B> {
    Http1(http1::SendRequest<B>),
    Http2(http2::SendRequest<B>),
}

impl<B> Connection<B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
{
    /// Connects to the host of `uri`: over TLS with `tls` for `https://`,
    /// over plain TCP for `http://`.
    ///
    /// # Errors
    ///
    /// If the URL has another scheme or no host, the name does not resolve,
    /// no address accepts the connection, or the TLS or HTTP handshake fails.
    pub(crate) async fn open(resolver: &Resolver, tls: &TlsConnector, uri: &Uri) -> Result<Self> {
        let https = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => false,
            _ => bail!("{uri} is not an http:// or https:// URL"),
        };
        let host = uri.host().context("URL has no host")?;
        let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
        let bare_host = host.trim_start_matches('[').trim_end_matches(']');
        let addresses = if let Ok(ip) = bare_host.parse::<IpAddr>() {
            vec![ip]
        } else {
            let name: Name = bare_host
                .parse()
                .with_context(|| format!("{host:?} is not a valid host name"))?;
            resolver.lookup_addresses(&name).await
        };
        if addresses.is_empty() {
            bail!("cannot resolve {host}");
        }
        let tcp = connect(&addresses, port).await?;
        let sender = if https {
            let server_name = ServerName::try_from(bare_host.to_owned())
                .with_context(|| format!("{host:?} is not a valid TLS server name"))?;
            let tls = tls.connect(server_name, tcp).await?;
            if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
                let (sender, connection) =
                    http2::handshake(TokioExecutor::new(), TokioIo::new(tls)).await?;
                tokio::spawn(connection);
                Sender::Http2(sender)
            } else {
                let (sender, connection) = http1::handshake(TokioIo::new(tls)).await?;
                tokio::spawn(connection);
                Sender::Http1(sender)
            }
        } else {
            let (sender, connection) = http1::handshake(TokioIo::new(tcp)).await?;
            tokio::spawn(connection);
            Sender::Http1(sender)
        };
        Ok(Self { sender })
    }

    /// A request for `uri` on this connection, in the form its HTTP version
    /// expects: the whole URI for HTTP/2, the path and a `Host` header for
    /// HTTP/1.1.
    ///
    /// # Errors
    ///
    /// If the URL has no authority.
    pub(crate) fn request(&self, method: Method, uri: &Uri) -> Result<request::Builder> {
        let builder = match self.sender {
            Sender::Http2(_) => Request::builder().method(method).uri(uri.clone()),
            Sender::Http1(_) => {
                let path = uri.path_and_query().map_or("/", |p| p.as_str());
                let authority = uri.authority().context("URL has no authority")?;
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header(HOST, authority.as_str())
            }
        };
        Ok(builder.header(USER_AGENT, concat!("goethite/", env!("CARGO_PKG_VERSION"))))
    }

    /// Sends `request` and waits for the response's head.
    ///
    /// # Errors
    ///
    /// If the connection fails.
    pub(crate) async fn send(&mut self, request: Request<B>) -> Result<Response<Incoming>> {
        Ok(match &mut self.sender {
            Sender::Http1(sender) => sender.send_request(request).await?,
            Sender::Http2(sender) => sender.send_request(request).await?,
        })
    }
}

/// Connects to the first reachable address.
async fn connect(addresses: &[IpAddr], port: u16) -> Result<TcpStream> {
    let mut last_error = None;
    for &ip in addresses {
        match timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect(SocketAddr::new(ip, port)),
        )
        .await
        {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(err)) => last_error = Some(err.to_string()),
            Err(_) => last_error = Some("connection timed out".to_owned()),
        }
    }
    bail!(
        "cannot connect: {}",
        last_error.unwrap_or_else(|| "no addresses".to_owned())
    )
}
