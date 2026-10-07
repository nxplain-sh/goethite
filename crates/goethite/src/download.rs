//! Downloading filter lists over HTTPS.
//!
//! Only `https://` URLs are fetched, redirects included. Host names are
//! resolved through goethite's own resolver (skipping the filter), not the
//! system resolver, which may be goethite itself; the TLS certificate check
//! then authenticates the host whatever the DNS answer was. Every download is
//! bounded in size and time, and revalidated with `ETag` and
//! `Last-Modified` so unchanged lists are not transferred again.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use goethite_proto::Name;
use goethite_resolver::Resolver;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{
    ETAG, HOST, HeaderMap, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, LOCATION, USER_AGENT,
};
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::debug;

/// Redirects followed before giving up.
const MAX_REDIRECTS: usize = 3;

/// How long connecting to one address may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a whole download may take, redirects included.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);

/// Longer `ETag` or `Last-Modified` values are not kept.
const MAX_VALIDATOR_LEN: usize = 1024;

/// What a previous download returned, to revalidate it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Validators {
    /// The `ETag` header.
    pub etag: Option<String>,
    /// The `Last-Modified` header.
    pub last_modified: Option<String>,
}

/// The result of a download.
pub enum Fetched {
    /// The server says the copy we have is current.
    NotModified,
    /// A new copy.
    Body {
        /// The list.
        bytes: Vec<u8>,
        /// Validators for the next revalidation.
        validators: Validators,
    },
}

enum Step {
    Done(Fetched),
    Redirect(String),
}

/// Fetches `https://` URLs.
pub struct Downloader {
    resolver: Arc<Resolver>,
    connector: TlsConnector,
    max_len: usize,
}

impl Downloader {
    /// A downloader resolving names with `resolver`, verifying certificates
    /// with `tls` and accepting bodies of at most `max_len` bytes.
    pub fn new(resolver: Arc<Resolver>, tls: Arc<ClientConfig>, max_len: usize) -> Self {
        Self {
            resolver,
            connector: TlsConnector::from(tls),
            max_len,
        }
    }

    /// Downloads `url`, sending `validators` so an unchanged list is not
    /// transferred again.
    pub async fn fetch(&self, url: &str, validators: &Validators) -> Result<Fetched> {
        timeout(DOWNLOAD_TIMEOUT, self.fetch_following(url, validators))
            .await
            .map_err(|_| anyhow!("timed out after {} s", DOWNLOAD_TIMEOUT.as_secs()))?
    }

    async fn fetch_following(&self, url: &str, validators: &Validators) -> Result<Fetched> {
        let mut uri = https_uri(url)?;
        for _ in 0..=MAX_REDIRECTS {
            match self.get(&uri, validators).await? {
                Step::Done(fetched) => return Ok(fetched),
                Step::Redirect(location) => {
                    debug!(from = %uri, to = %location, "following redirect");
                    uri = redirect_target(&uri, &location)?;
                }
            }
        }
        bail!("more than {MAX_REDIRECTS} redirects")
    }

    async fn get(&self, uri: &Uri, validators: &Validators) -> Result<Step> {
        let host = uri.host().context("URL has no host")?;
        let port = uri.port_u16().unwrap_or(443);
        let bare_host = host.trim_start_matches('[').trim_end_matches(']');
        let addresses = if let Ok(ip) = bare_host.parse::<IpAddr>() {
            vec![ip]
        } else {
            let name: Name = bare_host
                .parse()
                .with_context(|| format!("{host:?} is not a valid host name"))?;
            self.resolver.lookup_addresses(&name).await
        };
        if addresses.is_empty() {
            bail!("cannot resolve {host}");
        }
        let tcp = connect(&addresses, port).await?;
        let server_name = ServerName::try_from(bare_host.to_owned())
            .with_context(|| format!("{host:?} is not a valid TLS server name"))?;
        let tls = self.connector.connect(server_name, tcp).await?;
        let http2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
        let io = TokioIo::new(tls);

        let mut request = if http2 {
            Request::get(uri.clone())
        } else {
            let path = uri.path_and_query().map_or("/", |p| p.as_str());
            let authority = uri.authority().context("URL has no authority")?;
            Request::get(path).header(HOST, authority.as_str())
        };
        request = request.header(USER_AGENT, concat!("goethite/", env!("CARGO_PKG_VERSION")));
        if let Some(etag) = &validators.etag {
            request = request.header(IF_NONE_MATCH, etag);
        }
        if let Some(last_modified) = &validators.last_modified {
            request = request.header(IF_MODIFIED_SINCE, last_modified);
        }
        let request = request.body(Empty::<Bytes>::new())?;

        let response = if http2 {
            let (mut sender, connection) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), io).await?;
            tokio::spawn(connection);
            sender.send_request(request).await?
        } else {
            let (mut sender, connection) = hyper::client::conn::http1::handshake(io).await?;
            tokio::spawn(connection);
            sender.send_request(request).await?
        };
        self.handle(response).await
    }

    async fn handle(&self, response: Response<Incoming>) -> Result<Step> {
        match response.status() {
            StatusCode::OK => {
                let validators = validators(response.headers());
                let body = Limited::new(response.into_body(), self.max_len)
                    .collect()
                    .await
                    .map_err(|err| {
                        anyhow!(
                            "cannot read the list (at most {} bytes): {err}",
                            self.max_len
                        )
                    })?;
                Ok(Step::Done(Fetched::Body {
                    bytes: body.to_bytes().to_vec(),
                    validators,
                }))
            }
            StatusCode::NOT_MODIFIED => Ok(Step::Done(Fetched::NotModified)),
            StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT => {
                let location = response
                    .headers()
                    .get(LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .context("redirect without a Location")?;
                Ok(Step::Redirect(location.to_owned()))
            }
            status => bail!("HTTP status {status}"),
        }
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

/// Parses `url`, which must be an `https://` URL with a host.
pub fn https_uri(url: &str) -> Result<Uri> {
    let uri: Uri = url
        .parse()
        .with_context(|| format!("{url:?} is not a URL"))?;
    if uri.scheme_str() != Some("https") {
        bail!("{url:?} is not an https:// URL");
    }
    if uri.host().is_none_or(str::is_empty) {
        bail!("{url:?} has no host");
    }
    Ok(uri)
}

/// Where a redirect from `from` to `location` leads: an absolute `https://`
/// URL, or a path on the same host.
fn redirect_target(from: &Uri, location: &str) -> Result<Uri> {
    if location.starts_with('/') && !location.starts_with("//") {
        let authority = from.authority().context("URL has no authority")?;
        return https_uri(&format!("https://{authority}{location}"));
    }
    https_uri(location).context("redirect to a non-https:// URL")
}

fn validators(headers: &HeaderMap) -> Validators {
    let value = |name| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .filter(|value| value.len() <= MAX_VALIDATOR_LEN)
            .map(str::to_owned)
    };
    Validators {
        etag: value(ETAG),
        last_modified: value(LAST_MODIFIED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_urls() {
        assert!(https_uri("https://lists.example/hosts").is_ok());
        for bad in [
            "http://lists.example/hosts",
            "ftp://lists.example/hosts",
            "lists.example/hosts",
            "https:///hosts",
            "",
        ] {
            assert!(https_uri(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn redirects_stay_on_https() {
        let from = https_uri("https://lists.example:8443/a/hosts").unwrap();
        assert_eq!(
            redirect_target(&from, "/b/hosts").unwrap().to_string(),
            "https://lists.example:8443/b/hosts"
        );
        assert_eq!(
            redirect_target(&from, "https://cdn.example/hosts")
                .unwrap()
                .to_string(),
            "https://cdn.example/hosts"
        );
        assert!(redirect_target(&from, "http://cdn.example/hosts").is_err());
        assert!(redirect_target(&from, "//cdn.example/hosts").is_err());
    }
}
