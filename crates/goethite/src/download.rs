//! Downloading filter lists over HTTPS.
//!
//! Only `https://` URLs are fetched, redirects included. Host names are
//! resolved through goethite's own resolver (skipping the filter), not the
//! system resolver, which may be goethite itself; the TLS certificate check
//! then authenticates the host whatever the DNS answer was. Every download is
//! bounded in size and time, and revalidated with `ETag` and
//! `Last-Modified` so unchanged lists are not transferred again.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use goethite_resolver::Resolver;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{
    ETAG, HeaderMap, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, LOCATION, RANGE,
};
use hyper::{Method, Response, StatusCode, Uri};
use rustls::ClientConfig;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::debug;

use crate::connect::Connection;

/// Redirects followed before giving up.
const MAX_REDIRECTS: usize = 3;

/// How long a whole download may take, redirects included.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);

/// Longer `ETag` or `Last-Modified` values are not kept.
const MAX_VALIDATOR_LEN: usize = 1024;

/// What a previous download returned, to revalidate it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Validators {
    /// The `ETag` header.
    pub etag: Option<String>,
    /// The `Last-Modified` header.
    pub last_modified: Option<String>,
}

/// The result of a download.
pub(crate) enum Fetched {
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
    /// The server refuses ranges: ask for the whole thing.
    NoRange,
}

/// Fetches `https://` URLs.
pub(crate) struct Downloader {
    resolver: Arc<Resolver>,
    connector: TlsConnector,
    max_len: usize,
}

impl Downloader {
    /// A downloader resolving names with `resolver`, verifying certificates
    /// with `tls` and accepting bodies of at most `max_len` bytes.
    pub(crate) fn new(resolver: Arc<Resolver>, tls: Arc<ClientConfig>, max_len: usize) -> Self {
        Self {
            resolver,
            connector: TlsConnector::from(tls),
            max_len,
        }
    }

    /// Downloads `url`, sending `validators` so an unchanged list is not
    /// transferred again.
    pub(crate) async fn fetch(&self, url: &str, validators: &Validators) -> Result<Fetched> {
        timeout(
            DOWNLOAD_TIMEOUT,
            self.fetch_following(url, validators, None),
        )
        .await
        .map_err(|_| anyhow!("timed out after {} s", DOWNLOAD_TIMEOUT.as_secs()))?
    }

    /// The first `len` bytes of `url` (fewer if it is shorter), for its
    /// header: asked for with a range, and cut off there if the server
    /// sends more.
    pub(crate) async fn fetch_start(&self, url: &str, len: usize) -> Result<Vec<u8>> {
        let fetched = timeout(
            DOWNLOAD_TIMEOUT,
            self.fetch_following(url, &Validators::default(), Some(len)),
        )
        .await
        .map_err(|_| anyhow!("timed out after {} s", DOWNLOAD_TIMEOUT.as_secs()))??;
        match fetched {
            Fetched::Body { bytes, .. } => Ok(bytes),
            Fetched::NotModified => bail!("{url} answered \"not modified\" to a plain request"),
        }
    }

    async fn fetch_following(
        &self,
        url: &str,
        validators: &Validators,
        start: Option<usize>,
    ) -> Result<Fetched> {
        let mut uri = https_uri(url)?;
        let mut ranged = start.is_some();
        for _ in 0..=MAX_REDIRECTS.saturating_add(1) {
            match self.get(&uri, validators, start, ranged).await? {
                Step::Done(fetched) => return Ok(fetched),
                Step::Redirect(location) => {
                    debug!(from = %uri, to = %location, "following redirect");
                    uri = redirect_target(&uri, &location)?;
                }
                Step::NoRange if ranged => ranged = false,
                Step::NoRange => bail!("{uri} refused a request without a range"),
            }
        }
        bail!("more than {MAX_REDIRECTS} redirects")
    }

    async fn get(
        &self,
        uri: &Uri,
        validators: &Validators,
        start: Option<usize>,
        ranged: bool,
    ) -> Result<Step> {
        let mut connection =
            Connection::<Empty<Bytes>>::open(&self.resolver, &self.connector, uri).await?;
        let mut request = connection.request(Method::GET, uri)?;
        if let Some(etag) = &validators.etag {
            request = request.header(IF_NONE_MATCH, etag);
        }
        if let Some(last_modified) = &validators.last_modified {
            request = request.header(IF_MODIFIED_SINCE, last_modified);
        }
        if let Some(last) = start.and_then(|len| len.checked_sub(1)).filter(|_| ranged) {
            request = request.header(RANGE, format!("bytes=0-{last}"));
        }
        let response = connection
            .send(request.body(Empty::<Bytes>::new())?)
            .await?;
        match start {
            Some(len) => Self::handle_start(response, len).await,
            None => self.handle(response).await,
        }
    }

    /// The first `len` bytes of a 200 or 206 answer.
    async fn handle_start(response: Response<Incoming>, len: usize) -> Result<Step> {
        match response.status() {
            StatusCode::OK | StatusCode::PARTIAL_CONTENT => {
                let mut body = response.into_body();
                let mut bytes = Vec::new();
                while bytes.len() < len {
                    let Some(frame) = body.frame().await else {
                        break;
                    };
                    if let Ok(data) = frame?.into_data() {
                        bytes.extend_from_slice(&data);
                    }
                }
                bytes.truncate(len);
                Ok(Step::Done(Fetched::Body {
                    bytes,
                    validators: Validators::default(),
                }))
            }
            StatusCode::RANGE_NOT_SATISFIABLE => Ok(Step::NoRange),
            _ => redirect(&response),
        }
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
            _ => redirect(&response),
        }
    }
}

/// Where a redirect leads; any other status is an error.
fn redirect(response: &Response<Incoming>) -> Result<Step> {
    match response.status() {
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

/// Parses `url`, which must be an `https://` URL with a host.
pub(crate) fn https_uri(url: &str) -> Result<Uri> {
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
