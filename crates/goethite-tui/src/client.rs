//! A small HTTP client for the goethite API, and for the other JSON APIs
//! `goethite migrate` reads from.
//!
//! One HTTP/1.1 connection per request: the TUI makes a few requests a
//! second at most, so simplicity wins over connection reuse. HTTPS uses the
//! bundled Mozilla roots, or a CA certificate given on the command line for
//! a node with its own certificate.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, HOST, HeaderName, HeaderValue, IF_MATCH};
use hyper::{Method, Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

/// How long one request may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The largest response read.
const MAX_RESPONSE: usize = 16 * 1024 * 1024;

/// Why a request failed.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The API address is not an `http://` or `https://` URL with a host.
    #[error("{0:?} is not an http:// or https:// URL")]
    Url(String),
    /// The CA certificate could not be read.
    #[error("cannot read the CA certificate: {0}")]
    Ca(String),
    /// Connecting or talking to the API failed.
    #[error("cannot reach the API at {address}: {reason}")]
    Connect {
        /// Where.
        address: String,
        /// Why.
        reason: String,
    },
    /// The API answered with an error.
    #[error("{message} (HTTP {status})")]
    Api {
        /// The HTTP status.
        status: u16,
        /// The API's error code, if it sent one.
        code: String,
        /// The API's message.
        message: String,
    },
    /// The answer was not what was expected.
    #[error("unexpected answer from the API: {0}")]
    Decode(String),
    /// A header name or value that HTTP does not allow.
    #[error("invalid HTTP header {0:?}")]
    Header(String),
}

/// Connects to one goethite node's API.
#[derive(Clone)]
pub struct Client {
    host: String,
    port: u16,
    authority: String,
    tls: Option<(TlsConnector, ServerName<'static>)>,
    token: Option<String>,
    headers: Vec<(HeaderName, HeaderValue)>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("authority", &self.authority)
            .field("tls", &self.tls.is_some())
            .field("token", &self.token.as_ref().map(|_| "…"))
            .field(
                "headers",
                &self
                    .headers
                    .iter()
                    .map(|(name, _)| name.as_str())
                    .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A client for the API at `url`, such as `http://127.0.0.1:8053`.
    /// `token` is the admin token; `ca` a PEM CA certificate for HTTPS.
    ///
    /// # Errors
    ///
    /// [`ClientError::Url`] for an unusable URL, [`ClientError::Ca`] for an
    /// unreadable CA certificate.
    pub fn new(url: &str, token: Option<String>, ca: Option<&[u8]>) -> Result<Self, ClientError> {
        let uri: Uri = url.parse().map_err(|_| ClientError::Url(url.to_owned()))?;
        let https = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => false,
            _ => return Err(ClientError::Url(url.to_owned())),
        };
        let host = uri
            .host()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| ClientError::Url(url.to_owned()))?;
        let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
        let bare = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let authority = uri
            .authority()
            .map_or_else(|| host.to_owned(), |a| a.as_str().to_owned());
        let tls = if https {
            let mut roots = rustls::RootCertStore::empty();
            match ca {
                Some(pem) => {
                    use rustls::pki_types::pem::PemObject;
                    for cert in CertificateDer::pem_slice_iter(pem) {
                        let cert = cert.map_err(|err| ClientError::Ca(err.to_string()))?;
                        roots
                            .add(cert)
                            .map_err(|err| ClientError::Ca(err.to_string()))?;
                    }
                }
                None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
            }
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|err| ClientError::Ca(err.to_string()))?
                .with_root_certificates(roots)
                .with_no_client_auth();
            let name =
                ServerName::try_from(bare.clone()).map_err(|_| ClientError::Url(url.to_owned()))?;
            Some((TlsConnector::from(Arc::new(config)), name))
        } else {
            None
        };
        Ok(Self {
            host: bare,
            port,
            authority,
            tls,
            token,
            headers: Vec::new(),
        })
    }

    /// Sends `name: value` with every request, such as a session ID. The
    /// value is never printed.
    ///
    /// # Errors
    ///
    /// [`ClientError::Header`] for a name or value HTTP does not allow.
    pub fn with_header(mut self, name: &str, value: &str) -> Result<Self, ClientError> {
        let name = HeaderName::try_from(name).map_err(|_| ClientError::Header(name.to_owned()))?;
        let mut value =
            HeaderValue::try_from(value).map_err(|_| ClientError::Header(name.to_string()))?;
        value.set_sensitive(true);
        self.headers.push((name, value));
        Ok(self)
    }

    /// Where the client connects, for display.
    pub fn address(&self) -> &str {
        &self.authority
    }

    /// `GET`s `path` and decodes the JSON answer.
    ///
    /// # Errors
    ///
    /// A [`ClientError`].
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ClientError> {
        self.request::<(), T>(Method::GET, path, None, None).await
    }

    /// Sends `body` as JSON with `method` to `path` and decodes the answer.
    /// With `revision`, sends `If-Match`.
    ///
    /// # Errors
    ///
    /// A [`ClientError`].
    pub async fn send<B: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        revision: Option<u64>,
    ) -> Result<T, ClientError> {
        self.request(method, path, body, revision).await
    }

    /// Like [`Client::send`], for answers without a body (202, 204).
    ///
    /// # Errors
    ///
    /// A [`ClientError`].
    pub async fn send_empty<B: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<(), ClientError> {
        let (_, _) = self.exchange(method, path, body, None).await?;
        Ok(())
    }

    async fn request<B: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        revision: Option<u64>,
    ) -> Result<T, ClientError> {
        let (_, bytes) = self.exchange(method, path, body, revision).await?;
        serde_json::from_slice(&bytes).map_err(|err| ClientError::Decode(err.to_string()))
    }

    async fn exchange<B: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        revision: Option<u64>,
    ) -> Result<(StatusCode, Bytes), ClientError> {
        timeout(
            REQUEST_TIMEOUT,
            self.exchange_now(method, path, body, revision),
        )
        .await
        .map_err(|_| self.connect_error(&"timed out"))?
    }

    async fn exchange_now<B: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        revision: Option<u64>,
    ) -> Result<(StatusCode, Bytes), ClientError> {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(HOST, self.authority.as_str());
        if let Some(token) = &self.token {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        if let Some(revision) = revision {
            request = request.header(IF_MATCH, format!("\"{revision}\""));
        }
        for (name, value) in &self.headers {
            request = request.header(name, value);
        }
        let bytes = match body {
            Some(body) => {
                request = request.header(CONTENT_TYPE, "application/json");
                serde_json::to_vec(body).map_err(|err| ClientError::Decode(err.to_string()))?
            }
            None => Vec::new(),
        };
        let request = request
            .body(Full::new(Bytes::from(bytes)))
            .map_err(|err| ClientError::Decode(err.to_string()))?;
        let stream = TcpStream::connect((self.host.as_str(), self.port))
            .await
            .map_err(|err| self.connect_error(&err))?;
        let response = if let Some((connector, name)) = &self.tls {
            let stream = connector
                .connect(name.clone(), stream)
                .await
                .map_err(|err| self.connect_error(&err))?;
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream))
                    .await
                    .map_err(|err| self.connect_error(&err))?;
            tokio::spawn(connection);
            sender.send_request(request).await
        } else {
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream))
                    .await
                    .map_err(|err| self.connect_error(&err))?;
            tokio::spawn(connection);
            sender.send_request(request).await
        }
        .map_err(|err| self.connect_error(&err))?;
        let status = response.status();
        let body = Limited::new(response.into_body(), MAX_RESPONSE)
            .collect()
            .await
            .map_err(|err| self.connect_error(&err))?
            .to_bytes();
        if !status.is_success() {
            let error: Option<serde_json::Value> = serde_json::from_slice(&body).ok();
            let field = |name: &str| {
                error
                    .as_ref()
                    .and_then(|e| e.get("error"))
                    .and_then(|e| e.get(name))
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            };
            return Err(ClientError::Api {
                status: status.as_u16(),
                code: field("code").unwrap_or_default(),
                message: field("message")
                    .unwrap_or_else(|| status.canonical_reason().unwrap_or("error").to_owned()),
            });
        }
        Ok((status, body))
    }

    fn connect_error(&self, reason: &dyn std::fmt::Display) -> ClientError {
        ClientError::Connect {
            address: self.authority.clone(),
            reason: reason.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let plain = Client::new("http://127.0.0.1:8053", None, None).unwrap();
        assert_eq!(plain.address(), "127.0.0.1:8053");
        assert!(plain.tls.is_none());
        let secure = Client::new("https://dns.example.lan", Some("gth_x".into()), None).unwrap();
        assert_eq!(secure.port, 443);
        assert!(secure.tls.is_some());
        assert!(
            !format!("{secure:?}").contains("gth_x"),
            "the token is never printed"
        );
        let v6 = Client::new("http://[::1]:8053", None, None).unwrap();
        assert_eq!(v6.host, "::1");
        for bad in ["ftp://x", "127.0.0.1:8053", "http://", ""] {
            assert!(Client::new(bad, None, None).is_err(), "{bad}");
        }
        assert!(matches!(
            Client::new(
                "https://x",
                None,
                Some(b"-----BEGIN CERTIFICATE-----\nnope\n")
            ),
            Err(ClientError::Ca(_))
        ));
    }
}
