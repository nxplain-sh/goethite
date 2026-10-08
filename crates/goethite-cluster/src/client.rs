//! Talking to the peer over the cluster channel.
//!
//! One connection per request: a replica asks for the configuration about
//! once a minute (a long poll), so there is little to gain from keeping
//! connections. Every request is bounded in time and in response size.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use goethite_store::{ConfigExport, ConfigVersion};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::header::CONTENT_TYPE;
use hyper::header::HOST;
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::node::NodeId;
use crate::wire::{CONFIG_PATH, ConfigQuery, MAX_WAIT_SECS, NODE_PATH, NodeInfo, WireError};

/// How long connecting, the TLS handshake and an answer without waiting
/// may take.
const TIMEOUT: Duration = Duration::from_secs(10);

/// The largest answer read: a configuration with a million custom rules.
const MAX_RESPONSE: usize = 256 * 1024 * 1024;

/// Why a request to the peer failed.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The peer could not be reached, or the connection failed.
    #[error("cannot reach {peer} at {address}: {reason}")]
    Connect {
        /// The peer.
        peer: NodeId,
        /// Its address.
        address: SocketAddr,
        /// Why.
        reason: String,
    },
    /// The peer answered with an error.
    #[error("{peer} answered {status}: {message}")]
    Peer {
        /// The peer.
        peer: NodeId,
        /// The HTTP status.
        status: u16,
        /// The error code, such as `not_primary`.
        code: String,
        /// The message.
        message: String,
    },
    /// The answer could not be read.
    #[error("unexpected answer from {peer}: {reason}")]
    Decode {
        /// The peer.
        peer: NodeId,
        /// Why.
        reason: String,
    },
}

/// The peer, as seen from this node.
#[derive(Clone)]
pub struct PeerClient {
    peer: NodeId,
    address: SocketAddr,
    name: ServerName<'static>,
    connector: TlsConnector,
}

impl std::fmt::Debug for PeerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerClient")
            .field("peer", &self.peer)
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl PeerClient {
    /// A client for `peer` at `address`, with this node's
    /// [`crate::Identity::client_config`].
    ///
    /// # Errors
    ///
    /// Never for a valid node name; the error is rustls's.
    pub fn new(
        peer: NodeId,
        address: SocketAddr,
        tls: Arc<ClientConfig>,
    ) -> Result<Self, rustls::pki_types::InvalidDnsNameError> {
        let name = peer.server_name()?;
        Ok(Self {
            peer,
            address,
            name,
            connector: TlsConnector::from(tls),
        })
    }

    /// The peer's name.
    pub fn peer(&self) -> &NodeId {
        &self.peer
    }

    /// About the peer.
    ///
    /// # Errors
    ///
    /// A [`ClientError`].
    pub async fn node(&self) -> Result<NodeInfo, ClientError> {
        let (_, body) = self.get(NODE_PATH, TIMEOUT).await?;
        self.decode(&body)
    }

    /// The peer's configuration once it is newer than `have`, waiting up
    /// to `wait` seconds for a change; `None` if nothing changed in that
    /// time.
    ///
    /// # Errors
    ///
    /// A [`ClientError`], such as `not_primary` if the peer is not the
    /// primary.
    pub async fn config(
        &self,
        have: ConfigVersion,
        wait: u64,
    ) -> Result<Option<ConfigExport>, ClientError> {
        let wait = wait.min(MAX_WAIT_SECS);
        let path = format!(
            "{CONFIG_PATH}?{}",
            ConfigQuery::new(have, wait).to_query_string()
        );
        let limit = TIMEOUT.saturating_add(Duration::from_secs(wait));
        let (status, body) = self.get(&path, limit).await?;
        if status == StatusCode::NO_CONTENT {
            return Ok(None);
        }
        self.decode(&body).map(Some)
    }

    /// Sends `body` as JSON to `path` and decodes the JSON answer.
    ///
    /// # Errors
    ///
    /// A [`ClientError`].
    pub async fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ClientError> {
        let bytes = serde_json::to_vec(body).map_err(|err| ClientError::Decode {
            peer: self.peer.clone(),
            reason: err.to_string(),
        })?;
        let (_, answer) = self
            .send(Method::POST, path, Some(Bytes::from(bytes)), TIMEOUT)
            .await?;
        self.decode(&answer)
    }

    async fn get(&self, path: &str, limit: Duration) -> Result<(StatusCode, Bytes), ClientError> {
        self.send(Method::GET, path, None, limit).await
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<Bytes>,
        limit: Duration,
    ) -> Result<(StatusCode, Bytes), ClientError> {
        let (status, body) = timeout(limit, self.exchange(method, path, body))
            .await
            .map_err(|_| self.connect_error("timed out"))??;
        if status.is_success() {
            return Ok((status, body));
        }
        let error: Option<WireError> = serde_json::from_slice(&body).ok();
        Err(ClientError::Peer {
            peer: self.peer.clone(),
            status: status.as_u16(),
            code: error.as_ref().map_or_else(String::new, |e| e.code.clone()),
            message: error.map_or_else(
                || status.canonical_reason().unwrap_or("error").to_owned(),
                |e| e.message,
            ),
        })
    }

    async fn exchange(
        &self,
        method: Method,
        path: &str,
        body: Option<Bytes>,
    ) -> Result<(StatusCode, Bytes), ClientError> {
        let stream = timeout(TIMEOUT, TcpStream::connect(self.address))
            .await
            .map_err(|_| self.connect_error("connecting timed out"))?
            .map_err(|err| self.connect_error(err))?;
        let stream = timeout(TIMEOUT, self.connector.connect(self.name.clone(), stream))
            .await
            .map_err(|_| self.connect_error("the TLS handshake timed out"))?
            .map_err(|err| self.connect_error(err))?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|err| self.connect_error(err))?;
        tokio::spawn(connection);
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(HOST, self.peer.cert_name());
        if body.is_some() {
            request = request.header(CONTENT_TYPE, "application/json");
        }
        let request = request
            .body(Full::new(body.unwrap_or_default()))
            .map_err(|err| self.connect_error(err))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|err| self.connect_error(err))?;
        let status = response.status();
        let body = Limited::new(response.into_body(), MAX_RESPONSE)
            .collect()
            .await
            .map_err(|err| self.connect_error(err))?
            .to_bytes();
        Ok((status, body))
    }

    fn decode<T: DeserializeOwned>(&self, body: &[u8]) -> Result<T, ClientError> {
        serde_json::from_slice(body).map_err(|err| ClientError::Decode {
            peer: self.peer.clone(),
            reason: err.to_string(),
        })
    }

    fn connect_error(&self, reason: impl std::fmt::Display) -> ClientError {
        ClientError::Connect {
            peer: self.peer.clone(),
            address: self.address,
            reason: reason.to_string(),
        }
    }
}
