//! Talking to another member over the cluster channel.
//!
//! One connection per request: TLS 1.3 with session resumption is cheap,
//! and nothing stays open to go stale. Every request is bounded in time and
//! in response size.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use goethite_store::StatsReport;
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
use crate::raft::Member;
use crate::wire::{NODE_PATH, NodeInfo, STATS_PATH, WireError};

/// How long connecting, the TLS handshake and an answer without waiting
/// may take.
const TIMEOUT: Duration = Duration::from_secs(10);

/// The largest answer read.
const MAX_RESPONSE: usize = 16 * 1024 * 1024;

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

/// Another member, as seen from this node.
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

    /// A client for `member`, as Raft records it.
    ///
    /// # Errors
    ///
    /// Why its name or address cannot be used.
    pub fn for_member(member: &Member, tls: Arc<ClientConfig>) -> Result<Self, String> {
        let node = member.node().map_err(|err| err.to_string())?;
        let address = member
            .address
            .parse()
            .map_err(|_| format!("{} has no valid address: {:?}", node, member.address))?;
        Self::new(node, address, tls).map_err(|err| err.to_string())
    }

    /// The peer's name.
    pub fn peer(&self) -> &NodeId {
        &self.peer
    }

    /// The peer's address.
    pub fn address(&self) -> SocketAddr {
        self.address
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

    /// The peer's statistics for the last `hours` hours, with long top
    /// lists for merging.
    ///
    /// # Errors
    ///
    /// A [`ClientError`].
    pub async fn stats(&self, hours: u32) -> Result<StatsReport, ClientError> {
        let (_, body) = self
            .get(&format!("{STATS_PATH}?hours={hours}"), TIMEOUT)
            .await?;
        self.decode(&body)
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
        self.post_within(path, body, TIMEOUT).await
    }

    /// Sends `body` as JSON to `path` and decodes the JSON answer, all
    /// within `limit`.
    ///
    /// # Errors
    ///
    /// A [`ClientError`].
    pub async fn post_within<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        limit: Duration,
    ) -> Result<T, ClientError> {
        let bytes = serde_json::to_vec(body).map_err(|err| ClientError::Decode {
            peer: self.peer.clone(),
            reason: err.to_string(),
        })?;
        let (_, answer) = self
            .send(Method::POST, path, Some(Bytes::from(bytes)), limit)
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
