//! Mutual TLS between the nodes of a cluster.
//!
//! Each node presents its certificate in both directions and accepts only
//! certificates signed by the cluster's CA that name the expected peer: the
//! replica checks it reached the primary, and the primary checks the replica
//! is the configured one. Only TLS 1.3 is offered, since both ends are
//! goethite.

use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ParsedCertificate, WebPkiClientVerifier};
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, RootCertStore, ServerConfig,
    SignatureScheme,
};

use crate::node::NodeId;

/// The ALPN protocol both ends speak: HTTP/1.1 inside the tunnel.
const ALPN: &[u8] = b"http/1.1";

/// Why a node's TLS identity cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// A PEM file holds no usable certificate or key.
    #[error("{what}: {reason}")]
    Pem {
        /// Which file.
        what: &'static str,
        /// Why.
        reason: String,
    },
    /// The certificate does not belong to this cluster or this node, or
    /// does not match the key.
    #[error("the node certificate is not valid for {node}: {reason}")]
    NotValid {
        /// The node.
        node: NodeId,
        /// Why.
        reason: String,
    },
    /// rustls refused the configuration.
    #[error("TLS: {0}")]
    Rustls(#[from] rustls::Error),
}

/// A node's certificate and key, and the cluster CA to check peers with.
pub struct Identity {
    node: NodeId,
    roots: Arc<RootCertStore>,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    provider: Arc<CryptoProvider>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("node", &self.node)
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// The identity of `node` from PEM: the cluster CA, the node's
    /// certificate and its key. Checks that the certificate is signed by the
    /// CA, names `node` and matches the key.
    ///
    /// # Errors
    ///
    /// [`TlsError`] saying which part is wrong.
    pub fn from_pem(node: NodeId, ca: &[u8], cert: &[u8], key: &[u8]) -> Result<Self, TlsError> {
        let mut roots = RootCertStore::empty();
        for der in CertificateDer::pem_slice_iter(ca) {
            let der = der.map_err(|err| pem_error("the cluster CA", &err))?;
            roots
                .add(der)
                .map_err(|err| pem_error("the cluster CA", &err))?;
        }
        if roots.is_empty() {
            return Err(TlsError::Pem {
                what: "the cluster CA",
                reason: "no certificate in it".into(),
            });
        }
        let chain = CertificateDer::pem_slice_iter(cert)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| pem_error("the node certificate", &err))?;
        if chain.is_empty() {
            return Err(TlsError::Pem {
                what: "the node certificate",
                reason: "no certificate in it".into(),
            });
        }
        let key =
            PrivateKeyDer::from_pem_slice(key).map_err(|err| pem_error("the node key", &err))?;
        let identity = Self {
            node,
            roots: Arc::new(roots),
            chain,
            key,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        };
        identity.check()?;
        Ok(identity)
    }

    /// This node's name.
    pub fn node(&self) -> &NodeId {
        &self.node
    }

    /// Checks the certificate against the CA and this node's name, and
    /// against the key by building a server configuration with them.
    fn check(&self) -> Result<(), TlsError> {
        let not_valid = |reason: String| TlsError::NotValid {
            node: self.node.clone(),
            reason,
        };
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::clone(&self.roots),
            Arc::clone(&self.provider),
        )
        .build()
        .map_err(|err| not_valid(err.to_string()))?;
        let (end_entity, intermediates) = self
            .chain
            .split_first()
            .ok_or_else(|| not_valid("no certificate".into()))?;
        let name = self
            .node
            .server_name()
            .map_err(|err| not_valid(err.to_string()))?;
        verifier
            .verify_server_cert(end_entity, intermediates, &name, &[], UnixTime::now())
            .map_err(|err| not_valid(err.to_string()))?;
        self.server_config(&self.node)
            .map_err(|err| not_valid(err.to_string()))?;
        Ok(())
    }

    /// The configuration for this node's cluster listener, accepting only
    /// `peer`.
    ///
    /// # Errors
    ///
    /// [`TlsError`] if rustls refuses it.
    pub fn server_config(&self, peer: &NodeId) -> Result<Arc<ServerConfig>, TlsError> {
        let inner = WebPkiClientVerifier::builder_with_provider(
            Arc::clone(&self.roots),
            Arc::clone(&self.provider),
        )
        .build()
        .map_err(|err| rustls::Error::General(err.to_string()))?;
        let peer_name = peer
            .server_name()
            .map_err(|err| rustls::Error::General(err.to_string()))?;
        let mut config = ServerConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(Arc::new(PeerVerifier {
                inner,
                peer: peer_name,
            }))
            .with_single_cert(self.chain.clone(), self.key.clone_key())?;
        config.alpn_protocols = vec![ALPN.to_vec()];
        Ok(Arc::new(config))
    }

    /// The configuration for connecting to a peer: the peer's name is
    /// checked against its certificate when connecting.
    ///
    /// # Errors
    ///
    /// [`TlsError`] if rustls refuses it.
    pub fn client_config(&self) -> Result<Arc<ClientConfig>, TlsError> {
        let mut config = ClientConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(Arc::clone(&self.roots))
            .with_client_auth_cert(self.chain.clone(), self.key.clone_key())?;
        config.alpn_protocols = vec![ALPN.to_vec()];
        Ok(Arc::new(config))
    }
}

fn pem_error(what: &'static str, err: &dyn std::fmt::Display) -> TlsError {
    TlsError::Pem {
        what,
        reason: err.to_string(),
    }
}

/// Accepts a client certificate only if it is signed by the cluster CA and
/// names the expected peer.
#[derive(Debug)]
struct PeerVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    peer: ServerName<'static>,
}

impl ClientCertVerifier for PeerVerifier {
    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.inner
            .verify_client_cert(end_entity, intermediates, now)?;
        let parsed = ParsedCertificate::try_from(end_entity)?;
        rustls::client::verify_server_name(&parsed, &self.peer)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
