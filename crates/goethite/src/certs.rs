//! The TLS certificates goethite serves with: the API's, and the one for
//! DNS over TLS and HTTPS.
//!
//! Each is held behind an [`ArcSwap`] that rustls asks at every handshake,
//! so `SIGHUP` can read renewed files and swap them in while connections go
//! on. A file that cannot be read or does not hold a matching certificate
//! and key leaves the certificate in use as it is.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use arc_swap::ArcSwap;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tracing::{info, warn};

use crate::secrets::CertAndKey;

/// A certificate and its key, replaceable while serving.
pub struct Served {
    /// What it is, for messages, such as "API certificate".
    what: &'static str,
    /// The files it was read from, to read again.
    files: Option<(PathBuf, PathBuf)>,
    provider: Arc<CryptoProvider>,
    current: ArcSwap<CertifiedKey>,
}

impl std::fmt::Debug for Served {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Served")
            .field("what", &self.what)
            .field("files", &self.files)
            .finish_non_exhaustive()
    }
}

impl Served {
    /// The certificate in `pem`, read from `files` (which [`Served::reload`]
    /// reads again).
    ///
    /// # Errors
    ///
    /// If `pem` holds no certificate, no key, or a key that does not fit.
    pub fn new(
        what: &'static str,
        pem: &CertAndKey,
        files: Option<(PathBuf, PathBuf)>,
    ) -> Result<Arc<Self>> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let key = certified_key(what, pem, &provider)?;
        Ok(Arc::new(Self {
            what,
            files,
            provider,
            current: ArcSwap::from_pointee(key),
        }))
    }

    /// TLS settings serving this certificate, offering `alpn`.
    ///
    /// # Errors
    ///
    /// Never in practice: ring supports the default protocol versions.
    pub fn server_config(self: &Arc<Self>, alpn: &[&[u8]]) -> Result<Arc<rustls::ServerConfig>> {
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(Arc::clone(self) as Arc<dyn ResolvesServerCert>);
        tls.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
        Ok(Arc::new(tls))
    }

    /// Reads the files again and serves what they hold from the next
    /// handshake on. Returns whether the certificate changed.
    ///
    /// # Errors
    ///
    /// If the files cannot be read or do not hold a matching certificate
    /// and key; the certificate in use stays.
    pub fn reload(&self) -> Result<bool> {
        let Some((cert, key)) = &self.files else {
            return Ok(false);
        };
        let read = |path: &PathBuf| {
            std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))
        };
        let pem = CertAndKey {
            cert: read(cert)?,
            key: read(key)?,
        };
        let fresh = certified_key(self.what, &pem, &self.provider)?;
        if fresh.cert == self.current.load().cert {
            return Ok(false);
        }
        self.current.store(Arc::new(fresh));
        Ok(true)
    }

    /// [`Served::reload`], logged.
    pub fn reload_and_log(&self) {
        match self.reload() {
            Ok(true) => info!("serving the renewed {}", self.what),
            Ok(false) => {}
            Err(err) => warn!("{err:#}; still serving the {} in use", self.what),
        }
    }
}

impl ResolvesServerCert for Served {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.load_full())
    }
}

/// The certificate chain and key in `pem`, checked to fit together.
fn certified_key(what: &str, pem: &CertAndKey, provider: &CryptoProvider) -> Result<CertifiedKey> {
    let chain = CertificateDer::pem_slice_iter(pem.cert.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("cannot read the {what}"))?;
    if chain.is_empty() {
        bail!("the {what} holds no certificate");
    }
    let key = PrivateKeyDer::from_pem_slice(pem.key.as_bytes())
        .with_context(|| format!("cannot read the key of the {what}"))?;
    CertifiedKey::from_der(chain, key, provider)
        .with_context(|| format!("the {what} and its key do not fit together"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pem(name: &str) -> CertAndKey {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec![name.to_owned()]).unwrap();
        CertAndKey {
            cert: cert.pem(),
            key: signing_key.serialize_pem(),
        }
    }

    #[test]
    fn reloads_renewed_files_and_keeps_bad_ones_out() {
        let dir = std::env::temp_dir().join(format!("goethite-certs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert, key) = (dir.join("dns.crt"), dir.join("dns.key"));
        let first = pem("dns.example");
        std::fs::write(&cert, &first.cert).unwrap();
        std::fs::write(&key, &first.key).unwrap();
        let served =
            Served::new("DNS certificate", &first, Some((cert.clone(), key.clone()))).unwrap();
        served.server_config(&[b"dot"]).unwrap();
        assert!(!served.reload().unwrap(), "nothing changed");

        let renewed = pem("dns.example");
        std::fs::write(&cert, &renewed.cert).unwrap();
        std::fs::write(&key, &renewed.key).unwrap();
        assert!(served.reload().unwrap());
        let in_use = served.current.load_full();

        // A key that belongs to another certificate is refused.
        std::fs::write(&key, pem("other.example").key).unwrap();
        let err = served.reload().unwrap_err();
        assert!(format!("{err:#}").contains("do not fit"), "{err:#}");
        std::fs::write(&cert, "not PEM").unwrap();
        assert!(served.reload().is_err());
        std::fs::remove_file(&cert).unwrap();
        assert!(served.reload().is_err());
        assert!(Arc::ptr_eq(&in_use, &served.current.load_full()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn refuses_what_is_not_a_certificate() {
        let good = pem("dns.example");
        let no_cert = CertAndKey {
            cert: String::new(),
            key: good.key.clone(),
        };
        assert!(Served::new("x", &no_cert, None).is_err());
        let no_key = CertAndKey {
            cert: good.cert,
            key: String::new(),
        };
        assert!(Served::new("x", &no_key, None).is_err());
    }
}
