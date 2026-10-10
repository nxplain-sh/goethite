//! Keys and certificates read from files: the API's TLS certificate, the
//! one for DNS over TLS and HTTPS, the cluster's, and what goethite sends
//! telemetry with (the collector's headers and CA).
//!
//! They are read before privileges are dropped, so the files may be
//! readable by root only, and kept in memory: on an upgrade, the new
//! goethite runs without privileges and receives them from the old one
//! (unless it can read the files itself, which picks up renewed
//! certificates).

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::config::Config;

/// The PEM text of a certificate and its key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CertAndKey {
    /// The certificate chain.
    pub cert: String,
    /// The private key.
    pub key: String,
}

/// The cluster's CA, and this node's certificate and key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ClusterPem {
    /// The cluster CA's certificate.
    pub ca: String,
    /// This node's certificate and key.
    pub node: CertAndKey,
}

/// Every key and certificate the node uses.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Secrets {
    /// The API's TLS certificate, if it serves HTTPS.
    pub api_tls: Option<CertAndKey>,
    /// The certificate for DNS over TLS and HTTPS, if they are served.
    #[serde(default)]
    pub dns_tls: Option<CertAndKey>,
    /// The cluster's certificates, if the node is in a cluster.
    pub cluster: Option<ClusterPem>,
    /// The headers sent to the telemetry collector (`telemetry.headers_file`).
    #[serde(default)]
    pub telemetry_headers: Option<String>,
    /// The CA certificates for the telemetry collector (`telemetry.ca_file`).
    #[serde(default)]
    pub telemetry_ca: Option<String>,
}

/// Larger telemetry header files are refused: they hold a few short lines.
const MAX_HEADERS_FILE_LEN: usize = 8 * 1024;

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secrets")
            .field("api_tls", &self.api_tls.is_some())
            .field("dns_tls", &self.dns_tls.is_some())
            .field("cluster", &self.cluster.is_some())
            .field("telemetry_headers", &self.telemetry_headers.is_some())
            .field("telemetry_ca", &self.telemetry_ca.is_some())
            .finish()
    }
}

fn read(path: &Path, what: &str) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("cannot read {what} {}", path.display()))
}

impl Secrets {
    /// Reads every file the config file names.
    ///
    /// # Errors
    ///
    /// If one cannot be read.
    pub(crate) fn read(config: &Config) -> Result<Self> {
        let api_tls = match (&config.api.tls_cert, &config.api.tls_key) {
            (Some(cert), Some(key)) if config.api.enabled => Some(CertAndKey {
                cert: read(cert, "the API certificate")?,
                key: read(key, "the API key")?,
            }),
            _ => None,
        };
        let dns_tls = match &config.server.tls {
            Some(tls) => Some(CertAndKey {
                cert: read(&tls.cert, "the DNS certificate")?,
                key: read(&tls.key, "the DNS key")?,
            }),
            None => None,
        };
        let cluster = match &config.cluster {
            Some(cluster) => Some(ClusterPem {
                ca: read(&cluster.ca, "the cluster CA")?,
                node: CertAndKey {
                    cert: read(&cluster.cert, "the node certificate")?,
                    key: read(&cluster.key, "the node key")?,
                },
            }),
            None => None,
        };
        let telemetry = &config.telemetry;
        let telemetry_headers = match &telemetry.headers_file {
            Some(path) if telemetry.endpoint.is_some() => {
                let text = read(path, "the telemetry headers")?;
                if text.len() > MAX_HEADERS_FILE_LEN {
                    anyhow::bail!(
                        "{} is larger than {MAX_HEADERS_FILE_LEN} bytes",
                        path.display()
                    );
                }
                Some(text)
            }
            _ => None,
        };
        let telemetry_ca = match &telemetry.ca_file {
            Some(path) if telemetry.endpoint.is_some() => Some(read(path, "the telemetry CA")?),
            _ => None,
        };
        Ok(Self {
            api_tls,
            dns_tls,
            cluster,
            telemetry_headers,
            telemetry_ca,
        })
    }

    /// Reads the files if this process can (picking up renewed
    /// certificates), and otherwise keeps `handed_over`, from the goethite
    /// this one takes over from.
    pub(crate) fn read_or(config: &Config, handed_over: Self) -> Self {
        match Self::read(config) {
            Ok(fresh) => fresh,
            Err(err) => {
                info!(
                    "{err:#}; using the keys the previous goethite handed over (renewed \
                     certificates take effect on a restart)"
                );
                handed_over
            }
        }
    }
}
