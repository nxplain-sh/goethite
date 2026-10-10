//! Sending telemetry to an OpenTelemetry collector over OTLP/HTTP.
//!
//! The SDK's exporters run on their own threads. Each request they make runs
//! as a task on goethite's runtime, which the exporter's thread waits for, so
//! a slow or missing collector never holds up a DNS worker. Requests go
//! through goethite's own client ([`Connection`]): names resolved by
//! goethite's resolver, rustls with ring.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use goethite_resolver::{Resolver, TlsRoots, tls_client_config};
use http_body_util::{BodyExt, Full, Limited};
use hyper::header::{HeaderName, HeaderValue};
use opentelemetry_http::{Bytes, HttpClient, HttpError, Request, Response};
use opentelemetry_otlp::{MetricExporter, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::metrics::PeriodicReader;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use tokio::runtime::Handle;
use tokio_rustls::TlsConnector;
use tracing::{info, warn};

use crate::config::TelemetrySection;
use crate::connect::Connection;
use crate::secrets::Secrets;

/// How long one export may take, retries included.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(10);

/// Longer answers from the collector are not read.
const MAX_RESPONSE_LEN: usize = 64 * 1024;

/// More headers than this are refused.
const MAX_HEADERS: usize = 16;

/// How the requests for one signal fare.
#[derive(Debug, Default)]
pub(crate) struct Exports {
    /// Requests that failed, retries included.
    failed: AtomicU64,
    /// Whether the last request failed.
    failing: AtomicBool,
}

impl Exports {
    /// Requests that failed, retries included.
    pub(crate) fn failed(&self) -> u64 {
        self.failed.load(Ordering::Relaxed)
    }

    /// Counts a request for `signal`, and logs when requests start failing
    /// and when they succeed again: once each, not on every retry.
    fn record(&self, signal: &str, result: &Result<Response<Bytes>>) {
        let problem = match result {
            Ok(response) if response.status().is_success() => None,
            Ok(response) => Some(format!("HTTP status {}", response.status())),
            Err(err) => Some(format!("{err:#}")),
        };
        match problem {
            Some(problem) => {
                self.failed.fetch_add(1, Ordering::Relaxed);
                if !self.failing.swap(true, Ordering::Relaxed) {
                    warn!(
                        signal,
                        %problem,
                        "cannot send telemetry to the collector; trying again at the next export"
                    );
                }
            }
            None => {
                if self.failing.swap(false, Ordering::Relaxed) {
                    info!(signal, "telemetry reaches the collector again");
                }
            }
        }
    }
}

/// How the requests fare, by signal.
#[derive(Debug, Default)]
pub(crate) struct ExportFailures {
    /// Metric exports.
    pub metrics: Arc<Exports>,
}

/// Posts OTLP requests for one signal through goethite's own HTTP client.
#[derive(Clone)]
struct OtlpClient {
    signal: &'static str,
    resolver: Arc<Resolver>,
    tls: TlsConnector,
    runtime: Handle,
    exports: Arc<Exports>,
}

impl std::fmt::Debug for OtlpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtlpClient").finish_non_exhaustive()
    }
}

impl OtlpClient {
    async fn post(&self, request: Request<Bytes>) -> Result<Response<Bytes>> {
        let (parts, body) = request.into_parts();
        let mut connection =
            Connection::<Full<Bytes>>::open(&self.resolver, &self.tls, &parts.uri).await?;
        let mut builder = connection.request(parts.method, &parts.uri)?;
        for (name, value) in &parts.headers {
            builder = builder.header(name, value);
        }
        let response = connection.send(builder.body(Full::new(body))?).await?;
        let (parts, body) = response.into_parts();
        let body = Limited::new(body, MAX_RESPONSE_LEN)
            .collect()
            .await
            .map_err(|err| anyhow!("cannot read the collector's answer: {err}"))?
            .to_bytes();
        Ok(Response::from_parts(parts, body))
    }
}

impl HttpClient for OtlpClient {
    fn send_bytes<'client, 'call>(
        &'client self,
        request: Request<Bytes>,
    ) -> Pin<Box<dyn Future<Output = Result<Response<Bytes>, HttpError>> + Send + 'call>>
    where
        'client: 'call,
        Self: 'call,
    {
        let client = self.clone();
        Box::pin(async move {
            let (signal, exports) = (client.signal, Arc::clone(&client.exports));
            let task = client.runtime.clone().spawn(async move {
                tokio::time::timeout(EXPORT_TIMEOUT, client.post(request))
                    .await
                    .map_err(|_| anyhow!("timed out after {} s", EXPORT_TIMEOUT.as_secs()))?
            });
            let result = match task.await {
                Ok(result) => result,
                Err(err) => Err(anyhow!("the export was cancelled: {err}")),
            };
            exports.record(signal, &result);
            result.map_err(|err| HttpError::from(format!("{err:#}")))
        })
    }
}

/// A reader that sends the metrics to the collector every
/// `telemetry.interval`, if an endpoint is configured and metrics are on.
///
/// # Errors
///
/// If the headers or the CA are unusable, or the exporter cannot be built.
pub(crate) fn metrics_reader(
    config: &TelemetrySection,
    secrets: &Secrets,
    resolver: &Arc<Resolver>,
    failures: &ExportFailures,
) -> Result<Option<PeriodicReader<MetricExporter>>> {
    let Some(url) = config.signal_url("metrics").filter(|_| config.metrics) else {
        return Ok(None);
    };
    let client = OtlpClient {
        signal: "metrics",
        resolver: Arc::clone(resolver),
        tls: TlsConnector::from(tls_client_config(
            &roots(secrets.telemetry_ca.as_deref())?,
            &[b"h2", b"http/1.1"],
        )?),
        runtime: Handle::current(),
        exports: Arc::clone(&failures.metrics),
    };
    let exporter = MetricExporter::builder()
        .with_http()
        .with_http_client(client)
        .with_endpoint(url.clone())
        .with_headers(headers(secrets.telemetry_headers.as_deref().unwrap_or(""))?)
        .with_timeout(EXPORT_TIMEOUT)
        .build()
        .context("cannot set up the metrics export")?;
    if let Ok(Some(endpoint)) = config.endpoint()
        && endpoint.scheme_str() == Some("http")
        && !endpoint.host().is_some_and(is_loopback)
    {
        warn!("telemetry goes to the collector over plain HTTP: it and its headers can be read");
    }
    info!(%url, interval = config.interval, "sending metrics over OTLP");
    Ok(Some(
        PeriodicReader::builder(exporter)
            .with_interval(Duration::from_secs(config.interval))
            .build(),
    ))
}

fn is_loopback(host: &str) -> bool {
    host == "localhost"
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// The headers in a `telemetry.headers_file`: `Name: value` lines, with
/// blank lines and `#` comments skipped. Errors never quote a value.
///
/// # Errors
///
/// If a line is not a valid header, or there are more than
/// [`MAX_HEADERS`].
pub(crate) fn headers(text: &str) -> Result<HashMap<String, String>> {
    let mut headers = HashMap::new();
    for (index, line) in text.lines().enumerate() {
        let number = index.saturating_add(1);
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .with_context(|| format!("telemetry headers, line {number}: not \"Name: value\""))?;
        let (name, value) = (name.trim(), value.trim());
        HeaderName::from_bytes(name.as_bytes())
            .with_context(|| format!("telemetry headers, line {number}: invalid header name"))?;
        HeaderValue::from_str(value)
            .with_context(|| format!("telemetry headers, line {number}: invalid value"))?;
        headers.insert(name.to_ascii_lowercase(), value.to_owned());
        if headers.len() > MAX_HEADERS {
            bail!("telemetry headers: more than {MAX_HEADERS}");
        }
    }
    Ok(headers)
}

/// The CA certificates to verify the collector with: the ones in
/// `telemetry.ca_file`, or the public roots.
///
/// # Errors
///
/// If the file holds no certificate, or one that cannot be parsed.
pub(crate) fn roots(ca: Option<&str>) -> Result<TlsRoots> {
    let Some(pem) = ca else {
        return Ok(TlsRoots::Bundled);
    };
    let certificates = CertificateDer::pem_slice_iter(pem.as_bytes())
        .map(|certificate| certificate.map(|der| der.to_vec()))
        .collect::<Result<Vec<_>, _>>()
        .context("telemetry.ca_file holds an invalid certificate")?;
    if certificates.is_empty() {
        bail!("telemetry.ca_file holds no certificate");
    }
    Ok(TlsRoots::Custom(certificates))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_headers() {
        let parsed = headers(
            "# the vendor's key\nAuthorization: Bearer abc\n\n  X-Scope-OrgID :tenant-1  \n",
        )
        .unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed["authorization"], "Bearer abc");
        assert_eq!(parsed["x-scope-orgid"], "tenant-1");
        assert!(headers("").unwrap().is_empty());

        for (bad, expected) in [
            ("no colon here", "line 1: not \"Name: value\""),
            ("bad name: x", "line 1: invalid header name"),
            ("\nok: \u{7f}secret", "line 2: invalid value"),
        ] {
            let err = format!("{:#}", headers(bad).unwrap_err());
            assert!(err.contains(expected), "{bad:?}: {err}");
            assert!(!err.contains("secret"), "{err}");
        }
        let many = (0..=MAX_HEADERS)
            .map(|i| format!("h{i}: v"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(headers(&many).is_err());
    }

    #[test]
    fn reads_roots() {
        assert!(matches!(roots(None).unwrap(), TlsRoots::Bundled));
        assert!(roots(Some("not PEM")).is_err());
        let ca = rcgen::generate_simple_self_signed(vec!["collector.example".into()]).unwrap();
        let roots = roots(Some(&ca.cert.pem())).unwrap();
        assert!(matches!(roots, TlsRoots::Custom(certificates) if certificates.len() == 1));
    }
}
