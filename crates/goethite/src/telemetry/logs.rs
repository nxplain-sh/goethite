//! Log records for the collector: with `[telemetry] logs`, the events at
//! `INFO` and above go to the collector as well as to standard error.
//!
//! The layer is part of the subscriber from the start, so every command has
//! it, but it sends nothing until `goethite run` has the resolver and
//! runtime the export needs and calls [`export_to`]. Until then it costs an
//! atomic load per event that passes its filter.

use std::sync::OnceLock;

use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_sdk::logs::{SdkLogger, SdkLoggerProvider};
use tracing::{Event, Subscriber};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

/// What turns events into log records, once there is a collector.
static BRIDGE: OnceLock<OpenTelemetryTracingBridge<SdkLoggerProvider, SdkLogger>> = OnceLock::new();

/// What is sent: `INFO` and above, whatever `RUST_LOG` lets through to
/// standard error, with the libraries kept as quiet as there. Never what the
/// export itself logs, which would feed it.
const SENT: &str = "info,hickory_proto=off,openraft=warn,opentelemetry=off,goethite::telemetry=off,\
                    hyper=off,h2=off";

/// The layer that sends events to the collector, once [`export_to`] names
/// one.
#[derive(Debug)]
pub(crate) struct LogExport;

impl<S> Layer<S> for LogExport
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        if let Some(bridge) = BRIDGE.get() {
            bridge.on_event(event, ctx);
        }
    }
}

/// The filter for [`LogExport`].
pub(crate) fn filter() -> EnvFilter {
    EnvFilter::new(SENT)
}

/// Sends events to `provider` from now on. Only the first call counts.
pub(crate) fn export_to(provider: &SdkLoggerProvider) {
    let _ = BRIDGE.set(OpenTelemetryTracingBridge::new(provider));
}
