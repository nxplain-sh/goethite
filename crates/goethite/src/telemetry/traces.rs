//! Spans for the collector: with `[telemetry] traces`, the spans goethite
//! opens on its slow paths (forwarding, recursion, DNSSEC, list downloads,
//! the cluster, API requests) go to the collector as traces, a sampled share
//! of them.
//!
//! The layer is part of the subscriber from the start, but takes no span
//! until `goethite run` has the resolver and runtime the export needs and
//! calls [`export_to`]. Until then, or with traces off, a span costs an
//! atomic load, and events never reach the layer. The span processor and the
//! sampler wait for the configuration the same way, so the export thread
//! starts after the sandbox.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use opentelemetry::trace::{Link, SpanKind, TraceId, TraceState, TracerProvider as _};
use opentelemetry::{Context, KeyValue};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::trace::{
    BatchSpanProcessor, Sampler, SamplingDecision, SamplingResult, SdkTracerProvider, ShouldSample,
    Span, SpanData, SpanProcessor,
};
use tracing::Subscriber;
use tracing::level_filters::LevelFilter;
use tracing::subscriber::Interest;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::DynFilterFn;
use tracing_subscriber::registry::LookupSpan;

/// Whether spans are taken: set once the export is.
static ON: AtomicBool = AtomicBool::new(false);
/// The provider the layer's tracer comes from, made with the subscriber.
static PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();
/// What sends the finished spans, once there is a collector.
static PROCESSOR: OnceLock<BatchSpanProcessor> = OnceLock::new();
/// Which traces are kept, once there is a collector.
static SAMPLER: OnceLock<Sampler> = OnceLock::new();

/// The layer that turns goethite's spans into traces for the collector.
pub(crate) fn layer<S>() -> impl Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    let provider = PROVIDER.get_or_init(|| {
        SdkTracerProvider::builder()
            .with_span_processor(LateProcessor)
            .with_sampler(LateSampler)
            .build()
    });
    // Spans only, goethite's own (not openraft's), at DEBUG and above; and
    // only once traces are on. Events never reach the layer, so the trace!
    // on every query stays a callsite that is never enabled.
    let filter = DynFilterFn::new(|metadata, _| ON.load(Ordering::Relaxed) && takes(metadata))
        .with_callsite_filter(|metadata| {
            if takes(metadata) {
                Interest::sometimes()
            } else {
                Interest::never()
            }
        })
        .with_max_level_hint(LevelFilter::DEBUG);
    tracing_opentelemetry::layer()
        .with_tracer(provider.tracer("goethite"))
        .with_filter(filter)
}

fn takes(metadata: &tracing::Metadata<'_>) -> bool {
    metadata.is_span()
        && metadata.target().starts_with("goethite")
        && *metadata.level() <= tracing::Level::DEBUG
}

/// Sends the spans through `processor` from now on, keeping a share
/// `ratio` (0 to 1) of the traces that start in goethite. Only the first
/// call counts.
pub(crate) fn export_to(mut processor: BatchSpanProcessor, ratio: f64, resource: &Resource) {
    processor.set_resource(resource);
    let sampler = Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(ratio)));
    if SAMPLER.set(sampler).is_ok() && PROCESSOR.set(processor).is_ok() {
        ON.store(true, Ordering::Relaxed);
    }
}

/// Sends what is left. Blocks until that is done or has timed out.
pub(crate) fn shutdown() -> OTelSdkResult {
    ON.store(false, Ordering::Relaxed);
    PROCESSOR.get().map_or(Ok(()), SpanProcessor::shutdown)
}

/// The processor the provider is made with, before there is a collector:
/// it hands spans to [`PROCESSOR`] once that is set.
#[derive(Debug)]
struct LateProcessor;

impl SpanProcessor for LateProcessor {
    fn on_start(&self, span: &mut Span, cx: &Context) {
        if let Some(processor) = PROCESSOR.get() {
            processor.on_start(span, cx);
        }
    }

    fn on_end(&self, span: SpanData) {
        if let Some(processor) = PROCESSOR.get() {
            processor.on_end(span);
        }
    }

    fn force_flush(&self) -> OTelSdkResult {
        PROCESSOR.get().map_or(Ok(()), SpanProcessor::force_flush)
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        PROCESSOR
            .get()
            .map_or(Ok(()), |processor| processor.shutdown_with_timeout(timeout))
    }
}

/// The sampler the provider is made with: [`SAMPLER`] once it is set, and
/// nothing kept before.
#[derive(Clone, Debug)]
struct LateSampler;

impl ShouldSample for LateSampler {
    fn should_sample(
        &self,
        parent_context: Option<&Context>,
        trace_id: TraceId,
        name: &str,
        span_kind: &SpanKind,
        attributes: &[KeyValue],
        links: &[Link],
    ) -> SamplingResult {
        match SAMPLER.get() {
            Some(sampler) => {
                sampler.should_sample(parent_context, trace_id, name, span_kind, attributes, links)
            }
            None => SamplingResult {
                decision: SamplingDecision::Drop,
                attributes: Vec::new(),
                trace_state: TraceState::default(),
            },
        }
    }
}
