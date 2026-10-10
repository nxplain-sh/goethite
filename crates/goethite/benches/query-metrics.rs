//! What counting one answered query costs: v0.5.0's atomics against the
//! OpenTelemetry instruments that replaced them (ADR 0040), bound as
//! goethite binds them and, for scale, unbound.

use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use goethite_store::{Protocol, QueryOutcome};
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram, MeterProvider as _};
use opentelemetry_sdk::metrics::SdkMeterProvider;

#[path = "../src/telemetry/queries.rs"]
mod queries;

use queries::{BUCKETS, QueryMetrics};

/// v0.5.0's per-query counters, as `crates/goethite/src/metrics.rs` kept
/// them: relaxed atomics in fixed arrays.
#[derive(Default)]
struct Atomics {
    queries: [[AtomicU64; Protocol::ALL.len()]; QueryOutcome::ALL.len()],
    latency: [AtomicU64; BUCKETS.len() + 1],
    latency_sum_us: AtomicU64,
}

impl Atomics {
    fn observe(&self, outcome: QueryOutcome, protocol: Protocol, elapsed: Duration) {
        let o = QueryOutcome::ALL
            .iter()
            .position(|x| *x == outcome)
            .unwrap_or(0);
        let p = Protocol::ALL
            .iter()
            .position(|x| *x == protocol)
            .unwrap_or(0);
        if let Some(counter) = self.queries.get(o).and_then(|row| row.get(p)) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        let seconds = elapsed.as_secs_f64();
        let bucket = BUCKETS
            .iter()
            .position(|bound| seconds <= *bound)
            .unwrap_or(BUCKETS.len());
        if let Some(counter) = self.latency.get(bucket) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        self.latency_sum_us.fetch_add(micros, Ordering::Relaxed);
    }
}

/// The same instruments without binding: attributes looked up per query.
struct Unbound {
    queries: Counter<u64>,
    duration: Histogram<f64>,
    attributes: Vec<[KeyValue; 2]>,
}

impl Unbound {
    fn observe(&self, index: usize, elapsed: Duration) {
        if let Some(attributes) = self.attributes.get(index) {
            self.queries.add(1, attributes);
        }
        self.duration.record(elapsed.as_secs_f64(), &[]);
    }
}

/// A mix of outcomes, protocols and times, cycled through.
fn inputs() -> Vec<(QueryOutcome, Protocol, Duration)> {
    QueryOutcome::ALL
        .iter()
        .zip(Protocol::ALL.iter().cycle())
        .zip([80_u64, 400, 30_000, 2_000].iter().cycle())
        .map(|((outcome, protocol), micros)| (*outcome, *protocol, Duration::from_micros(*micros)))
        .collect()
}

/// A provider read the way goethite reads it, through the Prometheus
/// exporter.
fn provider() -> SdkMeterProvider {
    let exporter = opentelemetry_prometheus::exporter()
        .with_registry(prometheus::Registry::new())
        .without_target_info()
        .scope_info_enabled(false)
        .build();
    let mut builder = SdkMeterProvider::builder();
    if let Ok(exporter) = exporter {
        builder = builder.with_reader(exporter);
    }
    builder.build()
}

fn query_metrics(c: &mut Criterion) {
    let inputs = inputs();
    let mut group = c.benchmark_group("query metrics");

    let atomics = Atomics::default();
    let mut next = inputs.iter().cycle();
    group.bench_function("v0.5.0 atomics", |b| {
        b.iter(|| {
            if let Some((outcome, protocol, elapsed)) = next.next() {
                atomics.observe(
                    black_box(*outcome),
                    black_box(*protocol),
                    black_box(*elapsed),
                );
            }
        });
    });

    let provider = provider();
    let meter = provider.meter("goethite");
    let bound = QueryMetrics::new(&meter);
    let mut next = inputs.iter().cycle();
    group.bench_function("otel bound", |b| {
        b.iter(|| {
            if let Some((outcome, protocol, elapsed)) = next.next() {
                bound.observe(
                    black_box(*outcome),
                    black_box(*protocol),
                    black_box(*elapsed),
                );
            }
        });
    });

    let unbound = Unbound {
        queries: meter.u64_counter("unbound.queries").build(),
        duration: meter
            .f64_histogram("unbound.duration")
            .with_boundaries(BUCKETS.to_vec())
            .build(),
        attributes: inputs
            .iter()
            .map(|(outcome, protocol, _)| {
                [
                    KeyValue::new("outcome", outcome.as_str()),
                    KeyValue::new("protocol", protocol.as_str()),
                ]
            })
            .collect(),
    };
    let mut next = inputs.iter().enumerate().cycle();
    group.bench_function("otel unbound", |b| {
        b.iter(|| {
            if let Some((index, (_, _, elapsed))) = next.next() {
                unbound.observe(black_box(index), black_box(*elapsed));
            }
        });
    });
    group.finish();
}

criterion_group!(benches, query_metrics);
criterion_main!(benches);
