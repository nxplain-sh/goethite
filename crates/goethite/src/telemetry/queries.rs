//! A query's metrics: what it was answered with, over which protocol, and
//! how long that took.
//!
//! These are updated on every answered query, so every series is bound once
//! here: each update is then a single atomic operation in the SDK, with no
//! lock and no hashing of attributes. The criterion bench
//! (`benches/query-metrics.rs`) includes this file.

use std::time::Duration;

use goethite_store::{Protocol, QueryOutcome};
use opentelemetry::KeyValue;
use opentelemetry::metrics::{BoundCounter, BoundHistogram, Meter};

/// Upper bounds of the latency histogram's buckets, in seconds: 100 µs to
/// 2.5 s.
pub(crate) const BUCKETS: [f64; 14] = [
    0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
];

/// The per-query instruments, bound to every outcome and protocol.
pub(crate) struct QueryMetrics {
    queries: [[BoundCounter<u64>; Protocol::ALL.len()]; QueryOutcome::ALL.len()],
    duration: BoundHistogram<f64>,
}

impl std::fmt::Debug for QueryMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueryMetrics").finish_non_exhaustive()
    }
}

impl QueryMetrics {
    /// Creates `goethite.queries` and `goethite.query.duration` in `meter`
    /// and binds them.
    pub(crate) fn new(meter: &Meter) -> Self {
        let counter = meter
            .u64_counter("goethite.queries")
            .with_unit("{query}")
            .with_description("Answered queries, by outcome and protocol.")
            .build();
        let histogram = meter
            .f64_histogram("goethite.query.duration")
            .with_unit("s")
            .with_description("Time to resolve a query.")
            .with_boundaries(BUCKETS.to_vec())
            .build();
        Self {
            queries: QueryOutcome::ALL.map(|outcome| {
                Protocol::ALL.map(|protocol| {
                    counter.bind(&[
                        KeyValue::new("outcome", outcome.as_str()),
                        KeyValue::new("protocol", protocol.as_str()),
                    ])
                })
            }),
            duration: histogram.bind(&[]),
        }
    }

    /// Counts one answered query.
    pub(crate) fn observe(&self, outcome: QueryOutcome, protocol: Protocol, elapsed: Duration) {
        let outcome_index = QueryOutcome::ALL
            .iter()
            .position(|o| *o == outcome)
            .unwrap_or(0);
        let protocol_index = Protocol::ALL
            .iter()
            .position(|p| *p == protocol)
            .unwrap_or(0);
        if let Some(counter) = self
            .queries
            .get(outcome_index)
            .and_then(|row| row.get(protocol_index))
        {
            counter.add(1);
        }
        self.duration.record(elapsed.as_secs_f64());
    }
}
