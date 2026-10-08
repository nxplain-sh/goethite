//! Feeding every answered query to the query log and the metrics.

use std::sync::Arc;

use arc_swap::ArcSwapOption;

use goethite_resolver::Outcome;
use goethite_server::{QueryEvent, QueryObserver, Transport};
use goethite_store::{LogEvent, NameBuf, Protocol, QueryLog, QueryOutcome, RuleHit};
use jiff::Timestamp;

use crate::metrics::Metrics;

/// Reports queries to the query log and the metrics. It only copies and
/// queues: it never waits on the disk.
pub struct Observer {
    /// The query log, while the control plane runs: it can stop and start
    /// again (on an upgrade) while queries go on.
    pub log: Arc<ArcSwapOption<QueryLog>>,
    /// The metrics.
    pub metrics: Arc<Metrics>,
}

impl QueryObserver for Observer {
    fn observe(&self, event: &QueryEvent<'_>) {
        let resolution = event.resolution;
        let (outcome, upstream) = match resolution.outcome {
            Outcome::Local => (QueryOutcome::Local, None),
            Outcome::Blocked => (QueryOutcome::Blocked, None),
            Outcome::SafeSearch => (QueryOutcome::SafeSearch, None),
            Outcome::Cached => (QueryOutcome::Cached, None),
            Outcome::Upstream(index) => (QueryOutcome::Forwarded, Some(index)),
            Outcome::Failed => (QueryOutcome::Failed, None),
            _ => (QueryOutcome::Rejected, None),
        };
        let protocol = match event.transport {
            Transport::Udp => Protocol::Udp,
            Transport::Tcp => Protocol::Tcp,
        };
        self.metrics.observe(outcome, protocol, event.elapsed);
        let log = self.log.load();
        let Some(log) = log.as_ref() else {
            return;
        };
        let time = Timestamp::try_from(event.time).unwrap_or_else(|_| Timestamp::now());
        log.record(LogEvent {
            time,
            client: event.peer.ip(),
            protocol,
            name: NameBuf::new(&event.query.question.name),
            qtype: event.query.question.qtype.0,
            rcode: resolution.response.rcode.0,
            outcome,
            upstream,
            rule: resolution.filter.as_ref().map(|hit| RuleHit {
                action: hit.action,
                matched: hit.matched,
                source: hit.source.clone(),
                cname: hit.cname.clone(),
            }),
            client_id: resolution.client.clone(),
            group: resolution.group.clone(),
            elapsed: event.elapsed,
        });
    }
}
