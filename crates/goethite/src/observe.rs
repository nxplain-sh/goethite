//! Feeding every answered query to the query log and the metrics.

use std::sync::Arc;

use arc_swap::ArcSwapOption;

use goethite_api::leak::{Arrival, LeakTests};
use goethite_proto::Name;
use goethite_resolver::{HEALTH_NAME, Outcome};
use goethite_server::{QueryEvent, QueryObserver, Transport};
use goethite_store::{LogEvent, LogUpstream, NameBuf, Protocol, QueryLog, QueryOutcome, RuleHit};
use jiff::Timestamp;

use crate::metrics::Metrics;

/// Reports queries to the query log and the metrics. It only copies and
/// queues: it never waits on the disk.
pub(crate) struct Observer {
    /// The query log, while the control plane runs: it can stop and start
    /// again (on an upgrade) while queries go on.
    log: Arc<ArcSwapOption<QueryLog>>,
    /// The metrics.
    metrics: Arc<Metrics>,
    /// [`HEALTH_NAME`]: health checks are counted in the metrics, but kept
    /// out of the query log, which they would fill.
    health: Name,
    /// DNS leak tests, which record lookups of their names.
    leak: Arc<LeakTests>,
}

impl Observer {
    /// Reports to `log`, `metrics` and `leak`.
    ///
    /// # Errors
    ///
    /// Never in practice: [`HEALTH_NAME`] is a valid name.
    pub(crate) fn new(
        log: Arc<ArcSwapOption<QueryLog>>,
        metrics: Arc<Metrics>,
        leak: Arc<LeakTests>,
    ) -> Result<Self, goethite_proto::NameError> {
        Ok(Self {
            log,
            metrics,
            health: HEALTH_NAME.parse()?,
            leak,
        })
    }
}

impl QueryObserver for Observer {
    fn observe(&self, event: &QueryEvent<'_>) {
        let resolution = event.resolution;
        let (outcome, upstream) = match resolution.outcome {
            Outcome::Local => (QueryOutcome::Local, None),
            Outcome::Blocked => (QueryOutcome::Blocked, None),
            Outcome::SafeSearch => (QueryOutcome::SafeSearch, None),
            Outcome::Cached => (QueryOutcome::Cached, None),
            Outcome::Upstream(index) => (QueryOutcome::Forwarded, Some(LogUpstream::Index(index))),
            Outcome::Recursive(server) => {
                (QueryOutcome::Forwarded, Some(LogUpstream::Address(server)))
            }
            Outcome::Failed => (QueryOutcome::Failed, None),
            _ => (QueryOutcome::Rejected, None),
        };
        let protocol = match event.transport {
            Transport::Udp => Protocol::Udp,
            Transport::Tcp => Protocol::Tcp,
            Transport::Tls => Protocol::Dot,
            Transport::Https => Protocol::Doh,
            Transport::Quic => Protocol::Doq,
            Transport::Oblivious => Protocol::Odoh,
        };
        self.metrics.observe(outcome, protocol, event.elapsed);
        self.leak.observe(&event.query.question.name, || Arrival {
            address: event.peer.ip(),
            protocol,
            qtype: event.query.question.qtype,
            client: resolution.client.clone(),
            group: resolution.group.clone(),
            filtering: resolution.filtering,
        });
        if outcome == QueryOutcome::Local && event.query.question.name == self.health {
            return;
        }
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
