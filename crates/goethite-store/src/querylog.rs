//! The query log: every answered query, kept for a while.
//!
//! The data plane hands each answered query to [`QueryLog::record`] as a
//! [`LogEvent`] that holds no heap allocations of its own (the name is
//! copied into a fixed buffer). That only queues it on a bounded channel and
//! never waits: when the queue is full, the event is dropped and counted.
//! A writer thread takes events off the queue, updates the statistics, and
//! writes the log in batches of up to a second, encoding each record in a
//! compact binary form. It also enforces the retention limits.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use goethite_filter::{Action, Match};
use goethite_proto::{Name, RecordType, ResponseCode};
use jiff::Timestamp;
use redb::{ReadableDatabase, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};
use utoipa::ToSchema;

use crate::stats::Aggregator;
use crate::store::{Store, StoreError};

pub(crate) const QUERYLOG: TableDefinition<'static, u64, &'static [u8]> =
    TableDefinition::new("querylog");

/// Events waiting for the writer, at most.
pub const QUEUE_CAPACITY: usize = 16_384;

/// The most log entries one search looks at, so a search for something rare
/// cannot scan the whole log; the cursor continues from where it stopped.
pub const MAX_SCANNED: usize = 100_000;

/// The most entries one search returns.
pub const MAX_PAGE: usize = 1000;

/// How long the writer collects events before writing them.
const BATCH_TIME: Duration = Duration::from_secs(1);

/// How often the writer empties the queue. It never waits on the queue
/// itself: a waiting receiver would make every query wake it with a system
/// call. At this pace the queue holds [`QUEUE_CAPACITY`] / 0.05 s, over
/// 300,000 queries a second.
const POLL_EVERY: Duration = Duration::from_millis(50);

/// The most events written in one transaction.
const BATCH_SIZE: usize = 4096;

/// How often old entries are pruned.
const PRUNE_EVERY: Duration = Duration::from_secs(60);

/// Longest name kept, in bytes of its text form.
const MAX_NAME_TEXT: usize = 1024;

/// Longest other string kept, in bytes.
const MAX_FIELD: usize = 512;

/// Query log settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryLogConfig {
    /// Whether queries are written to the log. Statistics are kept either
    /// way.
    pub enabled: bool,
    /// How long entries are kept.
    pub retention: Duration,
    /// The most entries kept; older ones are dropped first.
    pub max_entries: u64,
    /// Whether client addresses are shortened to their /24 (IPv4) or /56
    /// (IPv6) before they are written or counted.
    pub anonymize: bool,
}

impl Default for QueryLogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            retention: Duration::from_hours(7 * 24),
            max_entries: 1_000_000,
            anonymize: false,
        }
    }
}

/// How a query reached goethite.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// DNS over UDP.
    Udp,
    /// DNS over TCP.
    Tcp,
    /// DNS over TLS (RFC 7858).
    Dot,
    /// DNS over HTTPS (RFC 8484).
    Doh,
}

impl Protocol {
    /// Every protocol, for metrics.
    pub const ALL: [Self; 4] = [Self::Udp, Self::Tcp, Self::Dot, Self::Doh];

    fn code(self) -> u8 {
        match self {
            Self::Udp => 0,
            Self::Tcp => 1,
            Self::Dot => 2,
            Self::Doh => 3,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::Udp,
            1 => Self::Tcp,
            2 => Self::Dot,
            3 => Self::Doh,
            _ => return None,
        })
    }

    /// The name in the API and in metrics, such as `doh`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Dot => "dot",
            Self::Doh => "doh",
        }
    }
}

/// How an answer came about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryOutcome {
    /// From goethite's own records.
    Local,
    /// Refused or rejected by policy.
    Rejected,
    /// Blocked by the filter.
    Blocked,
    /// A search host sent to its safe endpoint.
    SafeSearch,
    /// From the cache.
    Cached,
    /// From an upstream.
    Forwarded,
    /// No upstream answered.
    Failed,
}

impl QueryOutcome {
    fn code(self) -> u8 {
        match self {
            Self::Local => 0,
            Self::Rejected => 1,
            Self::Blocked => 2,
            Self::SafeSearch => 3,
            Self::Cached => 4,
            Self::Forwarded => 5,
            Self::Failed => 6,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::Local,
            1 => Self::Rejected,
            2 => Self::Blocked,
            3 => Self::SafeSearch,
            4 => Self::Cached,
            5 => Self::Forwarded,
            6 => Self::Failed,
            _ => return None,
        })
    }

    /// Every outcome, for metrics.
    pub const ALL: [Self; 7] = [
        Self::Local,
        Self::Rejected,
        Self::Blocked,
        Self::SafeSearch,
        Self::Cached,
        Self::Forwarded,
        Self::Failed,
    ];

    /// The name used in the API and metrics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Rejected => "rejected",
            Self::Blocked => "blocked",
            Self::SafeSearch => "safe_search",
            Self::Cached => "cached",
            Self::Forwarded => "forwarded",
            Self::Failed => "failed",
        }
    }
}

/// A name's labels in wire order, copied without allocating.
#[derive(Clone, Copy)]
pub struct NameBuf {
    len: u8,
    bytes: [u8; 255],
}

impl NameBuf {
    /// Copies `name`'s labels, each prefixed with its length.
    pub fn new(name: &Name) -> Self {
        let mut buf = Self {
            len: 0,
            bytes: [0; 255],
        };
        let mut at = 0_usize;
        for label in name.labels() {
            let end = at.saturating_add(1).saturating_add(label.len());
            let Some(out) = buf.bytes.get_mut(at..end) else {
                break;
            };
            if let Some((prefix, rest)) = out.split_first_mut() {
                *prefix = u8::try_from(label.len()).unwrap_or(0);
                rest.copy_from_slice(label);
            }
            at = end;
        }
        buf.len = u8::try_from(at).unwrap_or(u8::MAX);
        buf
    }

    /// The name again.
    pub fn name(&self) -> Option<Name> {
        let bytes = self.bytes.get(..usize::from(self.len))?;
        let mut labels = Vec::new();
        let mut at = 0_usize;
        while let Some(&len) = bytes.get(at) {
            let end = at.saturating_add(1).saturating_add(usize::from(len));
            labels.push(bytes.get(at.saturating_add(1)..end)?);
            at = end;
        }
        Name::from_labels(labels).ok()
    }
}

impl std::fmt::Debug for NameBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.name() {
            Some(name) => write!(f, "NameBuf({name})"),
            None => f.write_str("NameBuf(?)"),
        }
    }
}

/// The filter rule that applied to a query.
#[derive(Clone, Debug)]
pub struct RuleHit {
    /// Block or exception.
    pub action: Action,
    /// The deciding rule.
    pub matched: Match,
    /// The rule's source: a list ID, or `custom`.
    pub source: Option<Arc<str>>,
    /// For a block through a CNAME, the CNAME target.
    pub cname: Option<Name>,
}

/// An answered query, as the data plane reports it.
#[derive(Clone, Debug)]
pub struct LogEvent {
    /// When it arrived.
    pub time: Timestamp,
    /// The client's address.
    pub client: IpAddr,
    /// How it arrived.
    pub protocol: Protocol,
    /// The name asked for.
    pub name: NameBuf,
    /// The type asked for.
    pub qtype: u16,
    /// The response code.
    pub rcode: u16,
    /// How the answer came about.
    pub outcome: QueryOutcome,
    /// For a forwarded answer, the upstream's index.
    pub upstream: Option<usize>,
    /// The filter rule that applied.
    pub rule: Option<RuleHit>,
    /// The known client's ID.
    pub client_id: Option<Arc<str>>,
    /// The client's group's ID.
    pub group: Option<Arc<str>>,
    /// How long resolving took.
    pub elapsed: Duration,
}

/// One logged query, as the API shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct QueryEntry {
    /// The entry's ID; entries with lower IDs are older. Use it as the
    /// `before` cursor to page.
    pub id: u64,
    /// When the query arrived.
    pub time: Timestamp,
    /// The client's address (shortened if the log anonymizes clients).
    pub client: String,
    /// The known client's ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// The client's group's ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// How the query arrived.
    pub protocol: Protocol,
    /// The name asked for.
    pub name: String,
    /// The type asked for, such as `A` or `TYPE65`.
    pub qtype: String,
    /// The response code, such as `NOERROR`.
    pub rcode: String,
    /// How the answer came about.
    pub outcome: QueryOutcome,
    /// For a forwarded answer, the upstream's address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
    /// The filter rule that applied, in AdGuard syntax.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// The rule's list ID, or `custom` for custom rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub list: Option<String>,
    /// For a block through a CNAME, the CNAME target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cname: Option<String>,
    /// How long resolving took, in microseconds.
    pub elapsed_us: u32,
}

/// A query as stored: numbers where the API shows text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredQuery {
    /// When the query arrived.
    pub time: Timestamp,
    /// The client's address.
    pub client: IpAddr,
    /// How the query arrived.
    pub protocol: Protocol,
    /// The type asked for.
    pub qtype: u16,
    /// The response code.
    pub rcode: u16,
    /// How the answer came about.
    pub outcome: QueryOutcome,
    /// How long resolving took, in microseconds.
    pub elapsed_us: u32,
    /// The name asked for.
    pub name: String,
    /// The known client's ID.
    pub client_id: Option<String>,
    /// The client's group's ID.
    pub group: Option<String>,
    /// For a forwarded answer, the upstream's address.
    pub upstream: Option<String>,
    /// The filter rule that applied.
    pub rule: Option<String>,
    /// The rule's list ID.
    pub list: Option<String>,
    /// For a block through a CNAME, the CNAME target.
    pub cname: Option<String>,
}

impl StoredQuery {
    /// The API's view, with ID `id`.
    pub fn entry(self, id: u64) -> QueryEntry {
        QueryEntry {
            id,
            time: self.time,
            client: self.client.to_string(),
            client_id: self.client_id,
            group: self.group,
            protocol: self.protocol,
            name: self.name,
            qtype: RecordType(self.qtype).to_string(),
            rcode: ResponseCode(self.rcode).to_string(),
            outcome: self.outcome,
            upstream: self.upstream,
            rule: self.rule,
            list: self.list,
            cname: self.cname,
            elapsed_us: self.elapsed_us,
        }
    }
}

/// What to look for in the query log.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Search {
    /// Only entries older than this ID.
    pub before: Option<u64>,
    /// At most this many entries (capped at [`MAX_PAGE`]).
    pub limit: usize,
    /// Only this client address (as shown), client ID or group ID.
    pub client: Option<String>,
    /// Only names containing this text, ignoring case.
    pub name: Option<String>,
    /// Only this outcome.
    pub outcome: Option<QueryOutcome>,
    /// Only entries at or after this time.
    pub since: Option<Timestamp>,
}

/// A page of search results.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct QueryPage {
    /// Matching entries, newest first.
    pub entries: Vec<QueryEntry>,
    /// Pass as `before` for the next page; absent at the end of the log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<u64>,
}

/// The data plane's handle on the query log.
pub struct QueryLog {
    sender: SyncSender<LogEvent>,
    dropped: AtomicU64,
    stats: Arc<Mutex<Aggregator>>,
    /// Set to have the writer finish up and stop.
    closing: Arc<AtomicBool>,
    writer: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl QueryLog {
    /// Queues `event` for the writer. Never waits: if the queue is full, the
    /// event is dropped and counted.
    pub fn record(&self, event: LogEvent) {
        if self.closing.load(Ordering::Relaxed) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        match self.sender.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Writes what is queued, saves the statistics and stops the writer,
    /// which lets go of the store. Events recorded afterwards are dropped
    /// and counted. Blocks until the writer has stopped; call it once.
    pub fn close(&self) {
        self.closing.store(true, Ordering::Release);
        let handle = self
            .writer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(handle) = handle
            && handle.join().is_err()
        {
            error!("the query log writer failed");
        }
    }

    /// Events dropped because the writer could not keep up.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// The statistics the writer keeps.
    pub(crate) fn aggregator(&self) -> &Arc<Mutex<Aggregator>> {
        &self.stats
    }
}

impl Store {
    /// Starts the query log writer on its own thread. `upstreams` names the
    /// upstreams by index, for the log.
    ///
    /// # Errors
    ///
    /// A database error, or if the thread cannot be started.
    pub fn start_query_log(
        self: &Arc<Self>,
        config: QueryLogConfig,
        upstreams: Vec<String>,
    ) -> Result<Arc<QueryLog>, StoreError> {
        let tx = self.database().begin_write()?;
        tx.open_table(QUERYLOG)?;
        crate::stats::open_tables(&tx)?;
        tx.commit()?;
        let stats = Arc::new(Mutex::new(crate::stats::load(self)?));
        let (sender, receiver) = sync_channel(QUEUE_CAPACITY);
        let closing = Arc::new(AtomicBool::new(false));
        let store = Arc::clone(self);
        let writer_closing = Arc::clone(&closing);
        let writer_stats = Arc::clone(&stats);
        let handle = std::thread::Builder::new()
            .name("goethite-querylog".into())
            .spawn(move || {
                writer(
                    &store,
                    &config,
                    &upstreams,
                    &receiver,
                    &writer_stats,
                    &writer_closing,
                );
            })
            .map_err(|err| StoreError::Database(err.into()))?;
        Ok(Arc::new(QueryLog {
            sender,
            dropped: AtomicU64::new(0),
            stats,
            closing,
            writer: Mutex::new(Some(handle)),
        }))
    }

    /// Searches the query log, newest first.
    ///
    /// # Errors
    ///
    /// A database error.
    pub fn search_queries(&self, search: &Search) -> Result<QueryPage, StoreError> {
        let tx = self.database().begin_read()?;
        let table = match tx.open_table(QUERYLOG) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                return Ok(QueryPage {
                    entries: Vec::new(),
                    next: None,
                });
            }
            Err(err) => return Err(err.into()),
        };
        let limit = search.limit.clamp(1, MAX_PAGE);
        let name = search.name.as_ref().map(|name| name.to_ascii_lowercase());
        let since = search.since.map(key_floor);
        let mut entries = Vec::new();
        let mut scanned = 0_usize;
        let mut last = None;
        for row in table.range(..search.before.unwrap_or(u64::MAX))?.rev() {
            let (key, value) = row?;
            let id = key.value();
            if since.is_some_and(|since| id < since) {
                last = None;
                break;
            }
            scanned = scanned.saturating_add(1);
            last = Some(id);
            let Some(stored) = decode(value.value()) else {
                continue;
            };
            let matches = search
                .outcome
                .is_none_or(|outcome| stored.outcome == outcome)
                && name
                    .as_ref()
                    .is_none_or(|name| stored.name.to_ascii_lowercase().contains(name.as_str()))
                && search.client.as_ref().is_none_or(|client| {
                    stored.client.to_string() == *client
                        || stored.client_id.as_ref() == Some(client)
                        || stored.group.as_ref() == Some(client)
                });
            if matches {
                entries.push(stored.entry(id));
                if entries.len() >= limit {
                    break;
                }
            }
            if scanned >= MAX_SCANNED {
                break;
            }
        }
        // More may follow unless the scan reached the start of the log.
        let next = match last {
            Some(id) if table.range(..id)?.next_back().is_some() => Some(id),
            _ => None,
        };
        Ok(QueryPage { entries, next })
    }

    /// Entries in the query log.
    ///
    /// # Errors
    ///
    /// A database error.
    pub fn query_log_len(&self) -> Result<u64, StoreError> {
        let tx = self.database().begin_read()?;
        match tx.open_table(QUERYLOG) {
            Ok(table) => Ok(table.len()?),
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(0),
            Err(err) => Err(err.into()),
        }
    }
}

/// The smallest key at or after `time`.
fn key_floor(time: Timestamp) -> u64 {
    u64::try_from(time.as_microsecond())
        .unwrap_or(0)
        .saturating_mul(1024)
}

/// Shortens `ip` to its /24 or /56.
pub(crate) fn anonymize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(Ipv4Addr::from(u32::from(v4) & 0xffff_ff00)),
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(
            u128::from(v6) & !((1_u128 << 72).wrapping_sub(1)),
        )),
    }
}

/// The writer thread: batches events into the log and the statistics until
/// the data plane goes away.
fn writer(
    store: &Store,
    config: &QueryLogConfig,
    upstreams: &[String],
    receiver: &Receiver<LogEvent>,
    stats: &Mutex<Aggregator>,
    closing: &AtomicBool,
) {
    let mut last_key = 0_u64;
    let mut last_prune = Instant::now()
        .checked_sub(PRUNE_EVERY)
        .unwrap_or_else(Instant::now);
    let mut batch: Vec<LogEvent> = Vec::with_capacity(BATCH_SIZE);
    let mut last_write = Instant::now();
    loop {
        let mut disconnected = false;
        while batch.len() < BATCH_SIZE {
            match receiver.try_recv() {
                Ok(mut event) => {
                    if config.anonymize {
                        event.client = anonymize(event.client);
                    }
                    batch.push(event);
                }
                Err(TryRecvError::Empty) => {
                    // Closing: everything queued is in the batch.
                    disconnected = closing.load(Ordering::Acquire);
                    break;
                }
                Err(TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }
        let full = batch.len() >= BATCH_SIZE;
        if !full && !disconnected && last_write.elapsed() < BATCH_TIME {
            std::thread::sleep(POLL_EVERY);
            continue;
        }
        last_write = Instant::now();
        let entries: Vec<(u64, StoredQuery)> = batch
            .drain(..)
            .map(|event| {
                (
                    next_key(&mut last_key, event.time),
                    stored(event, upstreams),
                )
            })
            .collect();
        stats
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .add(&entries);
        if config.enabled
            && !entries.is_empty()
            && let Err(err) = write(store, &entries)
        {
            error!(%err, "cannot write the query log");
        }
        if last_prune.elapsed() >= PRUNE_EVERY || disconnected {
            last_prune = Instant::now();
            if let Err(err) = prune(store, config) {
                warn!(%err, "cannot prune the query log");
            }
            if let Err(err) = crate::stats::persist(store, stats) {
                warn!(%err, "cannot save statistics");
            }
        }
        if disconnected {
            return;
        }
    }
}

/// A key after `last`, from `time`: microseconds since the epoch times 1024,
/// so keys sort by time and up to 1024 entries fit in one microsecond.
fn next_key(last: &mut u64, time: Timestamp) -> u64 {
    let key = key_floor(time).max(last.saturating_add(1));
    *last = key;
    key
}

/// What gets stored for an event.
fn stored(event: LogEvent, upstreams: &[String]) -> StoredQuery {
    let name = event.name.name();
    let rule = event.rule.as_ref().and_then(|hit| {
        let base = hit.cname.as_ref().or(name.as_ref())?;
        Some(hit.matched.rule_text(base, hit.action))
    });
    StoredQuery {
        time: event.time,
        client: event.client,
        client_id: event.client_id.map(|id| id.to_string()),
        group: event.group.map(|id| id.to_string()),
        protocol: event.protocol,
        name: name.map(|name| name.to_string()).unwrap_or_default(),
        qtype: event.qtype,
        rcode: event.rcode,
        outcome: event.outcome,
        upstream: event
            .upstream
            .and_then(|index| upstreams.get(index).cloned()),
        rule,
        list: event
            .rule
            .as_ref()
            .and_then(|hit| hit.source.as_ref().map(ToString::to_string)),
        cname: event
            .rule
            .and_then(|hit| hit.cname.map(|cname| cname.to_string())),
        elapsed_us: u32::try_from(event.elapsed.as_micros()).unwrap_or(u32::MAX),
    }
}

fn write(store: &Store, entries: &[(u64, StoredQuery)]) -> Result<(), StoreError> {
    let tx = store.database().begin_write()?;
    {
        let mut table = tx.open_table(QUERYLOG)?;
        for (id, query) in entries {
            table.insert(*id, encode(query).as_slice())?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// Drops entries older than the retention time, then the oldest ones over
/// the size limit.
fn prune(store: &Store, config: &QueryLogConfig) -> Result<(), StoreError> {
    let cutoff = Timestamp::now()
        .checked_sub(jiff::SignedDuration::try_from(config.retention).unwrap_or_default())
        .map_or(0, key_floor);
    let tx = store.database().begin_write()?;
    {
        let mut table = tx.open_table(QUERYLOG)?;
        table.retain_in(..cutoff, |_, _| false)?;
        let len = table.len()?;
        if len > config.max_entries {
            let excess = len.saturating_sub(config.max_entries);
            let mut removed = 0_u64;
            while removed < excess {
                if table.pop_first()?.is_none() {
                    break;
                }
                removed = removed.saturating_add(1);
            }
        }
    }
    tx.commit()?;
    Ok(())
}

/// Record format version.
const VERSION: u8 = 1;

/// Encodes a query:
///
/// ```text
/// version u8, time i64 µs, family u8 (4 or 6), address (4 or 16 bytes),
/// protocol u8, qtype u16, rcode u16, outcome u8, elapsed u32 µs,
/// presence bits u8, name, then each present optional string
/// (client ID, group, upstream, rule, list, cname),
/// strings as u16 length and UTF-8 bytes, integers little-endian
/// ```
pub fn encode(query: &StoredQuery) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.push(VERSION);
    out.extend_from_slice(&query.time.as_microsecond().to_le_bytes());
    match query.client {
        IpAddr::V4(v4) => {
            out.push(4);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(6);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.push(query.protocol.code());
    out.extend_from_slice(&query.qtype.to_le_bytes());
    out.extend_from_slice(&query.rcode.to_le_bytes());
    out.push(query.outcome.code());
    out.extend_from_slice(&query.elapsed_us.to_le_bytes());
    let optional = [
        &query.client_id,
        &query.group,
        &query.upstream,
        &query.rule,
        &query.list,
        &query.cname,
    ];
    let mut present = 0_u8;
    for (bit, field) in (0_u32..).zip(optional) {
        if field.is_some() {
            present |= 1_u8.checked_shl(bit).unwrap_or(0);
        }
    }
    out.push(present);
    put_str(&mut out, &query.name, MAX_NAME_TEXT);
    for field in optional.into_iter().flatten() {
        put_str(&mut out, field, MAX_FIELD);
    }
    out
}

/// Writes `text`, cut at a character boundary to at most `max` bytes.
fn put_str(out: &mut Vec<u8>, text: &str, max: usize) {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let bytes = text.as_bytes().get(..end).unwrap_or_default();
    out.extend_from_slice(&u16::try_from(bytes.len()).unwrap_or(0).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// Reads bytes off the front of a record.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(len)?;
        self.0 = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn i64(&mut self) -> Option<i64> {
        Some(i64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    fn string(&mut self) -> Option<String> {
        let len = usize::from(self.u16()?);
        Some(String::from_utf8_lossy(self.take(len)?).into_owned())
    }
}

/// Decodes a record written by [`encode`], or `None` if it is not one.
pub fn decode(bytes: &[u8]) -> Option<StoredQuery> {
    let mut reader = Reader(bytes);
    if reader.u8()? != VERSION {
        return None;
    }
    let time = Timestamp::from_microsecond(reader.i64()?).ok()?;
    let client = match reader.u8()? {
        4 => IpAddr::from(<[u8; 4]>::try_from(reader.take(4)?).ok()?),
        6 => IpAddr::from(<[u8; 16]>::try_from(reader.take(16)?).ok()?),
        _ => return None,
    };
    let protocol = Protocol::from_code(reader.u8()?)?;
    let qtype = reader.u16()?;
    let rcode = reader.u16()?;
    let outcome = QueryOutcome::from_code(reader.u8()?)?;
    let elapsed_us = reader.u32()?;
    let present = reader.u8()?;
    if present >> 6 != 0 {
        return None;
    }
    let name = reader.string()?;
    let mut optional: [Option<String>; 6] = Default::default();
    for (bit, field) in (0_u32..).zip(optional.iter_mut()) {
        if present & 1_u8.checked_shl(bit)? != 0 {
            *field = Some(reader.string()?);
        }
    }
    if !reader.0.is_empty() {
        return None;
    }
    let [client_id, group, upstream, rule, list, cname] = optional;
    Some(StoredQuery {
        time,
        client,
        protocol,
        qtype,
        rcode,
        outcome,
        elapsed_us,
        name,
        client_id,
        group,
        upstream,
        rule,
        list,
        cname,
    })
}

#[cfg(test)]
mod tests {
    use goethite_filter::{Scope, Source};

    use super::*;

    fn query(name: &str) -> StoredQuery {
        StoredQuery {
            time: "2026-10-08T10:00:00.123456Z".parse().unwrap(),
            client: "2001:db8::1".parse().unwrap(),
            protocol: Protocol::Tcp,
            qtype: 28,
            rcode: 3,
            outcome: QueryOutcome::Blocked,
            elapsed_us: 123,
            name: name.into(),
            client_id: Some("cl_1".into()),
            group: None,
            upstream: None,
            rule: Some("||ads.example^".into()),
            list: Some("li_1".into()),
            cname: None,
        }
    }

    #[test]
    fn records_round_trip() {
        let mut forwarded = query("x.example.");
        forwarded.client = "192.0.2.1".parse().unwrap();
        forwarded.qtype = 65;
        forwarded.rcode = 0;
        forwarded.outcome = QueryOutcome::Forwarded;
        forwarded.upstream = Some("9.9.9.9:853".into());
        forwarded.rule = None;
        forwarded.list = None;
        forwarded.client_id = None;
        forwarded.group = Some("default".into());
        forwarded.protocol = Protocol::Udp;
        for stored in [query("ads.example."), forwarded] {
            assert_eq!(decode(&encode(&stored)), Some(stored));
        }
        for protocol in Protocol::ALL {
            let mut stored = query("ads.example.");
            stored.protocol = protocol;
            assert_eq!(decode(&encode(&stored)), Some(stored));
            assert_eq!(Protocol::from_code(protocol.code()), Some(protocol));
            assert_eq!(
                serde_json::to_value(protocol).unwrap(),
                serde_json::Value::from(protocol.as_str())
            );
        }
        let entry = query("ads.example.").entry(9);
        assert_eq!(
            (entry.qtype.as_str(), entry.rcode.as_str()),
            ("AAAA", "NXDOMAIN")
        );
        assert_eq!(entry.id, 9);
    }

    #[test]
    fn fuzz_seeds_decode() {
        for seed in ["forwarded-v4", "blocked-v6-cname", "minimal"] {
            let path = format!(
                "{}/../../fuzz/seeds/decode_query_record/{seed}",
                env!("CARGO_MANIFEST_DIR")
            );
            let bytes = std::fs::read(&path).unwrap();
            let decoded = decode(&bytes).unwrap_or_else(|| panic!("{seed}"));
            assert_eq!(encode(&decoded), bytes, "{seed}");
        }
    }

    #[test]
    fn decoding_rejects_damage() {
        let bytes = encode(&query("ads.example."));
        for len in 0..bytes.len() {
            assert_eq!(decode(&bytes[..len]), None, "truncated to {len}");
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(decode(&longer), None);
        let mut version = bytes;
        version[0] = 2;
        assert_eq!(decode(&version), None);
    }

    #[test]
    fn long_strings_are_cut_on_character_boundaries() {
        let decoded = decode(&encode(&query(&"é".repeat(2000)))).unwrap();
        assert!(decoded.name.len() <= MAX_NAME_TEXT);
        assert!(decoded.name.chars().all(|c| c == 'é'));
    }

    #[test]
    fn keys_increase_with_time() {
        let mut last = 0;
        let t: Timestamp = "2026-10-08T10:00:00Z".parse().unwrap();
        let a = next_key(&mut last, t);
        let b = next_key(&mut last, t);
        let earlier = next_key(
            &mut last,
            t.checked_sub(jiff::SignedDuration::from_secs(1)).unwrap(),
        );
        assert!(a < b && b < earlier, "never goes backwards");
        assert_eq!(a, key_floor(t));
    }

    #[test]
    fn names_are_copied_without_allocating() {
        let name: Name = "WWW.Example.com.".parse().unwrap();
        let buf = NameBuf::new(&name);
        assert!(buf.name().unwrap().eq_exact(&name));
        let label = [b'a'; 63];
        let longest = Name::from_labels([&label[..], &label, &label, &label[..61]]).unwrap();
        assert_eq!(NameBuf::new(&longest).name().unwrap(), longest);
        assert_eq!(NameBuf::new(&Name::root()).name().unwrap(), Name::root());
    }

    #[test]
    fn events_become_stored_queries() {
        let event = LogEvent {
            time: Timestamp::now(),
            client: "192.0.2.7".parse().unwrap(),
            protocol: Protocol::Udp,
            name: NameBuf::new(&"x.ads.example.".parse().unwrap()),
            qtype: 1,
            rcode: 0,
            outcome: QueryOutcome::Forwarded,
            upstream: Some(0),
            rule: Some(RuleHit {
                action: Action::Allow,
                matched: Match {
                    source: Source::new(1).unwrap(),
                    scope: Scope::Subtree,
                    labels: 2,
                },
                source: Some("li_ads".into()),
                cname: None,
            }),
            client_id: None,
            group: Some("default".into()),
            elapsed: Duration::from_micros(42),
        };
        let stored = stored(event, &["9.9.9.9:853".to_owned()]);
        assert_eq!(stored.rule.as_deref(), Some("@@||ads.example^"));
        assert_eq!(stored.list.as_deref(), Some("li_ads"));
        assert_eq!(stored.upstream.as_deref(), Some("9.9.9.9:853"));
        assert_eq!(stored.name, "x.ads.example.");
        assert_eq!(stored.elapsed_us, 42);
    }

    #[test]
    fn anonymizing() {
        assert_eq!(
            anonymize("192.0.2.77".parse().unwrap()),
            "192.0.2.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            anonymize("2001:db8:1:2:3:4:5:6".parse().unwrap()),
            "2001:db8:1::".parse::<IpAddr>().unwrap()
        );
    }
}
