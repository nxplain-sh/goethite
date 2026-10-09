//! Statistics: counts per hour, and the names and clients asked most.
//!
//! The query log writer feeds every answered query to an `Aggregator`,
//! whether or not the log itself is on. It keeps the current hour's counts
//! and approximate top lists, and every finished hour with its top 100 of
//! each list, for 30 days. Hours are saved to the store every minute and
//! loaded back on start, so a restart loses at most a minute of counts.
//!
//! The top lists are bounded: once 10,000 distinct names (or clients) have
//! been counted in an hour, all counts are halved and those that drop to
//! zero are forgotten. Frequent names survive that; a flood of random names
//! cannot use up memory.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Mutex, PoisonError};

use jiff::Timestamp;
use redb::{ReadableDatabase, TableDefinition, WriteTransaction};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::querylog::{QueryLog, QueryOutcome, StoredQuery};
use crate::store::{Store, StoreError};

const HOURS: TableDefinition<'static, i64, &'static [u8]> = TableDefinition::new("stats_hours");

/// Hours of statistics kept.
pub const RETENTION_HOURS: i64 = 30 * 24;

/// Entries kept in each top list of a finished hour.
const TOP_PER_HOUR: usize = 100;

/// Entries a report's top lists have.
pub const TOP_IN_REPORT: usize = 20;

/// Entries each node's top lists have when reports from several nodes are
/// merged, so the merged top lists come out right more often.
pub const TOP_FOR_MERGE: usize = TOP_PER_HOUR;

/// Distinct keys counted in an hour before counts are halved.
const MAX_TRACKED: usize = 10_000;

/// Counts of queries by outcome.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Counters {
    /// All answered queries.
    pub queries: u64,
    /// Blocked by the filter.
    pub blocked: u64,
    /// Answered from the cache.
    pub cached: u64,
    /// Answered by an upstream.
    pub forwarded: u64,
    /// No upstream answered.
    pub failed: u64,
    /// Sent to a safe search endpoint.
    pub safe_search: u64,
    /// Answered from goethite's own records.
    pub local: u64,
    /// Refused or rejected by policy.
    pub rejected: u64,
    /// Total time spent resolving, in microseconds; divide by `queries` for
    /// the average.
    pub elapsed_us: u64,
}

impl Counters {
    fn add(&mut self, query: &StoredQuery) {
        let count = match query.outcome {
            QueryOutcome::Blocked => &mut self.blocked,
            QueryOutcome::Cached => &mut self.cached,
            QueryOutcome::Forwarded => &mut self.forwarded,
            QueryOutcome::Failed => &mut self.failed,
            QueryOutcome::SafeSearch => &mut self.safe_search,
            QueryOutcome::Local => &mut self.local,
            QueryOutcome::Rejected => &mut self.rejected,
        };
        *count = count.saturating_add(1);
        self.queries = self.queries.saturating_add(1);
        self.elapsed_us = self.elapsed_us.saturating_add(u64::from(query.elapsed_us));
    }

    fn merge(&mut self, other: &Self) {
        let pairs = [
            (&mut self.queries, other.queries),
            (&mut self.blocked, other.blocked),
            (&mut self.cached, other.cached),
            (&mut self.forwarded, other.forwarded),
            (&mut self.failed, other.failed),
            (&mut self.safe_search, other.safe_search),
            (&mut self.local, other.local),
            (&mut self.rejected, other.rejected),
            (&mut self.elapsed_us, other.elapsed_us),
        ];
        for (mine, theirs) in pairs {
            *mine = mine.saturating_add(theirs);
        }
    }
}

/// One hour, as saved.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Hour {
    counters: Counters,
    names: Vec<(String, u64)>,
    blocked: Vec<(String, u64)>,
    clients: Vec<(String, u64)>,
}

/// Approximate counts of the most frequent keys, in bounded memory.
#[derive(Debug, Default)]
struct TopCounter(HashMap<String, u64>);

impl TopCounter {
    fn add(&mut self, key: &str) {
        if let Some(count) = self.0.get_mut(key) {
            *count = count.saturating_add(1);
            return;
        }
        if self.0.len() >= MAX_TRACKED {
            self.0.retain(|_, count| {
                *count /= 2;
                *count > 0
            });
        }
        self.0.insert(key.to_owned(), 1);
    }

    fn top(&self, n: usize) -> Vec<(String, u64)> {
        top(self.0.iter().map(|(key, count)| (key.clone(), *count)), n)
    }
}

/// The `n` largest counts, largest first, ties by key.
fn top(counts: impl Iterator<Item = (String, u64)>, n: usize) -> Vec<(String, u64)> {
    let mut all: Vec<(String, u64)> = counts.collect();
    all.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    all.truncate(n);
    all
}

/// Hours since the Unix epoch.
fn hour_of(time: Timestamp) -> i64 {
    time.as_second().div_euclid(3600)
}

/// The statistics the query log writer keeps.
#[derive(Debug, Default)]
pub(crate) struct Aggregator {
    hour: i64,
    counters: Counters,
    names: TopCounter,
    blocked: TopCounter,
    clients: TopCounter,
    history: BTreeMap<i64, Hour>,
    unsaved: BTreeSet<i64>,
}

impl Aggregator {
    /// Counts `queries`.
    pub(crate) fn add(&mut self, queries: &[(u64, StoredQuery)]) {
        for (_, query) in queries {
            let hour = hour_of(query.time);
            if hour > self.hour {
                self.finish();
                self.hour = hour;
            }
            self.counters.add(query);
            let name = query.name.to_ascii_lowercase();
            self.names.add(&name);
            if query.outcome == QueryOutcome::Blocked {
                self.blocked.add(&name);
            }
            let client = query
                .client_id
                .clone()
                .unwrap_or_else(|| query.client.to_string());
            self.clients.add(&client);
        }
        self.unsaved.insert(self.hour);
    }

    /// Moves the current hour into the history.
    fn finish(&mut self) {
        if self.counters.queries > 0 {
            let hour = self.current();
            self.history.insert(self.hour, hour);
            self.unsaved.insert(self.hour);
        }
        self.counters = Counters::default();
        self.names = TopCounter::default();
        self.blocked = TopCounter::default();
        self.clients = TopCounter::default();
    }

    fn current(&self) -> Hour {
        Hour {
            counters: self.counters,
            names: self.names.top(TOP_PER_HOUR),
            blocked: self.blocked.top(TOP_PER_HOUR),
            clients: self.clients.top(TOP_PER_HOUR),
        }
    }

    /// The hours from `from` on, the current one included.
    fn hours(&self, from: i64) -> Vec<(i64, Hour)> {
        let mut hours: Vec<(i64, Hour)> = self
            .history
            .range(from..)
            .filter(|(hour, _)| **hour != self.hour)
            .map(|(hour, data)| (*hour, data.clone()))
            .collect();
        if self.hour >= from && self.counters.queries > 0 {
            hours.push((self.hour, self.current()));
        }
        hours
    }
}

/// One hour in a report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct HourPoint {
    /// When the hour starts.
    pub start: Timestamp,
    /// Its counts.
    pub counters: Counters,
}

/// A name or client and how often it was seen.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TopEntry {
    /// The name, client ID or client address.
    pub key: String,
    /// How often, approximately.
    pub count: u64,
}

/// Statistics over a time range.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct StatsReport {
    /// The start of the first hour covered.
    pub from: Timestamp,
    /// When the report was made.
    pub to: Timestamp,
    /// Counts over the whole range.
    pub totals: Counters,
    /// Counts per hour, oldest first; hours without queries are left out.
    pub hours: Vec<HourPoint>,
    /// The names asked for most.
    pub top_names: Vec<TopEntry>,
    /// The blocked names asked for most.
    pub top_blocked: Vec<TopEntry>,
    /// The clients asking most, by client ID or address.
    pub top_clients: Vec<TopEntry>,
    /// For a cluster's statistics, the nodes whose counts are included.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<String>,
    /// For a cluster's statistics, the nodes that could not be asked: their
    /// counts are missing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unreachable: Vec<String>,
}

impl StatsReport {
    /// Adds `other`'s counts to this report's, for statistics over several
    /// nodes: totals and hours add up, top lists are merged by key and cut
    /// to `entries` entries. Merged top lists are approximate, like each node's.
    pub fn merge(&mut self, other: &Self, entries: usize) {
        self.from = self.from.min(other.from);
        self.to = self.to.max(other.to);
        self.totals.merge(&other.totals);
        let mut hours: BTreeMap<Timestamp, Counters> = self
            .hours
            .iter()
            .map(|point| (point.start, point.counters))
            .collect();
        for point in &other.hours {
            hours.entry(point.start).or_default().merge(&point.counters);
        }
        self.hours = hours
            .into_iter()
            .map(|(start, counters)| HourPoint { start, counters })
            .collect();
        for (mine, theirs) in [
            (&mut self.top_names, &other.top_names),
            (&mut self.top_blocked, &other.top_blocked),
            (&mut self.top_clients, &other.top_clients),
        ] {
            let mut counts: HashMap<String, u64> = HashMap::new();
            for entry in mine.drain(..).chain(theirs.iter().cloned()) {
                let total = counts.entry(entry.key).or_default();
                *total = total.saturating_add(entry.count);
            }
            *mine = top(counts.into_iter(), top_n(entries))
                .into_iter()
                .map(|(key, count)| TopEntry { key, count })
                .collect();
        }
    }
}

impl StatsReport {
    /// Cuts the top lists to `entries` entries.
    pub fn cut_top(&mut self, entries: usize) {
        for list in [
            &mut self.top_names,
            &mut self.top_blocked,
            &mut self.top_clients,
        ] {
            list.truncate(entries);
        }
    }
}

/// `n`, at most what an hour keeps.
fn top_n(n: usize) -> usize {
    n.min(TOP_PER_HOUR)
}

impl QueryLog {
    /// Statistics for the last `hours` hours (1 to 720), the current one
    /// included.
    pub fn stats(&self, hours: u32) -> StatsReport {
        self.stats_top(hours, TOP_IN_REPORT)
    }

    /// Like [`QueryLog::stats`], with up to `top` entries (at most 100) in
    /// each top list.
    pub fn stats_top(&self, hours: u32, top_entries: usize) -> StatsReport {
        let now = Timestamp::now();
        let span = i64::from(hours.clamp(1, 720));
        let from = hour_of(now).saturating_sub(span.saturating_sub(1));
        let data = self
            .aggregator()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .hours(from);
        let mut totals = Counters::default();
        let mut names: HashMap<String, u64> = HashMap::new();
        let mut blocked: HashMap<String, u64> = HashMap::new();
        let mut clients: HashMap<String, u64> = HashMap::new();
        let mut points = Vec::with_capacity(data.len());
        for (hour, data) in data {
            totals.merge(&data.counters);
            for (map, list) in [
                (&mut names, &data.names),
                (&mut blocked, &data.blocked),
                (&mut clients, &data.clients),
            ] {
                for (key, count) in list {
                    let total = map.entry(key.clone()).or_default();
                    *total = total.saturating_add(*count);
                }
            }
            points.push(HourPoint {
                start: Timestamp::from_second(hour.saturating_mul(3600)).unwrap_or(now),
                counters: data.counters,
            });
        }
        let entries = |map: HashMap<String, u64>| {
            top(map.into_iter(), top_n(top_entries))
                .into_iter()
                .map(|(key, count)| TopEntry { key, count })
                .collect()
        };
        StatsReport {
            from: Timestamp::from_second(from.saturating_mul(3600)).unwrap_or(now),
            to: now,
            totals,
            hours: points,
            top_names: entries(names),
            top_blocked: entries(blocked),
            top_clients: entries(clients),
            nodes: Vec::new(),
            unreachable: Vec::new(),
        }
    }
}

pub(crate) fn open_tables(tx: &WriteTransaction) -> Result<(), StoreError> {
    tx.open_table(HOURS)?;
    Ok(())
}

/// The saved hours, newest 30 days.
pub(crate) fn load(store: &Store) -> Result<Aggregator, StoreError> {
    let tx = store.database().begin_read()?;
    let table = tx.open_table(HOURS)?;
    let oldest = hour_of(Timestamp::now()).saturating_sub(RETENTION_HOURS);
    let mut aggregator = Aggregator {
        hour: hour_of(Timestamp::now()),
        ..Aggregator::default()
    };
    for row in table.range(oldest..)? {
        let (hour, bytes) = row?;
        if let Ok(data) = serde_json::from_slice::<Hour>(bytes.value()) {
            aggregator.history.insert(hour.value(), data);
        }
    }
    // Carry on counting a current hour saved before a restart.
    if let Some(saved) = aggregator.history.remove(&aggregator.hour) {
        aggregator.counters = saved.counters;
        for (counter, list) in [
            (&mut aggregator.names, saved.names),
            (&mut aggregator.blocked, saved.blocked),
            (&mut aggregator.clients, saved.clients),
        ] {
            counter.0.extend(list);
        }
    }
    Ok(aggregator)
}

/// Saves the hours that changed and drops those older than 30 days.
pub(crate) fn persist(store: &Store, aggregator: &Mutex<Aggregator>) -> Result<(), StoreError> {
    let (rows, oldest) = {
        let mut aggregator = aggregator.lock().unwrap_or_else(PoisonError::into_inner);
        let oldest = hour_of(Timestamp::now()).saturating_sub(RETENTION_HOURS);
        aggregator.history.retain(|hour, _| *hour >= oldest);
        let unsaved = std::mem::take(&mut aggregator.unsaved);
        let mut rows = Vec::new();
        for hour in unsaved {
            let data = if hour == aggregator.hour {
                Some(aggregator.current())
            } else {
                aggregator.history.get(&hour).cloned()
            };
            if let Some(data) = data {
                rows.push((hour, serde_json::to_vec(&data).map_err(StoreError::Encode)?));
            }
        }
        (rows, oldest)
    };
    let tx = store.database().begin_write()?;
    {
        let mut table = tx.open_table(HOURS)?;
        for (hour, bytes) in &rows {
            table.insert(*hour, bytes.as_slice())?;
        }
        table.retain_in(..oldest, |_, _| false)?;
    }
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::querylog::Protocol;

    fn query(time: &str, name: &str, client: &str, outcome: QueryOutcome) -> (u64, StoredQuery) {
        (
            0,
            StoredQuery {
                time: time.parse().unwrap(),
                client: client.parse().unwrap(),
                protocol: Protocol::Udp,
                qtype: 1,
                rcode: 0,
                outcome,
                elapsed_us: 100,
                name: name.into(),
                client_id: None,
                group: None,
                upstream: None,
                rule: None,
                list: None,
                cname: None,
            },
        )
    }

    #[test]
    fn counts_per_hour_with_top_lists() {
        let mut aggregator = Aggregator::default();
        aggregator.add(&[
            query(
                "2026-10-08T09:10:00Z",
                "a.example.",
                "10.0.0.1",
                QueryOutcome::Forwarded,
            ),
            query(
                "2026-10-08T09:20:00Z",
                "A.example.",
                "10.0.0.1",
                QueryOutcome::Cached,
            ),
            query(
                "2026-10-08T09:30:00Z",
                "ads.example.",
                "10.0.0.2",
                QueryOutcome::Blocked,
            ),
            query(
                "2026-10-08T10:05:00Z",
                "b.example.",
                "10.0.0.2",
                QueryOutcome::Forwarded,
            ),
        ]);
        let nine = hour_of("2026-10-08T09:00:00Z".parse().unwrap());
        let hours = aggregator.hours(nine);
        assert_eq!(hours.len(), 2);
        let first = &hours[0].1;
        assert_eq!(first.counters.queries, 3);
        assert_eq!(first.counters.blocked, 1);
        assert_eq!(first.counters.elapsed_us, 300);
        assert_eq!(
            first.names[0],
            ("a.example.".to_owned(), 2),
            "names are lowercased"
        );
        assert_eq!(first.blocked, [("ads.example.".to_owned(), 1)]);
        assert_eq!(first.clients[0], ("10.0.0.1".to_owned(), 2));
        assert_eq!(hours[1].1.counters.queries, 1);
    }

    #[test]
    fn reports_from_two_nodes_add_up() {
        let hour = |h: i64| Timestamp::from_second(h * 3600).unwrap();
        let counters = |queries: u64, blocked: u64| Counters {
            queries,
            blocked,
            ..Counters::default()
        };
        let entry = |key: &str, count: u64| TopEntry {
            key: key.into(),
            count,
        };
        let mut mine = StatsReport {
            from: hour(10),
            to: hour(12),
            totals: counters(30, 3),
            hours: vec![
                HourPoint {
                    start: hour(10),
                    counters: counters(10, 1),
                },
                HourPoint {
                    start: hour(11),
                    counters: counters(20, 2),
                },
            ],
            top_names: vec![entry("a.example", 20), entry("b.example", 10)],
            top_blocked: vec![entry("ads.example", 3)],
            top_clients: Vec::new(),
            nodes: Vec::new(),
            unreachable: Vec::new(),
        };
        let theirs = StatsReport {
            from: hour(9),
            to: hour(12),
            totals: counters(25, 5),
            hours: vec![
                HourPoint {
                    start: hour(9),
                    counters: counters(5, 0),
                },
                HourPoint {
                    start: hour(11),
                    counters: counters(20, 5),
                },
            ],
            top_names: vec![entry("b.example", 15), entry("c.example", 1)],
            top_blocked: vec![entry("ads.example", 5)],
            top_clients: vec![entry("cl_1", 25)],
            nodes: Vec::new(),
            unreachable: Vec::new(),
        };
        mine.merge(&theirs, 2);
        assert_eq!(mine.from, hour(9));
        assert_eq!((mine.totals.queries, mine.totals.blocked), (55, 8));
        let hours: Vec<_> = mine
            .hours
            .iter()
            .map(|p| (p.start, p.counters.queries))
            .collect();
        assert_eq!(hours, vec![(hour(9), 5), (hour(10), 10), (hour(11), 40)]);
        assert_eq!(
            mine.top_names,
            vec![entry("b.example", 25), entry("a.example", 20)],
            "cut to 2"
        );
        assert_eq!(mine.top_blocked, vec![entry("ads.example", 8)]);
        assert_eq!(mine.top_clients, vec![entry("cl_1", 25)]);
        mine.cut_top(1);
        assert_eq!(mine.top_names.len(), 1);
    }

    #[test]
    fn top_counters_stay_bounded() {
        let mut counter = TopCounter::default();
        for _ in 0..50 {
            counter.add("frequent.example.");
        }
        for i in 0..(MAX_TRACKED * 3) {
            counter.add(&format!("random{i}.example."));
        }
        assert!(counter.0.len() <= MAX_TRACKED);
        assert_eq!(counter.top(1)[0].0, "frequent.example.");
    }
}
