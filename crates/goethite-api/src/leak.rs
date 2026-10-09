//! DNS leak tests: whether a device's lookups reach goethite, and how.
//!
//! A test is [`PROBES`] names under [`ZONE`], which no one but goethite
//! answers (the `test` top-level domain is reserved, RFC 6761):
//! `<id>-<n>.leak.goethite.test.`. A device looks them up through whatever
//! resolver it uses; the web UI makes the browser do it by loading images
//! from them. The lookups that reach goethite are recorded with how they
//! arrived: from which address, over which protocol, as which client.
//! Names that never arrive were asked somewhere else: a leak.
//!
//! Everything is bounded: at most [`MAX_TESTS`] tests, each kept for
//! [`LIFETIME`] with at most [`MAX_LOOKUPS`] lookups; lookups for names
//! goethite did not hand out are not recorded. Tests live in memory, on the
//! node that made them.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use goethite_proto::{Name, RecordType};
use goethite_store::Protocol;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The zone test names are in.
pub const ZONE: &str = "leak.goethite.test.";
/// Names in one test.
pub const PROBES: u8 = 8;
/// Tests kept; making another forgets the oldest.
pub const MAX_TESTS: usize = 32;
/// Lookups recorded for one test.
pub const MAX_LOOKUPS: usize = 64;
/// How long a test is kept, and lookups for it recorded.
pub const LIFETIME: Duration = Duration::from_secs(3_600);

/// Hex digits in a test ID: 128 random bits.
const ID_LEN: usize = 32;

/// A test: the names to look up, and the lookups that reached goethite.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LeakTest {
    /// The test's ID.
    pub id: String,
    /// The names to look up, in order.
    pub names: Vec<String>,
    /// When the test was made.
    pub created_at: Timestamp,
    /// Until when the test is kept and lookups for it are recorded.
    pub expires_at: Timestamp,
    /// The address the test was made from, as the API saw it: the device
    /// being tested, when the web UI runs the test in its browser.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<String>,
    /// How many of the names reached goethite.
    pub reached: u32,
    /// The lookups that reached goethite, oldest first; at most 64.
    pub lookups: Vec<LeakLookup>,
}

/// A lookup of a test name that reached goethite.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LeakLookup {
    /// Which of the test's names, from 1.
    pub probe: u8,
    /// When it arrived.
    pub time: Timestamp,
    /// The address it came from.
    pub address: String,
    /// How it arrived.
    pub protocol: Protocol,
    /// The type asked for, such as `A` or `AAAA`.
    pub qtype: String,
    /// The known client it was identified as.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    /// The group whose filtering applies to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Whether that client's queries are filtered: its group filters and
    /// protection is on and not paused.
    pub filtering: bool,
}

/// The tests this node has, newest first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LeakTestList {
    /// The tests.
    pub tests: Vec<LeakTest>,
}

/// How a lookup arrived, for [`LeakTests::observe`].
#[derive(Clone, Debug)]
pub struct Arrival {
    /// The address it came from.
    pub address: IpAddr,
    /// How it arrived.
    pub protocol: Protocol,
    /// The type asked for.
    pub qtype: RecordType,
    /// The known client it was identified as.
    pub client: Option<Arc<str>>,
    /// Its group.
    pub group: Option<Arc<str>>,
    /// Whether its queries are filtered.
    pub filtering: bool,
}

struct Test {
    id: String,
    created_at: Timestamp,
    created: Instant,
    requested_by: Option<IpAddr>,
    lookups: Vec<LeakLookup>,
}

/// This node's leak tests.
pub struct LeakTests {
    zone: Name,
    tests: Mutex<VecDeque<Test>>,
}

impl std::fmt::Debug for LeakTests {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeakTests").finish_non_exhaustive()
    }
}

impl Default for LeakTests {
    fn default() -> Self {
        Self::new()
    }
}

impl LeakTests {
    /// No tests yet.
    pub fn new() -> Self {
        Self {
            zone: zone(),
            tests: Mutex::new(VecDeque::new()),
        }
    }

    /// Makes a test, for a device at `requested_by`.
    pub fn create(&self, requested_by: Option<IpAddr>) -> LeakTest {
        self.create_at(requested_by, Instant::now(), Timestamp::now())
    }

    fn create_at(&self, requested_by: Option<IpAddr>, now: Instant, at: Timestamp) -> LeakTest {
        let mut id = String::with_capacity(ID_LEN);
        for byte in rand::random::<[u8; 16]>() {
            let _ = write!(id, "{byte:02x}");
        }
        let test = Test {
            id,
            created_at: at,
            created: now,
            requested_by,
            lookups: Vec::new(),
        };
        let shown = show(&test);
        let mut tests = self.lock();
        forget_expired(&mut tests, now);
        while tests.len() >= MAX_TESTS {
            tests.pop_front();
        }
        tests.push_back(test);
        shown
    }

    /// The test with `id`, if it is still kept.
    pub fn get(&self, id: &str) -> Option<LeakTest> {
        let mut tests = self.lock();
        forget_expired(&mut tests, Instant::now());
        tests
            .iter()
            .find(|test| test.id.eq_ignore_ascii_case(id))
            .map(show)
    }

    /// Every test kept, newest first.
    pub fn list(&self) -> LeakTestList {
        let mut tests = self.lock();
        forget_expired(&mut tests, Instant::now());
        LeakTestList {
            tests: tests.iter().rev().map(show).collect(),
        }
    }

    /// Records a query for `name` if it is a test name this node handed
    /// out. Cheap for any other name: one suffix comparison, no lock.
    pub fn observe(&self, name: &Name, arrival: impl FnOnce() -> Arrival) {
        if !name.is_within(&self.zone) {
            return;
        }
        let Some((id, probe)) = parse_probe(name) else {
            return;
        };
        let now = Instant::now();
        let mut tests = self.lock();
        forget_expired(&mut tests, now);
        let Some(test) = tests.iter_mut().find(|test| test.id == id) else {
            return;
        };
        if test.lookups.len() >= MAX_LOOKUPS {
            return;
        }
        let arrival = arrival();
        test.lookups.push(LeakLookup {
            probe,
            time: Timestamp::now(),
            address: arrival.address.to_string(),
            protocol: arrival.protocol,
            qtype: arrival.qtype.to_string(),
            client: arrival.client.map(|client| client.to_string()),
            group: arrival.group.map(|group| group.to_string()),
            filtering: arrival.filtering,
        });
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, VecDeque<Test>> {
        self.tests.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn zone() -> Name {
    ZONE.parse().unwrap_or_else(|_| Name::root())
}

fn forget_expired(tests: &mut VecDeque<Test>, now: Instant) {
    while tests
        .front()
        .is_some_and(|test| now.saturating_duration_since(test.created) >= LIFETIME)
    {
        tests.pop_front();
    }
}

fn show(test: &Test) -> LeakTest {
    let mut reached: Vec<u8> = test.lookups.iter().map(|lookup| lookup.probe).collect();
    reached.sort_unstable();
    reached.dedup();
    let lifetime = jiff::SignedDuration::try_from(LIFETIME).unwrap_or_default();
    LeakTest {
        id: test.id.clone(),
        names: (1..=PROBES).map(|n| probe_name(&test.id, n)).collect(),
        created_at: test.created_at,
        expires_at: test
            .created_at
            .saturating_add(lifetime)
            .unwrap_or(test.created_at),
        requested_by: test.requested_by.map(|address| address.to_string()),
        reached: u32::try_from(reached.len()).unwrap_or(u32::MAX),
        lookups: test.lookups.clone(),
    }
}

/// The `n`th name of the test with `id`.
fn probe_name(id: &str, n: u8) -> String {
    format!("{id}-{n}.{ZONE}")
}

/// The test ID and probe number in a test name, `<id>-<n>.leak.goethite.test.`:
/// 32 hex digits (any case, since resolvers on the way may change it) and a
/// number from 1 to [`PROBES`].
pub fn parse_probe(name: &Name) -> Option<(String, u8)> {
    if name.parent()? != zone() {
        return None;
    }
    let label = name.labels().next()?;
    let (id, n) = label.split_at_checked(ID_LEN)?;
    let digit = match n {
        [b'-', digit] => *digit,
        _ => return None,
    };
    let probe = digit
        .checked_sub(b'0')
        .filter(|n| (1..=PROBES).contains(n))?;
    if !id.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let id = std::str::from_utf8(id).ok()?.to_ascii_lowercase();
    Some((id, probe))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arrival() -> Arrival {
        Arrival {
            address: "192.0.2.7".parse().unwrap(),
            protocol: Protocol::Doh,
            qtype: RecordType::AAAA,
            client: Some("phone".into()),
            group: Some("kids".into()),
            filtering: true,
        }
    }

    #[test]
    fn names_go_and_come_back() {
        let tests = LeakTests::new();
        let test = tests.create(Some("192.0.2.7".parse().unwrap()));
        assert_eq!(test.names.len(), usize::from(PROBES));
        assert_eq!(test.reached, 0);
        assert_eq!(test.requested_by.as_deref(), Some("192.0.2.7"));
        for (i, name) in test.names.iter().enumerate() {
            let parsed = parse_probe(&name.parse().unwrap()).unwrap();
            assert_eq!(parsed, (test.id.clone(), u8::try_from(i + 1).unwrap()));
        }
        // Twice for the third name (A and AAAA), once for the first, in
        // another case: two names reached.
        let third: Name = test.names[2].parse().unwrap();
        tests.observe(&third, arrival);
        tests.observe(&third, arrival);
        let shouted: Name = test.names[0].to_uppercase().parse().unwrap();
        tests.observe(&shouted, arrival);
        let seen = tests.get(&test.id).unwrap();
        assert_eq!(seen.reached, 2);
        assert_eq!(seen.lookups.len(), 3);
        let lookup = &seen.lookups[0];
        assert_eq!(lookup.probe, 3);
        assert_eq!(lookup.protocol, Protocol::Doh);
        assert_eq!(lookup.qtype, "AAAA");
        assert_eq!(lookup.client.as_deref(), Some("phone"));
        assert!(lookup.filtering);
        assert_eq!(tests.list().tests.len(), 1);
    }

    #[test]
    fn only_names_handed_out_are_recorded() {
        let tests = LeakTests::new();
        let test = tests.create(None);
        let made_up = format!("{}-1.{ZONE}", "ab".repeat(16));
        tests.observe(&made_up.parse().unwrap(), || panic!("not a test"));
        tests.observe(&"www.example.com.".parse().unwrap(), || {
            panic!("not a test")
        });
        for bad in [
            format!("{}-9.{ZONE}", test.id),
            format!("{}-0.{ZONE}", test.id),
            format!("{}-1.x.{ZONE}", test.id),
            format!("{}-1.{ZONE}", test.id.get(1..).unwrap()),
            format!("{}g-1.{ZONE}", test.id.get(1..).unwrap()),
            format!("{}-1.goethite.test.", test.id),
        ] {
            assert_eq!(parse_probe(&bad.parse().unwrap()), None, "{bad}");
        }
        assert_eq!(tests.get(&test.id).unwrap().lookups.len(), 0);
    }

    #[test]
    fn everything_is_bounded() {
        let tests = LeakTests::new();
        let first = tests.create(None);
        for _ in 0..MAX_TESTS {
            tests.create(None);
        }
        assert!(tests.get(&first.id).is_none(), "the oldest is forgotten");
        assert_eq!(tests.list().tests.len(), MAX_TESTS);
        let test = tests.create(None);
        let name: Name = test.names[0].parse().unwrap();
        for _ in 0..MAX_LOOKUPS + 10 {
            tests.observe(&name, arrival);
        }
        assert_eq!(tests.get(&test.id).unwrap().lookups.len(), MAX_LOOKUPS);
        // And kept for LIFETIME only.
        let tests = LeakTests::new();
        let old = tests.create(None);
        tests.lock()[0].created = Instant::now().checked_sub(LIFETIME).unwrap();
        assert!(tests.get(&old.id).is_none());
    }
}
