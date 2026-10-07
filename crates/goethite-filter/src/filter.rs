//! Compiling rules into an FST and matching names against it.
//!
//! Every rule becomes one key: its labels in reverse order (`com`, then
//! `example`, then `ads` for `ads.example.com.`), each lowercased and prefixed
//! with its length, so label boundaries stay unambiguous whatever bytes a
//! label holds. The key's value is a set of flags: block or allow, and exact,
//! subtree or subdomains-only. Rules for the same name share a key.
//!
//! Matching walks the FST once along the queried name's key. At every label
//! boundary where a key ends, its flags apply: subtree flags always, exact
//! flags only at the end of the name, subdomains-only flags only before it.
//! One walk therefore checks every suffix of the name at once.
//!
//! A Bloom filter over each rule's top two labels (or its only label) sits in
//! front: a name whose top one or two labels no rule shares cannot match, and
//! is answered without touching the FST.

use fst::raw::{Fst, Output};
use fst::{Map, MapBuilder};
use goethite_proto::Name;

use crate::bloom::Bloom;
use crate::rule::{Action, LineKind, Rule, Scope, parse_line};

/// The most rules one filter accepts; more are counted and dropped.
pub const MAX_RULES: usize = 5_000_000;

const BLOCK_EXACT: u64 = 1;
const BLOCK_SUBTREE: u64 = 1 << 1;
const BLOCK_SUBDOMAINS: u64 = 1 << 2;
const ALLOW_EXACT: u64 = 1 << 3;
const ALLOW_SUBTREE: u64 = 1 << 4;
const ALLOW_SUBDOMAINS: u64 = 1 << 5;

const BLOCK: u64 = BLOCK_EXACT | BLOCK_SUBTREE | BLOCK_SUBDOMAINS;
const ALLOW: u64 = ALLOW_EXACT | ALLOW_SUBTREE | ALLOW_SUBDOMAINS;
/// Flags that apply when the key covers the whole queried name.
const AT_NAME: u64 = BLOCK_EXACT | BLOCK_SUBTREE | ALLOW_EXACT | ALLOW_SUBTREE;
/// Flags that apply when the key is a proper suffix of the queried name.
const ABOVE_NAME: u64 = BLOCK_SUBTREE | BLOCK_SUBDOMAINS | ALLOW_SUBTREE | ALLOW_SUBDOMAINS;

fn flag(rule: &Rule) -> u64 {
    match (rule.action, rule.scope) {
        (Action::Block, Scope::Exact) => BLOCK_EXACT,
        (Action::Block, Scope::Subtree) => BLOCK_SUBTREE,
        (Action::Block, Scope::Subdomains) => BLOCK_SUBDOMAINS,
        (Action::Allow, Scope::Exact) => ALLOW_EXACT,
        (Action::Allow, Scope::Subtree) => ALLOW_SUBTREE,
        (Action::Allow, Scope::Subdomains) => ALLOW_SUBDOMAINS,
    }
}

/// What the filter says about a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// No rule matches.
    Pass,
    /// A block rule matches and no exception does.
    Blocked,
    /// An exception matches, so the name is never blocked.
    Allowed,
}

impl Verdict {
    fn from_flags(flags: u64) -> Self {
        if flags & ALLOW != 0 {
            Self::Allowed
        } else if flags & BLOCK != 0 {
            Self::Blocked
        } else {
            Self::Pass
        }
    }
}

/// Counts from reading rules, for logs and the API.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ListStats {
    /// Rules added.
    pub rules: usize,
    /// Comments, headers and blank lines.
    pub ignored: usize,
    /// Lines with syntax goethite does not support yet.
    pub unsupported: usize,
    /// Lines that are not valid rules.
    pub invalid: usize,
    /// Rules dropped because the filter reached [`MAX_RULES`].
    pub over_limit: usize,
}

impl ListStats {
    fn add(&mut self, other: Self) {
        self.rules = self.rules.saturating_add(other.rules);
        self.ignored = self.ignored.saturating_add(other.ignored);
        self.unsupported = self.unsupported.saturating_add(other.unsupported);
        self.invalid = self.invalid.saturating_add(other.invalid);
        self.over_limit = self.over_limit.saturating_add(other.over_limit);
    }
}

/// Why a filter could not be built.
#[derive(Debug, thiserror::Error)]
#[error("cannot build the filter: {0}")]
pub struct FilterError(fst::Error);

/// Collects rules and compiles them into a [`Filter`].
#[derive(Default)]
pub struct FilterBuilder {
    entries: Vec<(Vec<u8>, u64)>,
    stats: ListStats,
}

impl FilterBuilder {
    /// An empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one rule. Returns false, and adds nothing, for a rule naming the
    /// root (which the parser never produces) and once [`MAX_RULES`] rules
    /// have been added.
    pub fn add_rule(&mut self, rule: &Rule) -> bool {
        if rule.name.is_root() {
            self.stats.invalid = self.stats.invalid.saturating_add(1);
            return false;
        }
        if self.entries.len() >= MAX_RULES {
            self.stats.over_limit = self.stats.over_limit.saturating_add(1);
            return false;
        }
        self.entries.push((key(&rule.name), flag(rule)));
        self.stats.rules = self.stats.rules.saturating_add(1);
        true
    }

    /// Adds every rule in `text`, one per line, and returns the counts for
    /// this text alone.
    pub fn add_list(&mut self, text: &str) -> ListStats {
        let before = self.stats;
        let mut lines = ListStats::default();
        for line in text.lines() {
            match parse_line(line, |rule| {
                self.add_rule(&rule);
            }) {
                LineKind::Rules(_) => {}
                LineKind::Ignored => lines.ignored = lines.ignored.saturating_add(1),
                LineKind::Unsupported(_) => {
                    lines.unsupported = lines.unsupported.saturating_add(1);
                }
                LineKind::Invalid(_) => lines.invalid = lines.invalid.saturating_add(1),
            }
        }
        self.stats.add(lines);
        ListStats {
            rules: self.stats.rules.saturating_sub(before.rules),
            over_limit: self.stats.over_limit.saturating_sub(before.over_limit),
            ..lines
        }
    }

    /// Counts over everything added so far.
    pub fn stats(&self) -> ListStats {
        self.stats
    }

    /// Compiles the rules.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the FST cannot be built, which does not
    /// happen for keys this builder produced.
    pub fn build(mut self) -> Result<Filter, FilterError> {
        self.entries.sort_unstable();
        let mut merged: Vec<(Vec<u8>, u64)> = Vec::with_capacity(self.entries.len());
        for (key, flags) in self.entries {
            match merged.last_mut() {
                Some((last, last_flags)) if *last == key => *last_flags |= flags,
                _ => merged.push((key, flags)),
            }
        }
        let mut bloom = Bloom::with_capacity(merged.len());
        let mut builder = MapBuilder::memory();
        for (key, flags) in &merged {
            bloom.insert(anchor(key));
            builder.insert(key, *flags).map_err(FilterError)?;
        }
        Ok(Filter {
            map: builder.into_map(),
            bloom,
            rules: self.stats.rules,
        })
    }
}

/// A compiled, immutable filter. Cheap to share; swap a new one in to update.
pub struct Filter {
    map: Map<Vec<u8>>,
    bloom: Bloom,
    rules: usize,
}

impl Filter {
    /// A filter without rules: every name passes.
    pub fn empty() -> Self {
        Self {
            map: Map::default(),
            bloom: Bloom::with_capacity(0),
            rules: 0,
        }
    }

    /// Number of rules compiled into the filter.
    pub fn rule_count(&self) -> usize {
        self.rules
    }

    /// Bytes of memory used by the compiled rules.
    pub fn memory_bytes(&self) -> usize {
        self.map
            .as_fst()
            .as_bytes()
            .len()
            .saturating_add(self.bloom.size())
    }

    /// What the rules say about `name`.
    pub fn check(&self, name: &Name) -> Verdict {
        let key = key(name);
        let top_one = anchor_len(&key, 1);
        let top_two = anchor_len(&key, 2);
        let maybe = |len: Option<usize>| {
            len.and_then(|len| key.get(..len))
                .is_some_and(|anchor| self.bloom.may_contain(anchor))
        };
        if !maybe(top_one) && !maybe(top_two) {
            return Verdict::Pass;
        }
        Verdict::from_flags(walk(self.map.as_fst(), &key))
    }
}

impl Default for Filter {
    fn default() -> Self {
        Self::empty()
    }
}

/// Collects the flags that apply to the name encoded in `key`.
fn walk(fst: &Fst<Vec<u8>>, key: &[u8]) -> u64 {
    let mut node = fst.root();
    let mut output = Output::zero();
    let mut flags = 0;
    let mut position = 0_usize;
    while let Some(&len) = key.get(position) {
        let label_end = position.saturating_add(1).saturating_add(usize::from(len));
        let Some(label) = key.get(position..label_end) else {
            break;
        };
        for &byte in label {
            let Some(index) = node.find_input(byte) else {
                return flags;
            };
            let transition = node.transition(index);
            output = output.cat(transition.out);
            node = fst.node(transition.addr);
        }
        position = label_end;
        if node.is_final() {
            let found = output.cat(node.final_output()).value();
            let applicable = if position == key.len() {
                AT_NAME
            } else {
                ABOVE_NAME
            };
            flags |= found & applicable;
        }
    }
    flags
}

/// The key for `name`: labels from the root down, each lowercased and
/// prefixed with its length.
fn key(name: &Name) -> Vec<u8> {
    let mut key = Vec::with_capacity(name.label_count().saturating_mul(16));
    for label in name.labels().rev() {
        // Labels are at most 63 bytes, so the length always fits.
        key.push(u8::try_from(label.len()).unwrap_or(u8::MAX));
        key.extend(label.iter().map(u8::to_ascii_lowercase));
    }
    key
}

/// The length of the first `labels` labels of `key`, if it has that many.
fn anchor_len(key: &[u8], labels: usize) -> Option<usize> {
    let mut position = 0_usize;
    for _ in 0..labels {
        let len = *key.get(position)?;
        position = position.saturating_add(1).saturating_add(usize::from(len));
    }
    (position <= key.len()).then_some(position)
}

/// A rule key's Bloom anchor: its first two labels, or all of it if shorter.
fn anchor(key: &[u8]) -> &[u8] {
    let len = anchor_len(key, 2).unwrap_or(key.len());
    key.get(..len).unwrap_or(key)
}

/// The verdict of `rules` for `name`, computed rule by rule. This is the
/// definition [`Filter::check`] must agree with; tests and fuzzing compare
/// the two.
pub fn reference_check(rules: &[Rule], name: &Name) -> Verdict {
    let mut flags = 0;
    let valid = rules.iter().filter(|rule| !rule.name.is_root());
    for rule in valid.filter(|rule| rule.matches(name)) {
        flags |= flag(rule);
    }
    Verdict::from_flags(flags)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn filter(list: &str) -> Filter {
        let mut builder = FilterBuilder::new();
        builder.add_list(list);
        builder.build().unwrap()
    }

    #[test]
    fn scopes_and_exceptions() {
        let filter = filter(
            "||ads.example^\n\
             tracker.example\n\
             *.cdn.example\n\
             @@||good.ads.example^\n\
             0.0.0.0 pixel.example\n",
        );
        for (query, verdict) in [
            ("ads.example", Verdict::Blocked),
            ("x.y.ads.example", Verdict::Blocked),
            ("good.ads.example", Verdict::Allowed),
            ("x.good.ads.example", Verdict::Allowed),
            ("tracker.example", Verdict::Blocked),
            ("x.tracker.example", Verdict::Pass),
            ("cdn.example", Verdict::Pass),
            ("img.cdn.example", Verdict::Blocked),
            ("pixel.example", Verdict::Blocked),
            ("example", Verdict::Pass),
            ("badads.example", Verdict::Pass),
            ("ADS.Example", Verdict::Blocked),
            ("unrelated.test", Verdict::Pass),
        ] {
            assert_eq!(filter.check(&name(query)), verdict, "{query}");
        }
        assert_eq!(filter.rule_count(), 5);
    }

    #[test]
    fn top_level_rules_and_the_root() {
        let filter = filter("||zip^\n");
        assert_eq!(filter.check(&name("anything.zip")), Verdict::Blocked);
        assert_eq!(filter.check(&name("zip")), Verdict::Blocked);
        assert_eq!(filter.check(&name("zip.example")), Verdict::Pass);
        assert_eq!(filter.check(&Name::root()), Verdict::Pass);
    }

    #[test]
    fn labels_with_unusual_bytes_do_not_confuse_boundaries() {
        let mut builder = FilterBuilder::new();
        let dotted = Name::from_labels([&b"a.b"[..], b"example"]).unwrap();
        builder.add_rule(&Rule {
            name: dotted.clone(),
            scope: Scope::Exact,
            action: Action::Block,
        });
        let filter = builder.build().unwrap();
        assert_eq!(filter.check(&dotted), Verdict::Blocked);
        assert_eq!(filter.check(&name("a.b.example")), Verdict::Pass);
    }

    #[test]
    fn rules_for_the_root_are_refused() {
        // Found by fuzzing (fuzz/artifacts/parse_list): a root rule matched
        // `.` in the reference but not in the compiled filter.
        let root_rule = Rule {
            name: Name::root(),
            scope: Scope::Exact,
            action: Action::Block,
        };
        let mut builder = FilterBuilder::new();
        assert!(!builder.add_rule(&root_rule));
        assert_eq!(builder.stats().invalid, 1);
        let filter = builder.build().unwrap();
        let rules = [root_rule];
        for query in [Name::root(), name("example")] {
            assert_eq!(filter.check(&query), Verdict::Pass);
            assert_eq!(reference_check(&rules, &query), Verdict::Pass);
        }
    }

    #[test]
    fn counts_and_limits() {
        let mut builder = FilterBuilder::new();
        let stats = builder.add_list(
            "! comment\n||a.example^\n/regex/\nnot valid!\n\n0.0.0.0 b.example c.example\n",
        );
        assert_eq!(
            stats,
            ListStats {
                rules: 3,
                ignored: 2,
                unsupported: 1,
                invalid: 1,
                over_limit: 0
            }
        );
        let filter = builder.build().unwrap();
        assert!(filter.memory_bytes() > 0);
        assert_eq!(Filter::empty().check(&name("a.example")), Verdict::Pass);
    }
}
