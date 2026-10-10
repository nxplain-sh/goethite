//! Compiling rules into an FST and matching names against it.
//!
//! Every rule becomes one key: its labels in reverse order (`com`, then
//! `example`, then `ads` for `ads.example.com.`), each lowercased and prefixed
//! with its length, so label boundaries stay unambiguous whatever bytes a
//! label holds. Rules for the same name share a key.
//!
//! Every rule also has a [`Source`], usually the list it came from, so one
//! compiled filter serves groups of clients that use different lists: a
//! lookup names the [`Sources`] that apply. A key's value indexes a small
//! table of entries, each holding, for block and allow and for each scope
//! (exact, subtree, subdomains only), the set of sources with such a rule.
//! Keys with the same combination share an entry.
//!
//! Matching walks the FST once along the queried name's key. At every label
//! boundary where a key ends, its entry applies: subtree rules always, exact
//! rules only at the end of the name, subdomains-only rules only before it.
//! One walk therefore checks every suffix of the name at once.
//!
//! A Bloom filter over each rule's top two labels (or its only label) sits in
//! front: a name whose top one or two labels no rule shares cannot match, and
//! is answered without touching the FST.

use std::collections::HashMap;
use std::fmt::Write as _;

use fst::raw::Output;
use fst::{Map, MapBuilder};
use goethite_proto::Name;

use crate::bloom::Bloom;
use crate::rule::{Action, LineKind, Rule, Scope, parse_line};

/// The most rules one filter accepts; more are counted and dropped.
pub const MAX_RULES: usize = 5_000_000;

/// The most sources one filter tells apart.
pub const MAX_SOURCES: usize = 64;

/// The longest key: a name is at most 255 bytes on the wire, and its key
/// drops the root label.
const MAX_KEY_LEN: usize = 255;

/// Where a rule came from, such as a filter list: one of [`MAX_SOURCES`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Source(u8);

impl Source {
    /// The source with this index, if it is below [`MAX_SOURCES`].
    pub fn new(index: usize) -> Option<Self> {
        u8::try_from(index)
            .ok()
            .filter(|&index| usize::from(index) < MAX_SOURCES)
            .map(Self)
    }

    /// Its index.
    pub fn index(self) -> usize {
        usize::from(self.0)
    }

    fn bit(self) -> u64 {
        1_u64.checked_shl(u32::from(self.0)).unwrap_or(0)
    }
}

/// A set of sources.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Sources(u64);

impl Sources {
    /// Every source.
    pub const ALL: Self = Self(u64::MAX);
    /// No source: nothing matches.
    pub const NONE: Self = Self(0);

    /// The set whose bit `i` is source `i`.
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// This set plus `source`.
    #[must_use]
    pub fn with(self, source: Source) -> Self {
        Self(self.0 | source.bit())
    }

    /// Both sets together.
    #[must_use]
    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether `source` is in the set.
    pub fn contains(self, source: Source) -> bool {
        self.0 & source.bit() != 0
    }

    /// Whether the set is empty.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The lowest source in `mask & self`, if any.
    fn first_in(self, mask: u64) -> Option<Source> {
        let both = self.0 & mask;
        (both != 0)
            .then(|| u8::try_from(both.trailing_zeros()).ok())
            .flatten()
            .map(Source)
    }
}

impl FromIterator<Source> for Sources {
    fn from_iter<I: IntoIterator<Item = Source>>(iter: I) -> Self {
        iter.into_iter().fold(Self::NONE, Self::with)
    }
}

/// Index of a rule's action, scope and importance in an [`Entry`].
fn slot(action: Action, scope: Scope, important: bool) -> usize {
    let base: usize = match (action, scope) {
        (Action::Block, Scope::Exact) => 0,
        (Action::Block, Scope::Subtree) => 1,
        (Action::Block, Scope::Subdomains) => 2,
        (Action::Allow, Scope::Exact) => 3,
        (Action::Allow, Scope::Subtree) => 4,
        (Action::Allow, Scope::Subdomains) => 5,
    };
    if important {
        base.saturating_add(6)
    } else {
        base
    }
}

/// For one key: which sources have a rule of each action, scope and
/// importance, indexed by [`slot`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
struct Entry([u64; 12]);

impl Entry {
    fn get(&self, action: Action, scope: Scope, important: bool) -> u64 {
        self.0
            .get(slot(action, scope, important))
            .copied()
            .unwrap_or(0)
    }
}

/// The rule that decided a verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Match {
    /// Where the rule came from.
    pub source: Source,
    /// The rule's scope.
    pub scope: Scope,
    /// How many labels the rule's name has: the rule names the last `labels`
    /// labels of the queried name.
    pub labels: u8,
}

impl Match {
    /// The rule in AdGuard syntax, written out from the queried `name`: for
    /// example `||ads.example^`, `|ads.example^` or `*.ads.example`, with
    /// `@@` in front for an exception.
    pub fn rule_text(&self, name: &Name, action: Action) -> String {
        let skip = name.label_count().saturating_sub(usize::from(self.labels));
        let mut domain = String::new();
        for label in name.labels().skip(skip) {
            if !domain.is_empty() {
                domain.push('.');
            }
            for &byte in label {
                let byte = byte.to_ascii_lowercase();
                if byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' {
                    domain.push(char::from(byte));
                } else {
                    let _ = write!(domain, "\\{byte:03}");
                }
            }
        }
        let prefix = match action {
            Action::Block => "",
            Action::Allow => "@@",
        };
        match self.scope {
            Scope::Exact => format!("{prefix}|{domain}^"),
            Scope::Subtree => format!("{prefix}||{domain}^"),
            Scope::Subdomains => format!("{prefix}*.{domain}"),
        }
    }
}

/// What the filter says about a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// No rule matches.
    Pass,
    /// A block rule matches and no exception does (an `$important` block
    /// even over one).
    Blocked(Match),
    /// An exception matches, so the name is never blocked.
    Allowed(Match),
}

impl Verdict {
    /// Whether the name is blocked.
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked(_))
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
    rules: Vec<(Vec<u8>, Source, u8)>,
    /// The `$badfilter` rules, by the key and slot of the rule each disables.
    badfilters: Vec<(Vec<u8>, u8)>,
    stats: ListStats,
}

impl std::fmt::Debug for FilterBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilterBuilder")
            .field("rules", &self.rules.len())
            .field("badfilters", &self.badfilters.len())
            .field("stats", &self.stats)
            .finish()
    }
}

impl FilterBuilder {
    /// An empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one rule from `source`. Returns false, and adds nothing, for a
    /// rule naming the root (which the parser never produces) and once
    /// [`MAX_RULES`] rules have been added. A `$badfilter` rule adds no rule
    /// of its own: it disables the rule it names when the filter is built.
    pub fn add_rule(&mut self, source: Source, rule: &Rule) -> bool {
        if rule.name.is_root() {
            self.stats.invalid = self.stats.invalid.saturating_add(1);
            return false;
        }
        if self.rules.len().saturating_add(self.badfilters.len()) >= MAX_RULES {
            self.stats.over_limit = self.stats.over_limit.saturating_add(1);
            return false;
        }
        let slot = u8::try_from(slot(rule.action, rule.scope, rule.important)).unwrap_or(0);
        if rule.badfilter {
            self.badfilters.push((key(&rule.name), slot));
            return true;
        }
        self.rules.push((key(&rule.name), source, slot));
        self.stats.rules = self.stats.rules.saturating_add(1);
        true
    }

    /// Adds every rule in `text`, one per line, from `source`, and returns
    /// the counts for this text alone.
    pub fn add_list(&mut self, source: Source, text: &str) -> ListStats {
        let before = self.stats;
        let mut lines = ListStats::default();
        // A byte order mark, as Windows editors write, is not part of the
        // first line.
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        for line in text.lines() {
            match parse_line(line, |rule| {
                self.add_rule(source, &rule);
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
        // `$badfilter` disables the rule it names, from whatever source or
        // list it came: drop the rules it points at before compiling.
        if !self.badfilters.is_empty() {
            let badfilters = std::mem::take(&mut self.badfilters);
            let before = self.rules.len();
            self.rules.retain(|(key, _, slot)| {
                !badfilters
                    .iter()
                    .any(|(bad_key, bad_slot)| bad_key == key && bad_slot == slot)
            });
            let removed = before.saturating_sub(self.rules.len());
            self.stats.rules = self.stats.rules.saturating_sub(removed);
        }
        self.rules.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let mut entries: Vec<Entry> = Vec::new();
        let mut index_of: HashMap<Entry, u64> = HashMap::new();
        let mut keys = 0_usize;
        let mut builder = MapBuilder::memory();
        let mut bloom = Bloom::with_capacity(count_keys(&self.rules));
        let mut rules = self.rules.into_iter().peekable();
        while let Some((key, source, slot)) = rules.next() {
            let mut entry = Entry::default();
            let mut add = |source: Source, slot: u8| {
                if let Some(mask) = entry.0.get_mut(usize::from(slot)) {
                    *mask |= source.bit();
                }
            };
            add(source, slot);
            while let Some((_, source, slot)) = rules.next_if(|next| next.0 == key) {
                add(source, slot);
            }
            let index = *index_of.entry(entry).or_insert_with(|| {
                entries.push(entry);
                u64::try_from(entries.len().saturating_sub(1)).unwrap_or(u64::MAX)
            });
            bloom.insert(anchor(&key));
            builder.insert(&key, index).map_err(FilterError)?;
            keys = keys.saturating_add(1);
        }
        Ok(Filter {
            map: builder.into_map(),
            entries: entries.into_boxed_slice(),
            bloom,
            rules: self.stats.rules,
            keys,
        })
    }
}

/// Distinct keys in sorted `rules`, to size the Bloom filter.
fn count_keys(rules: &[(Vec<u8>, Source, u8)]) -> usize {
    rules
        .iter()
        .zip(rules.iter().skip(1))
        .filter(|(a, b)| a.0 != b.0)
        .count()
        .saturating_add(usize::from(!rules.is_empty()))
}

/// A compiled, immutable filter. Cheap to share; swap a new one in to update.
pub struct Filter {
    map: Map<Vec<u8>>,
    entries: Box<[Entry]>,
    bloom: Bloom,
    rules: usize,
    keys: usize,
}

// Counts only: the FST of a million rules is megabytes.
impl std::fmt::Debug for Filter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Filter")
            .field("rules", &self.rules)
            .field("keys", &self.keys)
            .finish_non_exhaustive()
    }
}

impl Filter {
    /// A filter without rules: every name passes.
    pub fn empty() -> Self {
        Self {
            map: Map::default(),
            entries: Box::default(),
            bloom: Bloom::with_capacity(0),
            rules: 0,
            keys: 0,
        }
    }

    /// Number of rules compiled into the filter.
    pub fn rule_count(&self) -> usize {
        self.rules
    }

    /// Number of distinct names among the rules.
    pub fn name_count(&self) -> usize {
        self.keys
    }

    /// Bytes of memory used by the compiled rules.
    pub fn memory_bytes(&self) -> usize {
        self.map
            .as_fst()
            .as_bytes()
            .len()
            .saturating_add(self.bloom.size())
            .saturating_add(self.entries.len().saturating_mul(size_of::<Entry>()))
    }

    /// What the rules from `sources` say about `name`.
    ///
    /// An `$important` exception wins over everything, then an `$important`
    /// block, then an exception, then a block. Within a kind, the block rule
    /// with the longest name decides; among rules for the same name, an exact
    /// rule comes before a subtree rule and that before a subdomains rule, and
    /// then the lowest source.
    pub fn check(&self, name: &Name, sources: Sources) -> Verdict {
        if sources.is_empty() {
            return Verdict::Pass;
        }
        let mut buffer = [0_u8; MAX_KEY_LEN];
        let Some(key) = key_into(name, &mut buffer) else {
            return Verdict::Pass;
        };
        let top_one = anchor_len(key, 1);
        let top_two = anchor_len(key, 2);
        let maybe = |len: Option<usize>| {
            len.and_then(|len| key.get(..len))
                .is_some_and(|anchor| self.bloom.may_contain(anchor))
        };
        if !maybe(top_one) && !maybe(top_two) {
            return Verdict::Pass;
        }
        self.walk(key, sources)
    }

    /// Walks the FST along `key`, keeping the deepest match of each action
    /// and importance.
    fn walk(&self, key: &[u8], sources: Sources) -> Verdict {
        let fst = self.map.as_fst();
        let mut node = fst.root();
        let mut output = Output::zero();
        let mut position = 0_usize;
        let mut labels = 0_u8;
        let mut block = None;
        let mut allow = None;
        let mut important_block = None;
        let mut important_allow = None;
        while let Some(&len) = key.get(position) {
            let label_end = position.saturating_add(1).saturating_add(usize::from(len));
            let Some(label) = key.get(position..label_end) else {
                break;
            };
            for &byte in label {
                let Some(index) = node.find_input(byte) else {
                    return decide(block, allow, important_block, important_allow);
                };
                let transition = node.transition(index);
                output = output.cat(transition.out);
                node = fst.node(transition.addr);
            }
            position = label_end;
            labels = labels.saturating_add(1);
            if !node.is_final() {
                continue;
            }
            let found = output.cat(node.final_output()).value();
            let Some(entry) = usize::try_from(found)
                .ok()
                .and_then(|index| self.entries.get(index))
            else {
                continue;
            };
            let scopes = if position == key.len() {
                [Scope::Exact, Scope::Subtree]
            } else {
                [Scope::Subtree, Scope::Subdomains]
            };
            let first = |action, important| {
                scopes.into_iter().find_map(|scope| {
                    sources
                        .first_in(entry.get(action, scope, important))
                        .map(|source| Match {
                            source,
                            scope,
                            labels,
                        })
                })
            };
            if let Some(found) = first(Action::Block, false) {
                block = Some(found);
            }
            if let Some(found) = first(Action::Allow, false) {
                allow = Some(found);
            }
            if let Some(found) = first(Action::Block, true) {
                important_block = Some(found);
            }
            if let Some(found) = first(Action::Allow, true) {
                important_allow = Some(found);
            }
        }
        decide(block, allow, important_block, important_allow)
    }
}

/// Which of the four kinds of match wins: an `$important` exception first,
/// then an `$important` block, then an exception, then a block.
fn decide(
    block: Option<Match>,
    allow: Option<Match>,
    important_block: Option<Match>,
    important_allow: Option<Match>,
) -> Verdict {
    if let Some(found) = important_allow {
        return Verdict::Allowed(found);
    }
    if let Some(found) = important_block {
        return Verdict::Blocked(found);
    }
    match (allow, block) {
        (Some(found), _) => Verdict::Allowed(found),
        (None, Some(found)) => Verdict::Blocked(found),
        (None, None) => Verdict::Pass,
    }
}

impl Default for Filter {
    fn default() -> Self {
        Self::empty()
    }
}

/// The key for `name`: labels from the root down, each lowercased and
/// prefixed with its length.
fn key(name: &Name) -> Vec<u8> {
    let mut buffer = [0_u8; MAX_KEY_LEN];
    key_into(name, &mut buffer)
        .map(<[u8]>::to_vec)
        .unwrap_or_default()
}

/// Writes the key for `name` into `buffer`, without allocating. `None` only
/// for a name longer than any valid name.
fn key_into<'a>(name: &Name, buffer: &'a mut [u8; MAX_KEY_LEN]) -> Option<&'a [u8]> {
    let mut len = 0_usize;
    for label in name.labels().rev() {
        let end = len.checked_add(1)?.checked_add(label.len())?;
        let out = buffer.get_mut(len..end)?;
        let (prefix, bytes) = out.split_first_mut()?;
        // Labels are at most 63 bytes, so the length always fits.
        *prefix = u8::try_from(label.len()).unwrap_or(u8::MAX);
        for (to, &from) in bytes.iter_mut().zip(label) {
            *to = from.to_ascii_lowercase();
        }
        len = end;
    }
    buffer.get(..len)
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

/// The verdict of `rules` from `sources` for `name`, computed rule by rule.
/// This is the definition [`Filter::check`] must agree with; tests and
/// fuzzing compare the two.
pub fn reference_check(rules: &[(Source, Rule)], name: &Name, sources: Sources) -> Verdict {
    let rank = |scope| match scope {
        Scope::Exact => 0,
        Scope::Subtree => 1,
        Scope::Subdomains => 2,
    };
    // A `$badfilter` rule disables every rule it names: the same name,
    // scope, action and importance, from any source.
    let disabled = |rule: &Rule| {
        rules.iter().any(|(_, bad)| {
            bad.badfilter
                && bad.name == rule.name
                && bad.scope == rule.scope
                && bad.action == rule.action
                && bad.important == rule.important
        })
    };
    let best = |action, important| {
        rules
            .iter()
            .filter(|(source, rule)| {
                !rule.badfilter
                    && !disabled(rule)
                    && rule.action == action
                    && rule.important == important
                    && sources.contains(*source)
                    && !rule.name.is_root()
                    && rule.matches(name)
            })
            .map(|(source, rule)| Match {
                source: *source,
                scope: rule.scope,
                labels: u8::try_from(rule.name.label_count()).unwrap_or(u8::MAX),
            })
            // Longest name first, then exact before subtree before
            // subdomains, then the lowest source.
            .min_by_key(|found| (std::cmp::Reverse(found.labels), rank(found.scope), found.source))
    };
    decide(
        best(Action::Block, false),
        best(Action::Allow, false),
        best(Action::Block, true),
        best(Action::Allow, true),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn source(index: usize) -> Source {
        Source::new(index).unwrap()
    }

    fn filter(list: &str) -> Filter {
        let mut builder = FilterBuilder::new();
        builder.add_list(source(0), list);
        builder.build().unwrap()
    }

    /// The verdict with every source, reduced to its kind.
    fn kind(filter: &Filter, query: &str) -> &'static str {
        match filter.check(&name(query), Sources::ALL) {
            Verdict::Pass => "pass",
            Verdict::Blocked(_) => "blocked",
            Verdict::Allowed(_) => "allowed",
        }
    }

    #[test]
    fn a_byte_order_mark_is_not_part_of_the_first_line() {
        let mut builder = FilterBuilder::new();
        let stats = builder.add_list(
            source(0),
            "\u{feff}# A list saved on Windows\nads.example\n",
        );
        assert_eq!((stats.rules, stats.ignored, stats.invalid), (1, 1, 0));
        let stats = builder.add_list(source(0), "\u{feff}tracker.example\n");
        assert_eq!((stats.rules, stats.invalid), (1, 0));
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
            ("ads.example", "blocked"),
            ("x.y.ads.example", "blocked"),
            ("good.ads.example", "allowed"),
            ("x.good.ads.example", "allowed"),
            ("tracker.example", "blocked"),
            ("x.tracker.example", "pass"),
            ("cdn.example", "pass"),
            ("img.cdn.example", "blocked"),
            ("pixel.example", "blocked"),
            ("example", "pass"),
            ("badads.example", "pass"),
            ("ADS.Example", "blocked"),
            ("unrelated.test", "pass"),
        ] {
            assert_eq!(kind(&filter, query), verdict, "{query}");
        }
        assert_eq!(filter.rule_count(), 5);
        assert_eq!(filter.name_count(), 5);
    }

    #[test]
    fn important_outranks_exceptions_and_blocks() {
        // An important block beats an exception.
        let important = filter("||ads.example^\n@@||ads.example^\n||ads.example^$important\n");
        assert_eq!(kind(&important, "ads.example"), "blocked");
        // An important exception beats an important block.
        let both = filter("||ads.example^$important\n@@||ads.example^$important\n");
        assert_eq!(kind(&both, "ads.example"), "allowed");
        // A regular exception still beats a regular block.
        let regular = filter("||ads.example^\n@@||ads.example^\n");
        assert_eq!(kind(&regular, "ads.example"), "allowed");
        // Importance belongs to the rule: the exception must carry it too.
        let one = filter("||ads.example^$important\n@@||ads.example^\n");
        assert_eq!(kind(&one, "ads.example"), "blocked");
        // The important rule wins whatever its length.
        let deep = filter("||ads.example^$important\n@@|x.y.ads.example^\n");
        assert_eq!(kind(&deep, "x.y.ads.example"), "blocked");
    }

    #[test]
    fn badfilter_disables_the_rule_it_names() {
        // The disabled rule goes away; the line counts no rule of its own.
        let gone = filter("||ads.example^\n||ads.example^$badfilter\n");
        assert_eq!(kind(&gone, "ads.example"), "pass");
        // Neither the disabled rule nor the badfilter itself counts.
        assert_eq!(gone.rule_count(), 0);
        // `$badfilter` names the same modifiers too.
        let important_left = filter("||ads.example^$important\n||ads.example^$badfilter\n");
        assert_eq!(kind(&important_left, "ads.example"), "blocked");
        let important_gone = filter("||ads.example^$important\n||ads.example^$important,badfilter\n");
        assert_eq!(kind(&important_gone, "ads.example"), "pass");
        // It reaches an exception, across lists.
        let mut builder = FilterBuilder::new();
        builder.add_list(source(0), "@@||good.example^\n");
        builder.add_list(source(1), "@@||good.example^$badfilter\n");
        let exceptions = builder.build().unwrap();
        assert_eq!(kind(&exceptions, "good.example"), "pass");
        // A badfilter for a rule nobody wrote changes nothing.
        let stray = filter("||ads.example^\n||other.example^$badfilter\n");
        assert_eq!(kind(&stray, "ads.example"), "blocked");
    }

    #[test]
    fn matches_name_the_deciding_rule() {
        let filter = filter("||ads.example^\n|x.ads.example^\n*.cdn.example\n@@|ok.ads.example^\n");
        let check = |query: &str| filter.check(&name(query), Sources::ALL);
        let Verdict::Blocked(found) = check("y.x.ads.example") else {
            panic!("blocked")
        };
        // The subtree rule for ads.example; x.ads.example is exact only.
        assert_eq!((found.scope, found.labels), (Scope::Subtree, 2));
        assert_eq!(
            found.rule_text(&name("y.x.ads.example"), Action::Block),
            "||ads.example^"
        );
        let Verdict::Blocked(exact) = check("X.ads.example") else {
            panic!("blocked")
        };
        // The deepest rule decides.
        assert_eq!((exact.scope, exact.labels), (Scope::Exact, 3));
        assert_eq!(
            exact.rule_text(&name("X.ads.example"), Action::Block),
            "|x.ads.example^"
        );
        let Verdict::Blocked(below) = check("img.cdn.example") else {
            panic!("blocked")
        };
        assert_eq!(
            below.rule_text(&name("img.cdn.example"), Action::Block),
            "*.cdn.example"
        );
        let Verdict::Allowed(ok) = check("ok.ads.example") else {
            panic!("allowed")
        };
        assert_eq!(
            ok.rule_text(&name("ok.ads.example"), Action::Allow),
            "@@|ok.ads.example^"
        );
    }

    #[test]
    fn sources_select_rules() {
        let mut builder = FilterBuilder::new();
        builder.add_list(source(0), "||ads.example^\n");
        builder.add_list(source(5), "||ads.example^\n||social.example^\n");
        builder.add_list(source(63), "@@||ads.example^\n");
        assert!(Source::new(64).is_none());
        let filter = builder.build().unwrap();
        let check = |query: &str, sources: &[usize]| {
            filter.check(&name(query), sources.iter().map(|&i| source(i)).collect())
        };
        let Verdict::Blocked(found) = check("ads.example", &[0, 5]) else {
            panic!("blocked")
        };
        assert_eq!(found.source, source(0), "the lowest source");
        let Verdict::Blocked(found) = check("ads.example", &[5]) else {
            panic!("blocked")
        };
        assert_eq!(found.source, source(5));
        assert!(check("social.example", &[5]).is_blocked());
        assert_eq!(check("social.example", &[0]), Verdict::Pass);
        assert!(matches!(
            check("ads.example", &[0, 63]),
            Verdict::Allowed(_)
        ));
        assert_eq!(check("ads.example", &[]), Verdict::Pass);
        assert_eq!(filter.name_count(), 2);
    }

    #[test]
    fn top_level_rules_and_the_root() {
        let filter = filter("||zip^\n");
        assert_eq!(kind(&filter, "anything.zip"), "blocked");
        assert_eq!(kind(&filter, "zip"), "blocked");
        assert_eq!(kind(&filter, "zip.example"), "pass");
        assert_eq!(filter.check(&Name::root(), Sources::ALL), Verdict::Pass);
    }

    #[test]
    fn labels_with_unusual_bytes_do_not_confuse_boundaries() {
        let mut builder = FilterBuilder::new();
        let dotted = Name::from_labels([&b"a.b"[..], b"example"]).unwrap();
        builder.add_rule(
            source(0),
            &Rule::new(dotted.clone(), Scope::Exact, Action::Block),
        );
        let filter = builder.build().unwrap();
        let Verdict::Blocked(found) = filter.check(&dotted, Sources::ALL) else {
            panic!("blocked")
        };
        assert_eq!(found.rule_text(&dotted, Action::Block), "|a\\046b.example^");
        assert_eq!(kind(&filter, "a.b.example"), "pass");
    }

    #[test]
    fn the_longest_names_fit_the_key_buffer() {
        let label = [b'a'; 63];
        let longest = Name::from_labels([&label[..], &label, &label, &label[..61]]).unwrap();
        let mut builder = FilterBuilder::new();
        builder.add_rule(
            source(0),
            &Rule::new(longest.clone(), Scope::Exact, Action::Block),
        );
        let filter = builder.build().unwrap();
        assert!(filter.check(&longest, Sources::ALL).is_blocked());
    }

    #[test]
    fn rules_for_the_root_are_refused() {
        // Found by fuzzing (fuzz/artifacts/parse-list): a root rule matched
        // `.` in the reference but not in the compiled filter.
        let root_rule = Rule::new(Name::root(), Scope::Exact, Action::Block);
        let mut builder = FilterBuilder::new();
        assert!(!builder.add_rule(source(0), &root_rule));
        assert_eq!(builder.stats().invalid, 1);
        let filter = builder.build().unwrap();
        let rules = [(source(0), root_rule)];
        for query in [Name::root(), name("example")] {
            assert_eq!(filter.check(&query, Sources::ALL), Verdict::Pass);
            assert_eq!(reference_check(&rules, &query, Sources::ALL), Verdict::Pass);
        }
    }

    #[test]
    fn counts_and_limits() {
        let mut builder = FilterBuilder::new();
        let stats = builder.add_list(
            source(0),
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
        assert_eq!(
            Filter::empty().check(&name("a.example"), Sources::ALL),
            Verdict::Pass
        );
    }
}
