//! A sharded, bounded TTL cache of upstream answers.
//!
//! The cache is split into shards, each behind its own mutex, so concurrent
//! queries rarely contend; a lock is only ever held for a short synchronous
//! map operation, never across an `.await`. Each shard holds a bounded number
//! of entries and evicts the oldest first.
//!
//! What is stored is deliberately narrow, to resist cache poisoning: only the
//! CNAME chain that answers the question and the records at its end, never
//! unrelated records from the answer, authority or additional sections. A
//! negative answer is cached only with an SOA record for a zone the name is
//! in, and for no longer than that SOA allows (RFC 2308). For clients that
//! set DO, the DNSSEC records that go with those are kept too: the RRSIGs
//! covering them, DNAMEs behind their CNAMEs, and NSEC and NSEC3 proofs.
//! Whether DNSSEC proved an answer authentic (AD) is kept with it.

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, VecDeque};
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use goethite_proto::{Name, Query, Record, RecordClass, RecordType, Response, ResponseCode};

use crate::restore_question_case;

/// The longest CNAME chain that is cached.
pub const MAX_CNAME_CHAIN: usize = 16;

/// Answers with more records than this are passed on but not cached, which
/// bounds the memory a single entry can take.
pub const MAX_CACHED_RECORDS: usize = 32;

/// The most entries a cache may be configured with.
pub const MAX_ENTRIES: usize = 1_000_000;

/// How many independently locked shards the cache is split into.
const SHARDS: usize = 16;

/// Cache settings.
#[derive(Clone, Debug)]
pub struct CacheConfig {
    /// Most entries kept; 0 turns the cache off. At most [`MAX_ENTRIES`].
    pub max_entries: usize,
    /// Positive answers are kept at least this many seconds, even if their
    /// TTL is lower (but TTL 0 is never cached).
    pub min_ttl: u32,
    /// Positive answers are kept at most this many seconds.
    pub max_ttl: u32,
    /// Negative answers (NXDOMAIN, NODATA) are kept at most this many seconds.
    pub max_negative_ttl: u32,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            min_ttl: 0,
            max_ttl: 86_400,
            max_negative_ttl: 3_600,
        }
    }
}

/// Hit and miss counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheStats {
    /// Lookups answered from the cache.
    pub hits: u64,
    /// Lookups that were not.
    pub misses: u64,
}

/// What a cached answer is stored under. `Name` compares and hashes without
/// regard to case, so differently cased queries share an entry.
#[derive(Clone, PartialEq, Eq, Hash)]
struct Key {
    name: Name,
    qtype: RecordType,
    qclass: RecordClass,
    dnssec_ok: bool,
    checking_disabled: bool,
}

impl Key {
    fn for_query(query: &Query) -> Self {
        Self {
            name: query.question.name.clone(),
            qtype: query.question.qtype,
            qclass: query.question.qclass,
            dnssec_ok: query.edns.is_some_and(|edns| edns.dnssec_ok),
            checking_disabled: query.checking_disabled,
        }
    }
}

/// The part of a response that is cached.
struct Answer {
    rcode: ResponseCode,
    answers: Vec<Record>,
    authority: Vec<Record>,
    /// Whether DNSSEC proved it authentic.
    authentic: bool,
    stored: Instant,
    expires: Instant,
}

struct Entry {
    answer: Arc<Answer>,
    generation: u64,
}

struct Shard {
    entries: HashMap<Key, Entry>,
    /// Keys in insertion order, tagged with the generation they were
    /// inserted with; a tag that no longer matches the entry is stale.
    order: VecDeque<(Key, u64)>,
    next_generation: u64,
    capacity: usize,
}

impl Shard {
    fn insert(&mut self, key: Key, answer: Arc<Answer>) {
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);
        if !self.entries.contains_key(&key) {
            while self.entries.len() >= self.capacity {
                if !self.evict_oldest() {
                    break;
                }
            }
        }
        self.order.push_back((key.clone(), generation));
        self.entries.insert(key, Entry { answer, generation });
        if self.order.len() > self.capacity.saturating_mul(2).saturating_add(16) {
            self.compact();
        }
    }

    /// Removes the oldest live entry; false if there is none.
    fn evict_oldest(&mut self) -> bool {
        while let Some((key, generation)) = self.order.pop_front() {
            if self
                .entries
                .get(&key)
                .is_some_and(|entry| entry.generation == generation)
            {
                self.entries.remove(&key);
                return true;
            }
        }
        false
    }

    /// Drops stale tags so the order queue stays proportional to the entries.
    fn compact(&mut self) {
        let entries = &self.entries;
        self.order.retain(|(key, generation)| {
            entries
                .get(key)
                .is_some_and(|entry| entry.generation == *generation)
        });
    }
}

/// A sharded, bounded TTL cache of upstream answers.
pub struct Cache {
    shards: Box<[Mutex<Shard>]>,
    hasher: RandomState,
    config: CacheConfig,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl Cache {
    /// An empty cache. `max_entries` is capped at [`MAX_ENTRIES`].
    pub fn new(mut config: CacheConfig) -> Self {
        config.max_entries = config.max_entries.min(MAX_ENTRIES);
        let capacity = config.max_entries.div_ceil(SHARDS);
        let shards = (0..SHARDS)
            .map(|_| {
                Mutex::new(Shard {
                    entries: HashMap::new(),
                    order: VecDeque::new(),
                    next_generation: 0,
                    capacity,
                })
            })
            .collect();
        Self {
            shards,
            // Randomly keyed per process, so clients cannot aim many names at
            // one shard.
            hasher: RandomState::new(),
            config,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// The cached response to `query`, with TTLs counted down, if there is a
    /// live entry.
    pub fn get(&self, query: &Query) -> Option<Response> {
        let answer = self.lookup(query);
        let counter = if answer.is_some() {
            &self.hits
        } else {
            &self.misses
        };
        counter.fetch_add(1, Ordering::Relaxed);
        let answer = answer?;

        let elapsed = Instant::now().saturating_duration_since(answer.stored);
        let elapsed = u32::try_from(elapsed.as_secs()).unwrap_or(u32::MAX);
        let age = |records: &[Record]| -> Vec<Record> {
            records
                .iter()
                .map(|record| {
                    let mut record = record.clone();
                    record.set_ttl(record.ttl().saturating_sub(elapsed));
                    record
                })
                .collect()
        };
        let mut response = Response::for_query(query, answer.rcode);
        response.recursion_available = true;
        response.authentic_data = answer.authentic;
        response.answers = age(&answer.answers);
        response.authority = age(&answer.authority);
        restore_question_case(&mut response, &query.question.name);
        Some(response)
    }

    fn lookup(&self, query: &Query) -> Option<Arc<Answer>> {
        if self.config.max_entries == 0 {
            return None;
        }
        let key = Key::for_query(query);
        let mut shard = self.shard(&key)?.lock().ok()?;
        let entry = shard.entries.get(&key)?;
        if entry.answer.expires <= Instant::now() {
            shard.entries.remove(&key);
            return None;
        }
        Some(Arc::clone(&entry.answer))
    }

    /// Stores the parts of `response` that answer `query`, if it is
    /// cacheable: NOERROR with a valid answer chain, or NXDOMAIN/NODATA with
    /// an in-bailiwick SOA. Anything else is ignored.
    pub fn insert(&self, query: &Query, response: &Response) {
        if self.config.max_entries == 0 {
            return;
        }
        let Some(answer) = cacheable(query, response, &self.config) else {
            return;
        };
        let key = Key::for_query(query);
        if let Some(Ok(mut shard)) = self.shard(&key).map(Mutex::lock) {
            shard.insert(key, Arc::new(answer));
        }
    }

    /// Number of entries, including expired ones not yet evicted.
    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .filter_map(|shard| shard.lock().ok().map(|shard| shard.entries.len()))
            .sum()
    }

    /// Whether the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Hit and miss counts since the cache was created.
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
        }
    }

    /// The shard `key` lives in. Always `Some`: the index is reduced modulo
    /// the shard count.
    fn shard(&self, key: &Key) -> Option<&Mutex<Shard>> {
        let hash = self.hasher.hash_one(key);
        let len = u64::try_from(self.shards.len()).ok()?;
        let index = usize::try_from(hash.checked_rem(len)?).ok()?;
        self.shards.get(index)
    }
}

/// Decides what of `response` may be cached for `query`, and for how long.
fn cacheable(query: &Query, response: &Response, config: &CacheConfig) -> Option<Answer> {
    if response.truncated {
        return None;
    }
    let question = &query.question;
    let (chain, end) = answer_chain(question.qtype, &question.name, &response.answers)?;
    let (answers, authority, ttl) = match response.rcode {
        ResponseCode::NO_ERROR
            if chain.iter().any(|r| r.record_type() == question.qtype)
                || (question.qtype == RecordType::ANY && !chain.is_empty()) =>
        {
            let ttl = chain.iter().map(Record::ttl).min()?;
            if ttl == 0 {
                return None;
            }
            let ttl = ttl.clamp(config.min_ttl, config.max_ttl.max(config.min_ttl));
            // Served TTLs count down from the entry's lifetime, never past it.
            let chain = with_ttl(chain, |record_ttl| record_ttl.clamp(config.min_ttl, ttl));
            (chain, Vec::new(), ttl)
        }
        // NODATA (possibly after a CNAME chain) or NXDOMAIN.
        ResponseCode::NO_ERROR | ResponseCode::NX_DOMAIN => {
            let soa = response
                .authority
                .iter()
                .find(|r| r.soa_minimum().is_some() && end.is_within(r.name()))?;
            let ttl = soa
                .ttl()
                .min(soa.soa_minimum()?)
                .min(config.max_negative_ttl);
            let ttl = chain.iter().map(Record::ttl).fold(ttl, u32::min);
            if ttl == 0 {
                return None;
            }
            // RFC 2308: the SOA in a negative answer carries the negative TTL.
            let soa = with_ttl(vec![soa.clone()], |_| ttl);
            (with_ttl(chain, |record_ttl| record_ttl.min(ttl)), soa, ttl)
        }
        _ => return None,
    };
    if answers.len().saturating_add(authority.len()) > MAX_CACHED_RECORDS {
        return None;
    }
    let (answers, authority) = if query.edns.is_some_and(|edns| edns.dnssec_ok) {
        with_dnssec(response, answers, authority, ttl)?
    } else {
        (answers, authority)
    };
    let stored = Instant::now();
    let expires = stored.checked_add(Duration::from_secs(u64::from(ttl)))?;
    Some(Answer {
        rcode: response.rcode,
        answers,
        authority,
        authentic: response.authentic_data,
        stored,
        expires,
    })
}

/// For a client that set DO: `answers` and `authority` with the DNSSEC
/// records of `response` that go with them, at most
/// [`MAX_CACHED_RECORDS`]: RRSIGs covering their RRsets, DNAMEs above
/// their CNAMEs, and NSEC and NSEC3 proofs with their RRSIGs; none kept
/// longer than `ttl`.
fn with_dnssec(
    response: &Response,
    mut answers: Vec<Record>,
    mut authority: Vec<Record>,
    ttl: u32,
) -> Option<(Vec<Record>, Vec<Record>)> {
    let covers = |sig: &Record, records: &[Record]| {
        sig.rrsig().is_some_and(|rrsig| {
            records
                .iter()
                .any(|r| r.name() == sig.name() && r.record_type() == rrsig.type_covered)
        })
    };
    let dnames: Vec<Record> = response
        .answers
        .iter()
        .filter(|dname| {
            dname.record_type() == RecordType::DNAME
                && answers.iter().any(|cname| {
                    cname.record_type() == RecordType::CNAME
                        && cname.name().is_within(dname.name())
                        && cname.name() != dname.name()
                })
        })
        .cloned()
        .collect();
    let signed: Vec<Record> = answers.iter().chain(&dnames).cloned().collect();
    let mut extra = dnames;
    extra.extend(
        response
            .answers
            .iter()
            .filter(|sig| covers(sig, &signed))
            .cloned(),
    );
    let proofs: Vec<Record> = response
        .authority
        .iter()
        .filter(|r| matches!(r.record_type(), RecordType::NSEC | RecordType::NSEC3))
        .cloned()
        .collect();
    let mut negative: Vec<Record> = response
        .authority
        .iter()
        .filter(|sig| covers(sig, &authority) || covers(sig, &proofs))
        .cloned()
        .collect();
    negative.extend(proofs);
    if extra.len().saturating_add(negative.len()) > MAX_CACHED_RECORDS {
        return None;
    }
    answers.extend(with_ttl(extra, |record_ttl| record_ttl.min(ttl)));
    authority.extend(with_ttl(negative, |record_ttl| record_ttl.min(ttl)));
    Some((answers, authority))
}

fn with_ttl(mut records: Vec<Record>, ttl: impl Fn(u32) -> u32) -> Vec<Record> {
    for record in &mut records {
        record.set_ttl(ttl(record.ttl()));
    }
    records
}

/// The records of `answers` that answer `qname`: the CNAME chain starting at
/// it (unless CNAMEs are asked for) and the records of `qtype` at the end of
/// the chain. Returns the chain and the name it ends at, or `None` if the
/// chain is longer than [`MAX_CNAME_CHAIN`] or loops.
fn answer_chain(
    qtype: RecordType,
    qname: &Name,
    answers: &[Record],
) -> Option<(Vec<Record>, Name)> {
    let mut chain = Vec::new();
    let mut current = qname.clone();
    if qtype != RecordType::CNAME {
        while let Some(cname) = answers
            .iter()
            .find(|r| r.record_type() == RecordType::CNAME && r.name() == &current)
        {
            if chain.len() >= MAX_CNAME_CHAIN {
                return None;
            }
            current = cname.cname_target()?;
            chain.push(cname.clone());
        }
    }
    chain.extend(
        answers
            .iter()
            .filter(|r| {
                r.name() == &current && (qtype == RecordType::ANY || r.record_type() == qtype)
            })
            .cloned(),
    );
    Some((chain, current))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use goethite_proto::{Edns, Question};

    use super::*;

    fn name(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn query(qname: &str, qtype: RecordType) -> Query {
        Query {
            id: 1,
            recursion_desired: true,
            checking_disabled: false,
            authentic_data: false,
            question: Question {
                name: name(qname),
                qtype,
                qclass: RecordClass::IN,
            },
            edns: Some(Edns {
                udp_payload_size: 1232,
                dnssec_ok: false,
                padding: false,
            }),
        }
    }

    fn a(owner: &str, ttl: u32, last: u8) -> Record {
        Record::a(name(owner), ttl, Ipv4Addr::new(192, 0, 2, last))
    }

    fn answer(query: &Query, records: Vec<Record>) -> Response {
        let mut response = Response::for_query(query, ResponseCode::NO_ERROR);
        response.answers = records;
        response
    }

    fn negative(query: &Query, rcode: ResponseCode, soa: Option<Record>) -> Response {
        let mut response = Response::for_query(query, rcode);
        response.authority.extend(soa);
        response
    }

    fn cache() -> Cache {
        Cache::new(CacheConfig::default())
    }

    #[test]
    fn hits_misses_and_case() {
        let cache = cache();
        let q = query("example.com.", RecordType::A);
        assert!(cache.get(&q).is_none());
        cache.insert(&q, &answer(&q, vec![a("example.com.", 300, 1)]));

        let shouty = query("EXAMPLE.com.", RecordType::A);
        let hit = cache.get(&shouty).unwrap();
        assert_eq!(hit.answers.len(), 1);
        assert!(hit.answers[0].name().eq_exact(&shouty.question.name));
        assert!(hit.recursion_available);
        assert_eq!(cache.stats(), CacheStats { hits: 1, misses: 1 });
        assert!(
            cache
                .get(&query("example.com.", RecordType::AAAA))
                .is_none()
        );
    }

    #[test]
    fn dnssec_ok_and_checking_disabled_are_part_of_the_key() {
        let cache = cache();
        let q = query("example.com.", RecordType::A);
        cache.insert(&q, &answer(&q, vec![a("example.com.", 300, 1)]));
        let mut with_do = q.clone();
        with_do.edns = Some(Edns {
            udp_payload_size: 1232,
            dnssec_ok: true,
            padding: false,
        });
        let mut with_cd = q.clone();
        with_cd.checking_disabled = true;
        assert!(cache.get(&with_do).is_none());
        assert!(cache.get(&with_cd).is_none());
        assert!(cache.get(&q).is_some());
    }

    #[test]
    fn only_the_answer_chain_is_cached() {
        let cache = cache();
        let q = query("www.example.com.", RecordType::A);
        let mut response = answer(
            &q,
            vec![
                Record::cname(name("www.example.com."), 600, name("cdn.example.net.")),
                a("cdn.example.net.", 60, 7),
                // Unrelated records a poisoner would like cached.
                a("bank.example.", 86_400, 66),
                Record::cname(name("other.example.com."), 600, name("evil.example.")),
            ],
        );
        response.additional.push(a("ns.bank.example.", 86_400, 66));
        response.authority.push(a("bank.example.", 86_400, 66));
        cache.insert(&q, &response);

        let hit = cache.get(&q).unwrap();
        assert_eq!(hit.answers.len(), 2);
        assert_eq!(
            hit.answers[0].cname_target(),
            Some(name("cdn.example.net."))
        );
        assert_eq!(
            hit.answers[1].ip(),
            Some(Ipv4Addr::new(192, 0, 2, 7).into())
        );
        assert_eq!(hit.authority, vec![]);
        assert_eq!(hit.additional, vec![]);
        // The entry lives as long as its shortest record.
        assert!(hit.answers.iter().all(|r| r.ttl() <= 60));
        assert!(cache.get(&query("bank.example.", RecordType::A)).is_none());
    }

    #[test]
    fn long_or_looping_cname_chains_are_not_cached() {
        let cache = cache();
        let q = query("loop.example.", RecordType::A);
        let looping = answer(
            &q,
            vec![
                Record::cname(name("loop.example."), 60, name("back.example.")),
                Record::cname(name("back.example."), 60, name("loop.example.")),
            ],
        );
        cache.insert(&q, &looping);
        assert!(cache.get(&q).is_none());

        let q = query("c0.example.", RecordType::A);
        let mut chain: Vec<Record> = (0..=MAX_CNAME_CHAIN)
            .map(|i| {
                Record::cname(
                    name(&format!("c{i}.example.")),
                    60,
                    name(&format!("c{}.example.", i + 1)),
                )
            })
            .collect();
        chain.push(a(&format!("c{}.example.", MAX_CNAME_CHAIN + 1), 60, 1));
        cache.insert(&q, &answer(&q, chain));
        assert!(cache.get(&q).is_none());
    }

    #[test]
    fn negative_answers_need_an_soa_in_bailiwick() {
        let cache = cache();
        let soa =
            |zone: &str, ttl, minimum| Record::soa(name(zone), ttl, name("ns.example."), minimum);

        let nx = query("missing.example.com.", RecordType::A);
        cache.insert(
            &nx,
            &negative(
                &nx,
                ResponseCode::NX_DOMAIN,
                Some(soa("example.com.", 900, 300)),
            ),
        );
        let hit = cache.get(&nx).unwrap();
        assert_eq!(hit.rcode, ResponseCode::NX_DOMAIN);
        // min(SOA TTL, SOA MINIMUM), as RFC 2308 says.
        assert!(hit.authority[0].ttl() <= 300 && hit.authority[0].ttl() >= 299);

        let nodata = query("example.com.", RecordType::AAAA);
        cache.insert(
            &nodata,
            &negative(&nodata, ResponseCode::NO_ERROR, Some(soa("com.", 900, 30))),
        );
        let hit = cache.get(&nodata).unwrap();
        assert_eq!(hit.rcode, ResponseCode::NO_ERROR);
        assert_eq!(hit.answers, vec![]);

        // No SOA, or an SOA for an unrelated zone: not cached.
        let bare = query("bare.example.com.", RecordType::A);
        cache.insert(&bare, &negative(&bare, ResponseCode::NX_DOMAIN, None));
        assert!(cache.get(&bare).is_none());
        let foreign = query("foreign.example.com.", RecordType::A);
        cache.insert(
            &foreign,
            &negative(
                &foreign,
                ResponseCode::NX_DOMAIN,
                Some(soa("evil.example.", 900, 900)),
            ),
        );
        assert!(cache.get(&foreign).is_none());
    }

    #[test]
    fn uncacheable_responses_are_ignored() {
        let cache = cache();
        let q = query("example.com.", RecordType::A);
        cache.insert(&q, &answer(&q, vec![a("example.com.", 0, 1)]));
        assert!(cache.get(&q).is_none(), "TTL 0");

        let mut truncated = answer(&q, vec![a("example.com.", 300, 1)]);
        truncated.truncated = true;
        cache.insert(&q, &truncated);
        assert!(cache.get(&q).is_none(), "truncated");

        cache.insert(&q, &Response::for_query(&q, ResponseCode::SERV_FAIL));
        assert!(cache.get(&q).is_none(), "SERVFAIL");

        let many = (0..=MAX_CACHED_RECORDS)
            .map(|i| a("example.com.", 300, u8::try_from(i).unwrap()))
            .collect();
        cache.insert(&q, &answer(&q, many));
        assert!(cache.get(&q).is_none(), "too many records");
        assert!(cache.is_empty());
    }

    #[test]
    fn ttls_are_clamped() {
        let cache = Cache::new(CacheConfig {
            max_ttl: 3_600,
            ..CacheConfig::default()
        });
        let q = query("example.com.", RecordType::A);
        cache.insert(&q, &answer(&q, vec![a("example.com.", 172_800, 1)]));
        assert_eq!(cache.get(&q).unwrap().answers[0].ttl(), 3_600);
    }

    #[test]
    fn size_is_bounded() {
        let cache = Cache::new(CacheConfig {
            max_entries: 32,
            ..CacheConfig::default()
        });
        for i in 0..1_000 {
            let q = query(&format!("n{i}.example."), RecordType::A);
            cache.insert(&q, &answer(&q, vec![a(&format!("n{i}.example."), 300, 1)]));
        }
        assert!(cache.len() <= 32, "{}", cache.len());
        let newest = query("n999.example.", RecordType::A);
        assert!(cache.get(&newest).is_some(), "the newest entry survives");
    }

    #[test]
    fn zero_entries_turns_the_cache_off() {
        let cache = Cache::new(CacheConfig {
            max_entries: 0,
            ..CacheConfig::default()
        });
        let q = query("example.com.", RecordType::A);
        cache.insert(&q, &answer(&q, vec![a("example.com.", 300, 1)]));
        assert!(cache.get(&q).is_none());
    }

    #[test]
    fn entries_expire_and_ttls_count_down() {
        let cache = cache();
        let q = query("short.example.", RecordType::A);
        cache.insert(&q, &answer(&q, vec![a("short.example.", 2, 1)]));
        std::thread::sleep(Duration::from_millis(1_100));
        assert_eq!(cache.get(&q).unwrap().answers[0].ttl(), 1);
        std::thread::sleep(Duration::from_millis(1_000));
        assert!(cache.get(&q).is_none());
    }

    #[test]
    fn dnssec_records_and_ad_are_kept_for_clients_with_do() {
        use goethite_proto::dnssec::signing::{self, Key};

        let key = Key::generate(&name("example."));
        let www = a("www.example.", 300, 1);
        let sig = key.sign(std::slice::from_ref(&www), 0, u32::MAX);
        let stray = key.sign(&[a("other.example.", 300, 2)], 0, u32::MAX);
        let mut q = query("www.example.", RecordType::A);
        q.edns = Some(Edns {
            udp_payload_size: 1232,
            dnssec_ok: true,
            padding: false,
        });
        let mut response = answer(&q, vec![www, sig.clone(), stray]);
        response.authentic_data = true;
        let cache = cache();
        cache.insert(&q, &response);
        let hit = cache.get(&q).unwrap();
        assert!(hit.authentic_data);
        assert_eq!(hit.answers.len(), 2, "the A record and its RRSIG only");
        assert_eq!(hit.answers[1].record_type(), RecordType::RRSIG);
        // Without DO, the RRSIG is not kept.
        let plain = query("www.example.", RecordType::A);
        cache.insert(&plain, &response);
        assert_eq!(cache.get(&plain).unwrap().answers.len(), 1);

        // A negative answer keeps its proof, signed.
        let mut nx = query("nope.example.", RecordType::A);
        nx.edns = q.edns;
        let soa = Record::soa(name("example."), 900, name("ns.example."), 300);
        let proof = signing::nsec(
            &name("example."),
            300,
            &name("www.example."),
            &[RecordType::SOA, RecordType::NSEC, RecordType::RRSIG],
        );
        let mut negative = negative(&nx, ResponseCode::NX_DOMAIN, Some(soa.clone()));
        negative.authority.extend([
            key.sign(std::slice::from_ref(&soa), 0, u32::MAX),
            proof.clone(),
            key.sign(std::slice::from_ref(&proof), 0, u32::MAX),
        ]);
        cache.insert(&nx, &negative);
        let hit = cache.get(&nx).unwrap();
        assert_eq!(hit.authority.len(), 4);
        assert!(!hit.authentic_data);
    }
}
