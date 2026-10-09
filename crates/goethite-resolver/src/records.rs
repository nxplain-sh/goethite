//! Local DNS records: names goethite answers itself, for every client and
//! before the filter, as configured, such as `nas.lan` for the network's
//! storage or `*.home.example` for everything behind a reverse proxy.
//!
//! An exact name wins over a wildcard, and a closer wildcard over one
//! further up. A name with local records answers only from them: an empty
//! answer (NODATA) for a type it has none of. A CNAME is followed through
//! other local records; where it leaves them, its target is resolved like
//! any other name, filter included.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use goethite_proto::{Name, Record, RecordType};

use crate::cache::MAX_CNAME_CHAIN;

/// The most local records a policy holds.
pub const MAX_LOCAL_RECORDS: usize = 10_000;

/// What a local record holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalData {
    /// An IPv4 address.
    A(Ipv4Addr),
    /// An IPv6 address.
    Aaaa(Ipv6Addr),
    /// Another name, which answers for this one.
    Cname(Name),
}

/// One local record, as configured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalRecord {
    /// The name; with `wildcard`, every name below it instead (`*.name`).
    pub name: Name,
    /// Whether the record is for the names below `name` rather than `name`.
    pub wildcard: bool,
    /// What it holds.
    pub data: LocalData,
    /// How long clients may cache it, in seconds.
    pub ttl: u32,
}

/// Local records, compiled for lookups by name.
#[derive(Debug, Default)]
pub struct LocalRecords {
    exact: HashMap<Name, Vec<(LocalData, u32)>>,
    wildcards: HashMap<Name, Vec<(LocalData, u32)>>,
}

/// How local records answer a question.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LocalAnswer {
    /// No local record has the name: it is resolved as usual.
    None,
    /// The whole answer: the CNAMEs followed and the records of the asked
    /// type, or none (NODATA).
    Records(Vec<Record>),
    /// Local CNAMEs that end at `target`, which has no local records: its
    /// own answer follows them.
    Alias {
        /// The CNAMEs, from the asked name on.
        chain: Vec<Record>,
        /// Where they lead.
        target: Name,
    },
    /// Local CNAMEs that go round in a loop, or further than
    /// `MAX_CNAME_CHAIN`.
    Loop,
}

impl LocalRecords {
    /// Compiles `records`, at most [`MAX_LOCAL_RECORDS`] of them.
    pub fn new(records: impl IntoIterator<Item = LocalRecord>) -> Self {
        let mut compiled = Self::default();
        for record in records.into_iter().take(MAX_LOCAL_RECORDS) {
            let table = if record.wildcard {
                &mut compiled.wildcards
            } else {
                &mut compiled.exact
            };
            table
                .entry(record.name)
                .or_default()
                .push((record.data, record.ttl));
        }
        compiled
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcards.is_empty()
    }

    /// How many records there are.
    pub fn len(&self) -> usize {
        self.exact
            .values()
            .chain(self.wildcards.values())
            .map(Vec::len)
            .sum()
    }

    /// The records for `name`: its own, or else the closest wildcard's.
    fn find(&self, name: &Name) -> Option<&[(LocalData, u32)]> {
        if let Some(found) = self.exact.get(name) {
            return Some(found);
        }
        if self.wildcards.is_empty() {
            return None;
        }
        let mut zone = name.parent();
        while let Some(parent) = zone {
            if let Some(found) = self.wildcards.get(&parent) {
                return Some(found);
            }
            zone = parent.parent();
        }
        None
    }

    /// How the local records answer `name`, asked for `qtype`.
    pub(crate) fn answer(&self, name: &Name, qtype: RecordType) -> LocalAnswer {
        if self.is_empty() {
            return LocalAnswer::None;
        }
        let mut owner = name.clone();
        let mut chain = Vec::new();
        for _ in 0..=MAX_CNAME_CHAIN {
            let Some(found) = self.find(&owner) else {
                return if chain.is_empty() {
                    LocalAnswer::None
                } else {
                    LocalAnswer::Alias {
                        chain,
                        target: owner,
                    }
                };
            };
            let cname = found.iter().find_map(|(data, ttl)| match data {
                LocalData::Cname(target) => Some((target, *ttl)),
                LocalData::A(_) | LocalData::Aaaa(_) => None,
            });
            if let Some((target, ttl)) = cname {
                chain.push(Record::cname(owner, ttl, target.clone()));
                if qtype == RecordType::CNAME {
                    return LocalAnswer::Records(chain);
                }
                owner = target.clone();
                continue;
            }
            chain.extend(found.iter().filter_map(|(data, ttl)| match data {
                LocalData::A(addr) if matches!(qtype, RecordType::A | RecordType::ANY) => {
                    Some(Record::a(owner.clone(), *ttl, *addr))
                }
                LocalData::Aaaa(addr) if matches!(qtype, RecordType::AAAA | RecordType::ANY) => {
                    Some(Record::aaaa(owner.clone(), *ttl, *addr))
                }
                LocalData::A(_) | LocalData::Aaaa(_) | LocalData::Cname(_) => None,
            }));
            return LocalAnswer::Records(chain);
        }
        LocalAnswer::Loop
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> Name {
        text.parse().unwrap()
    }

    fn record(text: &str, data: LocalData) -> LocalRecord {
        let (wildcard, text) = match text.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, text),
        };
        LocalRecord {
            name: name(text),
            wildcard,
            data,
            ttl: 300,
        }
    }

    fn a(text: &str) -> LocalData {
        LocalData::A(text.parse().unwrap())
    }

    fn records() -> LocalRecords {
        LocalRecords::new([
            record("nas.lan", a("192.168.1.10")),
            record("nas.lan", LocalData::Aaaa("fd00::10".parse().unwrap())),
            record("*.home.example", a("192.168.1.20")),
            record("*.lab.home.example", a("192.168.1.30")),
            record("files.home.example", LocalData::Cname(name("nas.lan"))),
            record("docs.lan", LocalData::Cname(name("docs.example.com"))),
            record("ping.lan", LocalData::Cname(name("pong.lan"))),
            record("pong.lan", LocalData::Cname(name("ping.lan"))),
        ])
    }

    #[test]
    fn exact_names_answer_their_types() {
        let records = records();
        let LocalAnswer::Records(answer) = records.answer(&name("NAS.lan"), RecordType::A) else {
            panic!("no answer");
        };
        assert_eq!(
            answer,
            vec![Record::a(
                name("NAS.lan"),
                300,
                "192.168.1.10".parse().unwrap()
            )]
        );
        assert!(
            answer[0].name().eq_exact(&name("NAS.lan")),
            "the asker's case"
        );
        assert_eq!(
            records.answer(&name("nas.lan"), RecordType::MX),
            LocalAnswer::Records(Vec::new()),
            "NODATA for a type it has none of"
        );
        assert_eq!(
            records.answer(&name("tv.lan"), RecordType::A),
            LocalAnswer::None
        );
    }

    #[test]
    fn wildcards_answer_below_their_name_closest_first() {
        let records = records();
        let answer = |text: &str| match records.answer(&name(text), RecordType::A) {
            LocalAnswer::Records(answer) => answer.first().and_then(Record::ip),
            other => panic!("{text}: {other:?}"),
        };
        assert_eq!(
            answer("a.home.example"),
            Some("192.168.1.20".parse().unwrap())
        );
        assert_eq!(
            answer("x.y.home.example"),
            Some("192.168.1.20".parse().unwrap())
        );
        assert_eq!(
            answer("pi.lab.home.example"),
            Some("192.168.1.30".parse().unwrap())
        );
        assert_eq!(
            records.answer(&name("home.example"), RecordType::A),
            LocalAnswer::None,
            "not the name itself"
        );
    }

    #[test]
    fn cnames_are_followed_through_local_records() {
        let records = records();
        let LocalAnswer::Records(answer) =
            records.answer(&name("files.home.example"), RecordType::AAAA)
        else {
            panic!("no answer");
        };
        assert_eq!(
            answer,
            vec![
                Record::cname(name("files.home.example"), 300, name("nas.lan")),
                Record::aaaa(name("nas.lan"), 300, "fd00::10".parse().unwrap()),
            ],
            "an exact name wins over the wildcard above it"
        );
        assert_eq!(
            records.answer(&name("docs.lan"), RecordType::A),
            LocalAnswer::Alias {
                chain: vec![Record::cname(
                    name("docs.lan"),
                    300,
                    name("docs.example.com")
                )],
                target: name("docs.example.com"),
            }
        );
        assert_eq!(
            records.answer(&name("docs.lan"), RecordType::CNAME),
            LocalAnswer::Records(vec![Record::cname(
                name("docs.lan"),
                300,
                name("docs.example.com")
            )])
        );
        assert_eq!(
            records.answer(&name("ping.lan"), RecordType::A),
            LocalAnswer::Loop
        );
    }
}
