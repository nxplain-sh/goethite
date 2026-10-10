//! What an authoritative server's response means, for an iterating
//! resolver: an answer, a referral to a zone further down, a negative
//! answer, or a server that cannot help.
//!
//! This is where bailiwick is enforced. A server is asked as a server of
//! one zone, and only records within that zone are believed: answer
//! records owned by names in it, referrals to zones strictly below it and
//! above the name asked, and glue addresses only for name servers within
//! it. Anything else is ignored, never cached.

use std::collections::HashSet;
use std::net::IpAddr;

use goethite_proto::{Name, Record, RecordClass, RecordType, Response, ResponseCode};

use crate::MAX_CNAME_CHAIN;

/// The most name servers taken from one referral.
pub const MAX_NAME_SERVERS: usize = 16;

/// The most glue addresses taken for one name server.
const MAX_GLUE_PER_SERVER: usize = 8;

/// What a response means.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Records answering the question: the CNAME chain from the name asked,
    /// within the zone, then the records of the type asked at its end.
    /// `next` is where the chain continues, if it leaves the zone or stops
    /// without them.
    Answer {
        /// The chain and the records at its end.
        records: Vec<Record>,
        /// Where to continue: a CNAME target this response does not answer
        /// for.
        next: Option<Name>,
    },
    /// The name exists but has no records of the type asked.
    NoData {
        /// The zone's SOA, for negative caching.
        soa: Option<Record>,
    },
    /// The name asked, or the end of its CNAME chain, does not exist.
    NxDomain {
        /// The CNAME chain from the name asked, within the zone.
        records: Vec<Record>,
        /// The name the denial is for: the chain's end (RFC 6604).
        end: Name,
        /// The zone's SOA, for negative caching.
        soa: Option<Record>,
    },
    /// Ask the servers of `zone` instead.
    Referral {
        /// A zone strictly below the one asked and containing the name.
        zone: Name,
        /// Its name servers.
        servers: Vec<Name>,
        /// The lowest TTL of the NS records.
        ttl: u32,
        /// Addresses for name servers within the zone that was asked.
        glue: Vec<(Name, IpAddr, u32)>,
    },
    /// The server is not authoritative for the zone it was asked as a
    /// server of, or sent something useless: ask another.
    Lame,
    /// The server failed: SERVFAIL, REFUSED and the like.
    Failed(ResponseCode),
}

/// Records of class IN.
fn internet(records: &[Record]) -> impl Iterator<Item = &Record> {
    records
        .iter()
        .filter(|record| record.class() == RecordClass::IN)
}

/// The SOA in `response`'s authority section for a zone within `zone`
/// that contains `name`.
fn soa(response: &Response, zone: &Name, name: &Name) -> Option<Record> {
    internet(&response.authority)
        .find(|record| {
            record.record_type() == RecordType::SOA
                && record.name().is_within(zone)
                && name.is_within(record.name())
        })
        .cloned()
}

/// What `response` from a server of `zone` means for the question
/// `name` / `qtype`.
pub fn classify(response: &Response, zone: &Name, name: &Name, qtype: RecordType) -> Kind {
    if !name.is_within(zone) {
        return Kind::Lame;
    }
    match response.rcode {
        ResponseCode::NO_ERROR => {}
        ResponseCode::NX_DOMAIN => {
            // RFC 6604: the denial is for the end of the CNAME chain, not
            // the name asked, which may well exist.
            let (records, end) = chain(response, zone, name);
            if !end.is_within(zone) {
                // A denial for a name this server does not hold.
                return Kind::Lame;
            }
            return Kind::NxDomain {
                records,
                soa: soa(response, zone, &end),
                end,
            };
        }
        rcode => return Kind::Failed(rcode),
    }
    if let Some(answer) = answer(response, zone, name, qtype) {
        return answer;
    }
    if let Some(referral) = referral(response, zone, name, qtype) {
        return referral;
    }
    match soa(response, zone, name) {
        Some(soa) => Kind::NoData { soa: Some(soa) },
        None if response.authoritative => Kind::NoData { soa: None },
        None => Kind::Lame,
    }
}

/// The CNAME chain from `name` that stays within `zone`: its records, and
/// the name it ends at (RFC 6604, for a negative answer).
fn chain(response: &Response, zone: &Name, name: &Name) -> (Vec<Record>, Name) {
    let mut records = Vec::new();
    let mut at = name.clone();
    let mut seen = HashSet::new();
    for _ in 0..=MAX_CNAME_CHAIN {
        if !at.is_within(zone) || !seen.insert(at.clone()) {
            break;
        }
        let Some(cname) = internet(&response.answers)
            .find(|record| record.record_type() == RecordType::CNAME && record.name() == &at)
        else {
            break;
        };
        let Some(target) = cname.cname_target() else {
            break;
        };
        records.push(cname.clone());
        at = target;
    }
    (records, at)
}

/// The CNAME chain from `name` within `zone` and the records of `qtype` at
/// its end, if the response has any of it.
fn answer(response: &Response, zone: &Name, name: &Name, qtype: RecordType) -> Option<Kind> {
    let mut records = Vec::new();
    let mut at = name.clone();
    let mut seen = HashSet::new();
    for _ in 0..=MAX_CNAME_CHAIN {
        if !at.is_within(zone) || !seen.insert(at.clone()) {
            break;
        }
        let owned: Vec<&Record> = internet(&response.answers)
            .filter(|record| record.name() == &at)
            .collect();
        let wanted: Vec<Record> = match qtype {
            // RFC 8482: answer ANY with one RRset, not every type at the
            // name, which hostile clients would otherwise make the server
            // and its upstreams carry for a penny a query.
            RecordType::ANY => match owned.first() {
                Some(first) => owned
                    .iter()
                    .filter(|record| record.record_type() == first.record_type())
                    .map(|record| (*record).clone())
                    .collect(),
                None => Vec::new(),
            },
            _ => owned
                .iter()
                .filter(|record| record.record_type() == qtype)
                .map(|record| (*record).clone())
                .collect(),
        };
        if !wanted.is_empty() {
            records.extend(wanted);
            return Some(Kind::Answer {
                records,
                next: None,
            });
        }
        let Some(cname) = owned
            .iter()
            .find(|record| record.record_type() == RecordType::CNAME)
        else {
            break;
        };
        let Some(target) = cname.cname_target() else {
            break;
        };
        records.push((*cname).clone());
        at = target;
    }
    if records.is_empty() {
        None
    } else {
        Some(Kind::Answer {
            records,
            next: Some(at),
        })
    }
}

/// A referral to a zone strictly below `zone` that contains `name`; for a
/// DS question, not to `name` itself, whose parent holds its DS records.
fn referral(response: &Response, zone: &Name, name: &Name, qtype: RecordType) -> Option<Kind> {
    let first =
        internet(&response.authority).find(|record| record.record_type() == RecordType::NS)?;
    let cut = first.name().clone();
    let below = cut.is_within(zone) && cut != *zone && name.is_within(&cut);
    if !below || (qtype == RecordType::DS && cut == *name) {
        // An NS set for the zone itself (some servers add it to answers
        // and NODATA) is no referral; one for anywhere else is lame.
        return (cut != *zone).then_some(Kind::Lame);
    }
    let mut servers: Vec<Name> = Vec::new();
    let mut ttl = u32::MAX;
    for record in internet(&response.authority)
        .filter(|record| record.record_type() == RecordType::NS && record.name() == &cut)
    {
        let Some(server) = record.ns_target() else {
            continue;
        };
        ttl = ttl.min(record.ttl());
        if !servers.contains(&server) && servers.len() < MAX_NAME_SERVERS {
            servers.push(server);
        }
    }
    if servers.is_empty() {
        return Some(Kind::Lame);
    }
    let mut glue: Vec<(Name, IpAddr, u32)> = Vec::new();
    for record in internet(&response.additional) {
        let Some(ip) = record.ip() else {
            continue;
        };
        let owner = record.name();
        let per_server = glue.iter().filter(|(name, _, _)| name == owner).count();
        if owner.is_within(zone) && servers.contains(owner) && per_server < MAX_GLUE_PER_SERVER {
            glue.push((owner.clone(), ip, record.ttl()));
        }
    }
    Some(Kind::Referral {
        zone: cut,
        servers,
        ttl,
        glue,
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use goethite_proto::{Edns, Query, Question};

    use super::*;

    fn name(text: &str) -> Name {
        text.parse().unwrap()
    }

    fn response(rcode: ResponseCode) -> Response {
        let query = Query {
            id: 1,
            recursion_desired: false,
            checking_disabled: false,
            authentic_data: false,
            question: Question {
                name: name("www.example.com."),
                qtype: RecordType::A,
                qclass: RecordClass::IN,
            },
            edns: Some(Edns::ours()),
        };
        Response::for_query(&query, rcode)
    }

    fn a(owner: &str, last: u8) -> Record {
        Record::a(name(owner), 300, Ipv4Addr::new(192, 0, 2, last))
    }

    #[test]
    fn referrals_go_down_and_glue_stays_in_bailiwick() {
        let mut referral = response(ResponseCode::NO_ERROR);
        referral.authority = vec![
            Record::ns(name("example.com."), 172_800, name("ns1.example.com.")),
            Record::ns(name("example.com."), 86_400, name("ns.other.net.")),
        ];
        referral.additional = vec![
            a("ns1.example.com.", 1),
            // Out of the com servers' bailiwick: never believed.
            a("ns.other.net.", 2),
            // Not a name server of the referral.
            a("www.example.com.", 3),
        ];
        let kind = classify(
            &referral,
            &name("com."),
            &name("www.example.com."),
            RecordType::A,
        );
        let Kind::Referral {
            zone,
            servers,
            ttl,
            glue,
        } = kind
        else {
            panic!("{kind:?}");
        };
        assert_eq!(zone, name("example.com."));
        assert_eq!(servers, [name("ns1.example.com."), name("ns.other.net.")]);
        assert_eq!(ttl, 86_400);
        assert_eq!(glue.len(), 1);
        assert_eq!(glue[0].0, name("ns1.example.com."));

        // From the example.com servers, an NS set for example.com is no
        // referral; for com or a sibling it is lame.
        assert_eq!(
            classify(
                &referral,
                &name("example.com."),
                &name("www.example.com."),
                RecordType::A
            ),
            Kind::Lame
        );
        let mut upward = response(ResponseCode::NO_ERROR);
        upward.authority = vec![Record::ns(
            Name::root(),
            518_400,
            name("a.root-servers.net."),
        )];
        assert_eq!(
            classify(
                &upward,
                &name("example.com."),
                &name("www.example.com."),
                RecordType::A
            ),
            Kind::Lame
        );
        // The parent answers DS: a referral to the name itself is lame.
        assert_eq!(
            classify(
                &referral,
                &name("com."),
                &name("example.com."),
                RecordType::DS
            ),
            Kind::Lame
        );
    }

    #[test]
    fn any_answers_one_rrset() {
        let mut answer = response(ResponseCode::NO_ERROR);
        answer.authoritative = true;
        let first = a("www.example.com.", 1);
        let second = a("www.example.com.", 2);
        answer.answers = vec![
            first.clone(),
            Record::aaaa(
                name("www.example.com."),
                300,
                "2001:db8::1".parse().unwrap(),
            ),
            second.clone(),
        ];
        let kind = classify(
            &answer,
            &name("example.com."),
            &name("www.example.com."),
            RecordType::ANY,
        );
        let Kind::Answer { records, next } = kind else {
            panic!("{kind:?}");
        };
        assert_eq!(records, vec![first, second], "one RRset, not every type");
        assert_eq!(next, None);
    }

    #[test]
    fn answers_follow_cnames_within_the_zone() {
        let mut answer = response(ResponseCode::NO_ERROR);
        answer.authoritative = true;
        answer.answers = vec![
            Record::cname(name("www.example.com."), 300, name("web.example.com.")),
            Record::cname(name("web.example.com."), 300, name("cdn.example.net.")),
            // Out of bailiwick: not believed.
            a("cdn.example.net.", 9),
            // Unrelated.
            a("other.example.com.", 8),
        ];
        let kind = classify(
            &answer,
            &name("example.com."),
            &name("www.example.com."),
            RecordType::A,
        );
        assert_eq!(
            kind,
            Kind::Answer {
                records: answer.answers[..2].to_vec(),
                next: Some(name("cdn.example.net.")),
            }
        );

        answer.answers = vec![a("www.example.com.", 1), a("www.example.com.", 2)];
        let Kind::Answer { records, next } = classify(
            &answer,
            &name("example.com."),
            &name("www.example.com."),
            RecordType::A,
        ) else {
            panic!("an answer");
        };
        assert_eq!((records.len(), next), (2, None));

        // A loop ends.
        answer.answers = vec![
            Record::cname(name("a.example.com."), 300, name("b.example.com.")),
            Record::cname(name("b.example.com."), 300, name("a.example.com.")),
        ];
        let Kind::Answer { records, next } = classify(
            &answer,
            &name("example.com."),
            &name("a.example.com."),
            RecordType::A,
        ) else {
            panic!("an answer");
        };
        assert_eq!(records.len(), 2);
        assert_eq!(next, Some(name("a.example.com.")));
    }

    #[test]
    fn negative_answers_and_failures() {
        let soa = Record::soa(name("example.com."), 3_600, name("ns1.example.com."), 300);
        let mut nodata = response(ResponseCode::NO_ERROR);
        nodata.authority = vec![soa.clone()];
        assert_eq!(
            classify(
                &nodata,
                &name("example.com."),
                &name("www.example.com."),
                RecordType::A
            ),
            Kind::NoData {
                soa: Some(soa.clone())
            }
        );
        let mut nxdomain = response(ResponseCode::NX_DOMAIN);
        nxdomain.authority = vec![
            soa.clone(),
            // A SOA for some other zone is not taken.
            Record::soa(name("example.net."), 3_600, name("ns.example.net."), 300),
        ];
        assert_eq!(
            classify(
                &nxdomain,
                &name("example.com."),
                &name("www.example.com."),
                RecordType::A
            ),
            Kind::NxDomain {
                records: Vec::new(),
                end: name("www.example.com."),
                soa: Some(soa),
            }
        );
        // An NXDOMAIN with a CNAME applies to the chain's end (RFC 6604).
        let mut chained = response(ResponseCode::NX_DOMAIN);
        chained.answers = vec![Record::cname(
            name("www.example.com."),
            300,
            name("missing.example.com."),
        )];
        chained.authority = vec![Record::soa(
            name("example.com."),
            3_600,
            name("ns1.example.com."),
            300,
        )];
        let Kind::NxDomain { records, end, soa } = classify(
            &chained,
            &name("example.com."),
            &name("www.example.com."),
            RecordType::A,
        ) else {
            panic!("an NXDOMAIN");
        };
        assert_eq!(records.len(), 1, "the chain is kept");
        assert_eq!(end, name("missing.example.com."));
        assert!(soa.is_some());
        // A chain leaving the zone: the server cannot deny the end.
        let mut leaving = response(ResponseCode::NX_DOMAIN);
        leaving.answers = vec![Record::cname(
            name("www.example.com."),
            300,
            name("www.example.net."),
        )];
        assert_eq!(
            classify(
                &leaving,
                &name("example.com."),
                &name("www.example.com."),
                RecordType::A
            ),
            Kind::Lame
        );
        // Neither an answer, a referral, a SOA nor authoritative: lame.
        assert_eq!(
            classify(
                &response(ResponseCode::NO_ERROR),
                &name("example.com."),
                &name("www.example.com."),
                RecordType::A
            ),
            Kind::Lame
        );
        assert_eq!(
            classify(
                &response(ResponseCode::REFUSED),
                &name("example.com."),
                &name("www.example.com."),
                RecordType::A
            ),
            Kind::Failed(ResponseCode::REFUSED)
        );
        // Asked about a name outside the zone: nothing it says counts.
        assert_eq!(
            classify(
                &nodata,
                &name("example.org."),
                &name("www.example.com."),
                RecordType::A
            ),
            Kind::Lame
        );
    }
}
