//! Answering blocked names.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use arc_swap::ArcSwap;
use goethite_filter::{Filter, Sources, Verdict};
use goethite_proto::{Name, Query, Record, RecordType, Response, ResponseCode};

/// How a blocked name is answered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockResponse {
    /// `0.0.0.0` for `A`, `::` for `AAAA`, and an empty `NOERROR` for other
    /// types. Clients fail fast, without retrying another resolver.
    #[default]
    NullIp,
    /// `NXDOMAIN`: the name does not exist.
    NxDomain,
    /// `REFUSED`.
    Refused,
}

/// The current filter and how to answer what it blocks.
///
/// The filter is behind an [`ArcSwap`]: [`Blocking::replace`] swaps in a new
/// one atomically, and lookups never wait on a lock.
pub struct Blocking {
    filter: ArcSwap<Filter>,
    response: BlockResponse,
    ttl: u32,
}

impl Blocking {
    /// Blocks what `filter` blocks, answering with `response` and, for null
    /// IPs, records with time to live `ttl`.
    pub fn new(filter: Filter, response: BlockResponse, ttl: u32) -> Self {
        Self {
            filter: ArcSwap::from_pointee(filter),
            response,
            ttl,
        }
    }

    /// Replaces the filter; queries in progress finish with the old one.
    pub fn replace(&self, filter: Filter) {
        self.filter.store(Arc::new(filter));
    }

    /// The current filter.
    pub fn filter(&self) -> Arc<Filter> {
        self.filter.load_full()
    }

    /// The verdict of the current filter for `name`, with every source.
    pub fn check(&self, name: &Name) -> Verdict {
        self.filter.load().check(name, Sources::ALL)
    }

    /// The response for a blocked `query`.
    pub fn respond(&self, query: &Query) -> Response {
        match self.response {
            BlockResponse::NxDomain => Response::for_query(query, ResponseCode::NX_DOMAIN),
            BlockResponse::Refused => Response::for_query(query, ResponseCode::REFUSED),
            BlockResponse::NullIp => {
                let mut response = Response::for_query(query, ResponseCode::NO_ERROR);
                let name = query.question.name.clone();
                match query.question.qtype {
                    RecordType::A => {
                        response
                            .answers
                            .push(Record::a(name, self.ttl, Ipv4Addr::UNSPECIFIED));
                    }
                    RecordType::AAAA => {
                        response
                            .answers
                            .push(Record::aaaa(name, self.ttl, Ipv6Addr::UNSPECIFIED));
                    }
                    _ => {}
                }
                response
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use goethite_filter::{FilterBuilder, Source};
    use goethite_proto::{Edns, Question, RecordClass};

    use super::*;

    fn blocking(response: BlockResponse) -> Blocking {
        let mut builder = FilterBuilder::new();
        builder.add_list(Source::new(0).unwrap(), "||ads.example^\n");
        Blocking::new(builder.build().unwrap(), response, 10)
    }

    fn query(qtype: RecordType) -> Query {
        Query {
            id: 5,
            recursion_desired: true,
            checking_disabled: false,
            authentic_data: false,
            question: Question {
                name: "x.ads.example.".parse().unwrap(),
                qtype,
                qclass: RecordClass::IN,
            },
            edns: Some(Edns {
                udp_payload_size: 1232,
                dnssec_ok: false,
            }),
        }
    }

    #[test]
    fn null_ip_answers() {
        let blocking = blocking(BlockResponse::NullIp);
        let a = blocking.respond(&query(RecordType::A));
        assert_eq!(a.rcode, ResponseCode::NO_ERROR);
        assert_eq!(a.answers[0].ip(), Some(Ipv4Addr::UNSPECIFIED.into()));
        assert_eq!(a.answers[0].ttl(), 10);
        let aaaa = blocking.respond(&query(RecordType::AAAA));
        assert_eq!(aaaa.answers[0].ip(), Some(Ipv6Addr::UNSPECIFIED.into()));
        let mx = blocking.respond(&query(RecordType::MX));
        assert_eq!(mx.rcode, ResponseCode::NO_ERROR);
        assert_eq!(mx.answers, vec![]);
    }

    #[test]
    fn nxdomain_and_refused() {
        let nx = blocking(BlockResponse::NxDomain).respond(&query(RecordType::A));
        assert_eq!(nx.rcode, ResponseCode::NX_DOMAIN);
        assert_eq!(nx.answers, vec![]);
        let refused = blocking(BlockResponse::Refused).respond(&query(RecordType::A));
        assert_eq!(refused.rcode, ResponseCode::REFUSED);
    }

    #[test]
    fn replacing_the_filter() {
        let blocking = blocking(BlockResponse::NullIp);
        let name: Name = "x.ads.example.".parse().unwrap();
        assert!(blocking.check(&name).is_blocked());
        blocking.replace(Filter::empty());
        assert_eq!(blocking.check(&name), Verdict::Pass);
        assert_eq!(blocking.filter().rule_count(), 0);
    }
}
