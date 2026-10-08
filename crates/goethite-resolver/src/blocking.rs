//! Answering blocked names.

use std::net::{Ipv4Addr, Ipv6Addr};

use goethite_proto::{Query, Record, RecordType, Response, ResponseCode};

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

/// The answer to a blocked `query`, by `kind`; null-IP records have time to
/// live `ttl`.
pub(crate) fn blocked_response(query: &Query, kind: BlockResponse, ttl: u32) -> Response {
    match kind {
        BlockResponse::NxDomain => Response::for_query(query, ResponseCode::NX_DOMAIN),
        BlockResponse::Refused => Response::for_query(query, ResponseCode::REFUSED),
        BlockResponse::NullIp => {
            let mut response = Response::for_query(query, ResponseCode::NO_ERROR);
            let name = query.question.name.clone();
            match query.question.qtype {
                RecordType::A => {
                    response
                        .answers
                        .push(Record::a(name, ttl, Ipv4Addr::UNSPECIFIED));
                }
                RecordType::AAAA => {
                    response
                        .answers
                        .push(Record::aaaa(name, ttl, Ipv6Addr::UNSPECIFIED));
                }
                _ => {}
            }
            response
        }
    }
}

#[cfg(test)]
mod tests {
    use goethite_proto::{Edns, Question, RecordClass};

    use super::*;

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
                padding: false,
            }),
        }
    }

    #[test]
    fn null_ip_answers() {
        let a = blocked_response(&query(RecordType::A), BlockResponse::NullIp, 10);
        assert_eq!(a.rcode, ResponseCode::NO_ERROR);
        assert_eq!(a.answers[0].ip(), Some(Ipv4Addr::UNSPECIFIED.into()));
        assert_eq!(a.answers[0].ttl(), 10);
        let aaaa = blocked_response(&query(RecordType::AAAA), BlockResponse::NullIp, 10);
        assert_eq!(aaaa.answers[0].ip(), Some(Ipv6Addr::UNSPECIFIED.into()));
        let mx = blocked_response(&query(RecordType::MX), BlockResponse::NullIp, 10);
        assert_eq!(mx.rcode, ResponseCode::NO_ERROR);
        assert_eq!(mx.answers, vec![]);
    }

    #[test]
    fn nxdomain_and_refused() {
        let nx = blocked_response(&query(RecordType::A), BlockResponse::NxDomain, 10);
        assert_eq!(nx.rcode, ResponseCode::NX_DOMAIN);
        assert_eq!(nx.answers, vec![]);
        let refused = blocked_response(&query(RecordType::A), BlockResponse::Refused, 10);
        assert_eq!(refused.rcode, ResponseCode::REFUSED);
    }
}
