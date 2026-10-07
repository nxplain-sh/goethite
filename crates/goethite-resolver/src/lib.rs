//! Query resolution for goethite.
//!
//! The [`Resolver`] runs the resolution pipeline for one query: query-type
//! policy, then local records, then forwarding to upstream resolvers. Later
//! milestones add the cache and the filter check in front of forwarding, and
//! later phases recursion with DNSSEC validation.

#![forbid(unsafe_code)]

mod forward;

use std::net::Ipv4Addr;

use goethite_proto::{
    Name, NameError, Query, Record, RecordClass, RecordType, Response, ResponseCode,
};

pub use forward::{
    Forwarder, ForwarderConfig, ForwarderError, MAX_UPSTREAMS, Transport, UpstreamConfig,
};

/// The name every build answers itself, to check that the server is alive.
pub const TEST_NAME: &str = "goethite.test.";

/// The address [`TEST_NAME`] resolves to.
pub const TEST_ADDR: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 53);

/// Time to live of the built-in test record, in seconds.
pub const TEST_TTL: u32 = 60;

/// The built-in record `goethite.test. 60 IN A 127.0.0.53`.
///
/// # Errors
///
/// Never in practice; [`TEST_NAME`] is a valid name. The `Result` keeps name
/// parsing panic-free.
pub fn test_record() -> Result<Record, NameError> {
    Ok(Record::a(TEST_NAME.parse::<Name>()?, TEST_TTL, TEST_ADDR))
}

/// Answers queries.
pub struct Resolver {
    local: Vec<Record>,
    forwarder: Option<Forwarder>,
}

impl Resolver {
    /// A resolver that answers authoritatively for the names in `local` and
    /// refuses everything else.
    pub fn new(local: Vec<Record>) -> Self {
        Self {
            local,
            forwarder: None,
        }
    }

    /// Forwards everything that is not a local name to `forwarder`.
    #[must_use]
    pub fn with_forwarder(mut self, forwarder: Forwarder) -> Self {
        self.forwarder = Some(forwarder);
        self
    }

    /// Answers `query`.
    ///
    /// - zone transfers (`AXFR`, `IXFR`): `REFUSED`, since none are offered
    ///   (RFC 5936);
    /// - meta-types and obsolete query types that have no place in a question
    ///   (`OPT`, `TKEY`, `TSIG`, `MAILA`, `MAILB`, 128 to 248): `FORMERR`, as
    ///   Unbound answers them (RFC 6895);
    /// - classes other than `IN` (e.g. `CH` server-identification probes):
    ///   `REFUSED`, never forwarded;
    /// - a name with local records: those records of the asked type,
    ///   authoritatively, or an empty `NOERROR` (NODATA) if there are none;
    /// - anything else: forwarded upstream, or `REFUSED` without a forwarder.
    pub async fn resolve(&self, query: &Query) -> Response {
        let mut response = self.answer(query).await;
        response.recursion_available = self.forwarder.is_some();
        response
    }

    async fn answer(&self, query: &Query) -> Response {
        let question = &query.question;
        if matches!(question.qtype, RecordType::AXFR | RecordType::IXFR) {
            return Response::for_query(query, ResponseCode::REFUSED);
        }
        if is_meta_qtype(question.qtype) {
            return Response::for_query(query, ResponseCode::FORM_ERR);
        }
        if question.qclass != RecordClass::IN {
            return Response::for_query(query, ResponseCode::REFUSED);
        }
        if let Some(response) = self.local_answer(query) {
            return response;
        }
        match &self.forwarder {
            Some(forwarder) => forwarder.forward(query).await,
            None => Response::for_query(query, ResponseCode::REFUSED),
        }
    }

    fn local_answer(&self, query: &Query) -> Option<Response> {
        let question = &query.question;
        let mut matching = self
            .local
            .iter()
            .filter(|record| record.name() == &question.name)
            .peekable();
        matching.peek()?;
        let mut response = Response::for_query(query, ResponseCode::NO_ERROR);
        response.authoritative = true;
        response.answers = matching
            .filter(|record| {
                question.qtype == RecordType::ANY || record.record_type() == question.qtype
            })
            .cloned()
            .collect();
        Some(response)
    }
}

/// Types that are not valid in a question: meta-types other than `ANY` and
/// the zone transfers, plus the obsolete mail query types.
fn is_meta_qtype(qtype: RecordType) -> bool {
    matches!(
        qtype,
        RecordType::OPT
            | RecordType::TKEY
            | RecordType::TSIG
            | RecordType::MAILB
            | RecordType::MAILA
    ) || (128..=248).contains(&qtype.0)
}

#[cfg(test)]
mod tests {
    use goethite_proto::{Edns, Question};

    use super::*;

    fn resolver() -> Resolver {
        Resolver::new(vec![test_record().unwrap()])
    }

    fn query(name: &str, qtype: RecordType, qclass: RecordClass) -> Query {
        Query {
            id: 42,
            recursion_desired: true,
            checking_disabled: false,
            authentic_data: false,
            question: Question {
                name: name.parse().unwrap(),
                qtype,
                qclass,
            },
            edns: Some(Edns {
                udp_payload_size: 4096,
                dnssec_ok: false,
            }),
        }
    }

    /// Resolves without a runtime: the paths tested here never wait.
    fn resolve(resolver: &Resolver, query: &Query) -> Response {
        let mut future = std::pin::pin!(resolver.resolve(query));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        match future.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(response) => response,
            std::task::Poll::Pending => panic!("local resolution should not wait"),
        }
    }

    #[test]
    fn answers_the_test_name() {
        let response = resolve(
            &resolver(),
            &query(TEST_NAME, RecordType::A, RecordClass::IN),
        );
        assert_eq!(response.rcode, ResponseCode::NO_ERROR);
        assert!(response.authoritative);
        assert!(!response.recursion_available);
        assert_eq!(response.id, 42);
        assert_eq!(response.answers, vec![test_record().unwrap()]);
    }

    #[test]
    fn name_matching_ignores_case() {
        let response = resolve(
            &resolver(),
            &query("GoEtHiTe.TeSt", RecordType::A, RecordClass::IN),
        );
        assert_eq!(response.rcode, ResponseCode::NO_ERROR);
        assert_eq!(response.answers.len(), 1);
    }

    #[test]
    fn other_types_of_the_test_name_get_nodata() {
        let response = resolve(
            &resolver(),
            &query(TEST_NAME, RecordType::AAAA, RecordClass::IN),
        );
        assert_eq!(response.rcode, ResponseCode::NO_ERROR);
        assert_eq!(response.answers, vec![]);
    }

    #[test]
    fn zone_transfers_are_refused() {
        for qtype in [RecordType::AXFR, RecordType::IXFR] {
            let response = resolve(&resolver(), &query(TEST_NAME, qtype, RecordClass::IN));
            assert_eq!(response.rcode, ResponseCode::REFUSED, "{qtype}");
            assert!(!response.authoritative);
            assert_eq!(response.answers, vec![]);
        }
    }

    #[test]
    fn meta_types_get_formerr() {
        for qtype in [
            RecordType::OPT,
            RecordType::TKEY,
            RecordType::TSIG,
            RecordType::MAILA,
            RecordType::MAILB,
            RecordType(128),
            RecordType(248),
        ] {
            for name in [TEST_NAME, "example.com."] {
                let response = resolve(&resolver(), &query(name, qtype, RecordClass::IN));
                assert_eq!(response.rcode, ResponseCode::FORM_ERR, "{name} {qtype}");
            }
        }
        // ANY (255) and ordinary types above the meta range are not meta-types.
        let any = resolve(
            &resolver(),
            &query(TEST_NAME, RecordType::ANY, RecordClass::IN),
        );
        assert_eq!(any.rcode, ResponseCode::NO_ERROR);
        assert_eq!(any.answers.len(), 1);
        let caa = resolve(
            &resolver(),
            &query(TEST_NAME, RecordType(257), RecordClass::IN),
        );
        assert_eq!(caa.rcode, ResponseCode::NO_ERROR);
    }

    #[test]
    fn without_a_forwarder_everything_else_is_refused() {
        for (name, qclass) in [
            ("example.com.", RecordClass::IN),
            ("test.", RecordClass::IN),
            ("sub.goethite.test.", RecordClass::IN),
            (TEST_NAME, RecordClass::CH),
        ] {
            let response = resolve(&resolver(), &query(name, RecordType::A, qclass));
            assert_eq!(response.rcode, ResponseCode::REFUSED, "{name} {qclass}");
            assert_eq!(response.answers, vec![]);
            assert!(!response.authoritative);
        }
    }
}
