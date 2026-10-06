//! Queries, responses and records.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{Name, Opcode, RecordClass, RecordType, ResponseCode};

/// Size of the fixed DNS message header.
pub const HEADER_LEN: usize = 12;

/// The largest UDP payload a message without EDNS may use (RFC 1035).
pub const MIN_UDP_PAYLOAD: u16 = 512;

/// The UDP payload size goethite advertises and the most it sends over UDP.
///
/// 1232 bytes avoids IP fragmentation on virtually every path (DNS flag day
/// 2020, RFC 9715).
pub const MAX_UDP_PAYLOAD: u16 = 1232;

/// The question of a query: which records of which name are wanted.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Question {
    /// The name being asked about.
    pub name: Name,
    /// The record type being asked for.
    pub qtype: RecordType,
    /// The class being asked for, nearly always `IN`.
    pub qclass: RecordClass,
}

/// The EDNS(0) parameters of a message (RFC 6891).
///
/// Only version 0 exists; queries with any other version are rejected with
/// `BADVERS` while decoding, so the version is not stored. EDNS options are
/// not modelled yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Edns {
    /// The largest UDP payload the sender can receive. Values below 512 are
    /// treated as 512.
    pub udp_payload_size: u16,
    /// The DNSSEC OK (`DO`) bit.
    pub dnssec_ok: bool,
}

impl Edns {
    /// The EDNS parameters goethite puts in its own messages.
    pub const fn ours() -> Self {
        Self {
            udp_payload_size: MAX_UDP_PAYLOAD,
            dnssec_ok: false,
        }
    }
}

/// A standard query (`OPCODE` = `QUERY`) with exactly one question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    /// Transaction ID, copied into the response.
    pub id: u16,
    /// `RD`: the client wants recursion.
    pub recursion_desired: bool,
    /// `CD`: the client asks to skip DNSSEC validation.
    pub checking_disabled: bool,
    /// `AD`: the client understands the authentic-data bit (RFC 6840).
    pub authentic_data: bool,
    /// The question.
    pub question: Question,
    /// EDNS parameters, if the query carried an OPT record.
    pub edns: Option<Edns>,
}

impl Query {
    /// The largest response that may be sent back to this query over UDP.
    ///
    /// The client's advertised EDNS payload size, clamped to
    /// [`MIN_UDP_PAYLOAD`]..=[`MAX_UDP_PAYLOAD`], or 512 bytes without EDNS.
    pub fn max_udp_response_len(&self) -> usize {
        let limit = self.edns.map_or(MIN_UDP_PAYLOAD, |edns| {
            edns.udp_payload_size
                .clamp(MIN_UDP_PAYLOAD, MAX_UDP_PAYLOAD)
        });
        usize::from(limit)
    }
}

/// The data of a resource record.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RecordData {
    /// An IPv4 address.
    A(Ipv4Addr),
    /// An IPv6 address.
    Aaaa(Ipv6Addr),
}

impl RecordData {
    /// The record type this data belongs to.
    pub fn record_type(&self) -> RecordType {
        match self {
            Self::A(_) => RecordType::A,
            Self::Aaaa(_) => RecordType::AAAA,
        }
    }
}

/// A resource record in class `IN`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Record {
    /// Owner name.
    pub name: Name,
    /// Time to live in seconds.
    pub ttl: u32,
    /// Record data.
    pub data: RecordData,
}

impl Record {
    /// The record's type.
    pub fn record_type(&self) -> RecordType {
        self.data.record_type()
    }
}

/// A response message.
#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "DNS header flags are independent bits"
)]
pub struct Response {
    /// Transaction ID of the query being answered.
    pub id: u16,
    /// Opcode of the query being answered.
    pub opcode: Opcode,
    /// `AA`: the answer comes from an authoritative source.
    pub authoritative: bool,
    /// `RD`, copied from the query.
    pub recursion_desired: bool,
    /// `RA`: the server offers recursion.
    pub recursion_available: bool,
    /// `AD`: all answer data is DNSSEC-validated.
    pub authentic_data: bool,
    /// `CD`, copied from the query.
    pub checking_disabled: bool,
    /// Response code, including the EDNS extended range.
    pub rcode: ResponseCode,
    /// The question being answered, if it could be parsed.
    pub question: Option<Question>,
    /// Answer section.
    pub answers: Vec<Record>,
    /// EDNS parameters; present whenever the query used EDNS.
    pub edns: Option<Edns>,
}

impl Response {
    /// An empty response to `query` with the given code.
    ///
    /// Copies the ID, `RD`, `CD` and question, and includes goethite's own
    /// EDNS parameters if the query used EDNS.
    pub fn for_query(query: &Query, rcode: ResponseCode) -> Self {
        Self {
            id: query.id,
            opcode: Opcode::QUERY,
            authoritative: false,
            recursion_desired: query.recursion_desired,
            recursion_available: false,
            authentic_data: false,
            checking_disabled: query.checking_disabled,
            rcode,
            question: Some(query.question.clone()),
            answers: Vec::new(),
            edns: query.edns.map(|_| Edns::ours()),
        }
    }

    /// A response with only a header (and OPT record if `edns` is set), for
    /// queries whose question could not be used.
    pub(crate) fn header_only(
        id: u16,
        opcode: Opcode,
        recursion_desired: bool,
        rcode: ResponseCode,
        edns: Option<Edns>,
    ) -> Self {
        Self {
            id,
            opcode,
            authoritative: false,
            recursion_desired,
            recursion_available: false,
            authentic_data: false,
            checking_disabled: false,
            rcode,
            question: None,
            answers: Vec::new(),
            edns,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(edns: Option<Edns>) -> Query {
        Query {
            id: 7,
            recursion_desired: true,
            checking_disabled: true,
            authentic_data: false,
            question: Question {
                name: "goethite.test.".parse().unwrap(),
                qtype: RecordType::A,
                qclass: RecordClass::IN,
            },
            edns,
        }
    }

    #[test]
    fn udp_limit_without_edns_is_512() {
        assert_eq!(query(None).max_udp_response_len(), 512);
    }

    #[test]
    fn udp_limit_is_clamped() {
        let edns = |size| {
            Some(Edns {
                udp_payload_size: size,
                dnssec_ok: false,
            })
        };
        assert_eq!(query(edns(100)).max_udp_response_len(), 512);
        assert_eq!(query(edns(1000)).max_udp_response_len(), 1000);
        assert_eq!(query(edns(4096)).max_udp_response_len(), 1232);
    }

    #[test]
    fn response_copies_query_fields() {
        let q = query(Some(Edns {
            udp_payload_size: 4096,
            dnssec_ok: true,
        }));
        let r = Response::for_query(&q, ResponseCode::REFUSED);
        assert_eq!(r.id, 7);
        assert!(r.recursion_desired);
        assert!(r.checking_disabled);
        assert_eq!(r.question.as_ref(), Some(&q.question));
        assert_eq!(r.edns, Some(Edns::ours()));
        assert_eq!(r.rcode, ResponseCode::REFUSED);
    }
}
