//! Queries, responses and records.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_proto::rr::rdata::svcb::{IpHint, SvcParamValue};
use hickory_proto::rr::{RData, rdata};
use hickory_proto::serialize::binary::BinEncodable;

use crate::codec::Escaped;
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

impl Question {
    /// Whether `other` asks the same thing with the name in exactly the same
    /// case. Used to match upstream responses to 0x20-randomized queries.
    pub fn matches_exactly(&self, other: &Question) -> bool {
        self.qtype == other.qtype && self.qclass == other.qclass && self.name.eq_exact(&other.name)
    }
}

/// The EDNS(0) parameters of a message (RFC 6891).
///
/// Only version 0 exists; queries with any other version are rejected with
/// `BADVERS` while decoding, so the version is not stored. Of the EDNS
/// options, only Padding is modelled; the codec checks the others' lengths
/// and drops them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Edns {
    /// The largest UDP payload the sender can receive. Values below 512 are
    /// treated as 512.
    pub udp_payload_size: u16,
    /// The DNSSEC OK (`DO`) bit.
    pub dnssec_ok: bool,
    /// The Padding option (RFC 7830). Decoded: the message carried one.
    /// Encoded: the message is padded as RFC 8467 recommends, a query to a
    /// multiple of [`QUERY_PADDING_BLOCK`] bytes and a response to a
    /// multiple of [`RESPONSE_PADDING_BLOCK`], within its size limit.
    /// Padding hides a message's length from someone watching an encrypted
    /// connection; it is pointless, and never used, in plain DNS.
    pub padding: bool,
    /// The info code of an Extended DNS Error (RFC 8914) the message
    /// carries, without its extra text. Blocked answers use `15`
    /// ("Blocked"); an upstream's code is relayed as it came.
    pub extended_error: Option<u16>,
}

impl Edns {
    /// The EDNS parameters goethite puts in its own messages.
    pub const fn ours() -> Self {
        Self {
            udp_payload_size: MAX_UDP_PAYLOAD,
            dnssec_ok: false,
            padding: false,
            extended_error: None,
        }
    }
}

/// Queries are padded to a multiple of this many bytes (RFC 8467 4.1).
pub const QUERY_PADDING_BLOCK: usize = 128;

/// Responses are padded to a multiple of this many bytes (RFC 8467 4.1).
pub const RESPONSE_PADDING_BLOCK: usize = 468;

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

/// A resource record of any type.
///
/// The record data is opaque: goethite forwards and caches records it does
/// not understand, and looks inside only the few it acts on (addresses,
/// aliases, SOA minimums).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Record {
    name: Name,
    class: RecordClass,
    ttl: u32,
    pub(crate) data: RData,
}

impl Record {
    /// An `IN A` record.
    pub fn a(name: Name, ttl: u32, addr: Ipv4Addr) -> Self {
        Self::new(name, ttl, RData::A(rdata::A(addr)))
    }

    /// An `IN AAAA` record.
    pub fn aaaa(name: Name, ttl: u32, addr: Ipv6Addr) -> Self {
        Self::new(name, ttl, RData::AAAA(rdata::AAAA(addr)))
    }

    /// An `IN CNAME` record pointing at `target`.
    pub fn cname(name: Name, ttl: u32, target: Name) -> Self {
        Self::new(name, ttl, RData::CNAME(rdata::CNAME(target.0)))
    }

    /// An `IN NS` record naming `server`.
    pub fn ns(name: Name, ttl: u32, server: Name) -> Self {
        Self::new(name, ttl, RData::NS(rdata::NS(server.0)))
    }

    /// An `IN SOA` record; only the fields negative caching needs are taken.
    pub fn soa(zone: Name, ttl: u32, primary: Name, minimum: u32) -> Self {
        let mailbox = hickory_proto::rr::Name::root();
        let soa = rdata::SOA::new(primary.0, mailbox, 1, 3600, 600, 86_400, minimum);
        Self::new(zone, ttl, RData::SOA(soa))
    }

    fn new(name: Name, ttl: u32, data: RData) -> Self {
        Self {
            name,
            class: RecordClass::IN,
            ttl,
            data,
        }
    }

    pub(crate) fn from_parts(name: Name, class: RecordClass, ttl: u32, data: RData) -> Self {
        Self {
            name,
            class,
            ttl,
            data,
        }
    }

    /// Owner name.
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Replaces the owner name, keeping everything else.
    pub fn set_name(&mut self, name: Name) {
        self.name = name;
    }

    /// The record's class.
    pub fn class(&self) -> RecordClass {
        self.class
    }

    /// Time to live in seconds.
    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Replaces the time to live.
    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
    }

    /// The record's type.
    pub fn record_type(&self) -> RecordType {
        RecordType(self.data.record_type().into())
    }

    /// The address of an `A` or `AAAA` record.
    pub fn ip(&self) -> Option<IpAddr> {
        self.data.ip_addr()
    }

    /// The target of a `CNAME` record.
    pub fn cname_target(&self) -> Option<Name> {
        match &self.data {
            RData::CNAME(target) => Some(Name(target.0.clone())),
            _ => None,
        }
    }

    /// Undoes 0x20 randomization in the owner name and the names in the
    /// record data (see [`Name::with_case_restored`]).
    pub fn restore_case(&mut self, randomized: &Name, original: &Name) {
        let restore = |name: &mut hickory_proto::rr::Name| {
            let restored = Name(name.clone()).with_case_restored(randomized, original);
            *name = restored.0;
        };
        self.name = self.name.with_case_restored(randomized, original);
        match &mut self.data {
            RData::CNAME(rdata::CNAME(name))
            | RData::NS(rdata::NS(name))
            | RData::PTR(rdata::PTR(name)) => restore(name),
            RData::MX(mx) => restore(&mut mx.exchange),
            RData::SRV(srv) => restore(&mut srv.target),
            RData::SOA(soa) => {
                restore(&mut soa.mname);
                restore(&mut soa.rname);
            }
            RData::SVCB(svcb) | RData::HTTPS(rdata::HTTPS(svcb)) => restore(&mut svcb.target_name),
            _ => {}
        }
    }

    /// The name server of an `NS` record.
    pub fn ns_target(&self) -> Option<Name> {
        match &self.data {
            RData::NS(server) => Some(Name(server.0.clone())),
            _ => None,
        }
    }

    /// The `MINIMUM` field of an `SOA` record (the negative-caching TTL).
    pub fn soa_minimum(&self) -> Option<u32> {
        match &self.data {
            RData::SOA(soa) => Some(soa.minimum),
            _ => None,
        }
    }

    /// Removes the `ipv4hint` and `ipv6hint` addresses of an `SVCB` or
    /// `HTTPS` record (RFC 9460 7.3) for which `remove` is true, returning
    /// how many addresses were there. Other record types are untouched.
    pub fn prune_svc_hints(&mut self, remove: impl Fn(IpAddr) -> bool) -> usize {
        let (RData::SVCB(svcb) | RData::HTTPS(rdata::HTTPS(svcb))) = &mut self.data else {
            return 0;
        };
        let mut removed: usize = 0;
        for (_, value) in &mut svcb.svc_params {
            match value {
                SvcParamValue::Ipv4Hint(IpHint(hints)) => {
                    let before = hints.len();
                    hints.retain(|address| !remove(IpAddr::V4(address.0)));
                    removed = removed.saturating_add(before.saturating_sub(hints.len()));
                }
                SvcParamValue::Ipv6Hint(IpHint(hints)) => {
                    let before = hints.len();
                    hints.retain(|address| !remove(IpAddr::V6(address.0)));
                    removed = removed.saturating_add(before.saturating_sub(hints.len()));
                }
                _ => {}
            }
        }
        removed
    }
}

/// The size of `records` in wire bytes, with each name written out in full
/// (no compression), for budgeting caches of answers from untrusted servers.
pub fn records_wire_len(records: &[Record]) -> usize {
    let mut out = Vec::new();
    let mut encoder = hickory_proto::serialize::binary::BinEncoder::new(&mut out);
    encoder.set_canonical_form(true);
    encoder.set_name_encoding(hickory_proto::serialize::binary::NameEncoding::Uncompressed);
    for record in records {
        let wire = hickory_proto::rr::Record::from_rdata(
            record.name.0.clone(),
            record.ttl,
            record.data.clone(),
        );
        if wire.emit(&mut encoder).is_err() {
            return usize::MAX;
        }
    }
    out.len()
}

impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Record({} {} {} {} {})",
            self.name,
            self.ttl,
            self.class,
            self.record_type(),
            Escaped(&self.data.to_string())
        )
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
    /// `TC`: the message was truncated. Set by goethite when a response does
    /// not fit, and read from upstream responses.
    pub truncated: bool,
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
    /// Authority section, e.g. the SOA record of a negative answer.
    pub authority: Vec<Record>,
    /// Additional section, without the OPT record (see `edns`).
    pub additional: Vec<Record>,
    /// EDNS parameters; present whenever the query used EDNS.
    pub edns: Option<Edns>,
}

impl Response {
    /// An empty response to `query` with the given code.
    ///
    /// Copies the ID, `RD`, `CD` and question. If the query used EDNS, the
    /// response carries goethite's own EDNS parameters with the query's `DO`
    /// bit copied, as RFC 3225 requires.
    pub fn for_query(query: &Query, rcode: ResponseCode) -> Self {
        Self {
            id: query.id,
            opcode: Opcode::QUERY,
            authoritative: false,
            truncated: false,
            recursion_desired: query.recursion_desired,
            recursion_available: false,
            authentic_data: false,
            checking_disabled: query.checking_disabled,
            rcode,
            question: Some(query.question.clone()),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            edns: query.edns.map(|edns| Edns {
                dnssec_ok: edns.dnssec_ok,
                ..Edns::ours()
            }),
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
            truncated: false,
            recursion_desired,
            recursion_available: false,
            authentic_data: false,
            checking_disabled: false,
            rcode,
            question: None,
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
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
    fn records_are_measured_in_full() {
        let name: Name = "a-b-c.example.".parse().unwrap();
        let records = vec![
            Record::a(name.clone(), 300, Ipv4Addr::new(192, 0, 2, 1)),
            Record::a(name, 300, Ipv4Addr::new(192, 0, 2, 2)),
        ];
        // 15 bytes of name plus 10 fixed and 4 of address, each; a second
        // record would compress its name to two bytes if allowed.
        assert_eq!(records_wire_len(&records), 2 * 29);
    }

    #[test]
    fn svc_hints_lose_the_addresses_asked_for() {
        use hickory_proto::rr::Name as HickoryName;
        use hickory_proto::rr::rdata::svcb::{IpHint, SvcParamKey, SvcParamValue as Param, SVCB};
        use hickory_proto::rr::rdata::{A, AAAA};

        let params = vec![
            (
                SvcParamKey::Ipv4Hint,
                Param::Ipv4Hint(IpHint(vec![
                    A(Ipv4Addr::new(192, 168, 1, 5)),
                    A(Ipv4Addr::new(192, 0, 2, 7)),
                ])),
            ),
            (
                SvcParamKey::Ipv6Hint,
                Param::Ipv6Hint(IpHint(vec![AAAA("fd00::1".parse().unwrap())])),
            ),
        ];
        let mut record = Record::from_parts(
            "svc.example.".parse().unwrap(),
            RecordClass::IN,
            60,
            RData::HTTPS(rdata::HTTPS(SVCB::new(
                1,
                HickoryName::root(),
                params,
            ))),
        );
        let removed = record.prune_svc_hints(|ip| match ip {
            IpAddr::V4(v4) => v4.is_private(),
            IpAddr::V6(v6) => !v6.is_loopback() && v6.segments()[0] & 0xfe00 == 0xfc00,
        });
        assert_eq!(removed, 2, "the 192.168.x and fd00:: hints");
        // One hint is left: the public 192.0.2.7.
        assert_eq!(record.prune_svc_hints(|_| true), 1);
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
                padding: false,
                extended_error: None,
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
            padding: true,
            extended_error: None,
        }));
        let r = Response::for_query(&q, ResponseCode::REFUSED);
        assert_eq!(r.id, 7);
        assert!(r.recursion_desired);
        assert!(r.checking_disabled);
        assert_eq!(r.question.as_ref(), Some(&q.question));
        assert_eq!(
            r.edns,
            Some(Edns {
                udp_payload_size: MAX_UDP_PAYLOAD,
                dnssec_ok: true,
                padding: false,
                extended_error: None,
            })
        );
        assert_eq!(r.rcode, ResponseCode::REFUSED);
    }
}
