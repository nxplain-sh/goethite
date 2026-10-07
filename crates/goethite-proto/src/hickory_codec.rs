//! [`DnsCodec`] implemented with hickory-proto.
//!
//! This is the only module that touches hickory-proto's message types.

use hickory_proto::op::{self, Message, MessageType, OpCode};
use hickory_proto::rr::{self, DNSClass, RData, rdata};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};

use crate::codec::RawHeader;
use crate::{
    DecodeError, DnsCodec, Edns, EncodeError, Name, Query, Question, RecordClass, RecordData,
    RecordType, Response, WireError,
};

/// The default [`DnsCodec`], backed by hickory-proto.
#[derive(Clone, Copy, Debug, Default)]
pub struct HickoryCodec;

impl DnsCodec for HickoryCodec {
    fn decode_query(&self, wire: &[u8]) -> Result<Query, DecodeError> {
        let header = RawHeader::check_query(wire)?;
        check_sections(wire, &header)?;
        // The question and every additional record are structurally sound, so
        // whatever hickory still rejects (a second OPT record, an inconsistent
        // option) is in the additional section.
        let message = Message::from_vec(wire).map_err(|e| DecodeError::MalformedAdditional {
            context: header.context(),
            source: WireError::new(e),
        })?;

        // `check_query` guarantees exactly one question in the header, and the
        // parser read exactly that many.
        let Some(question) = message.queries.first() else {
            return Err(DecodeError::FormatError(header.context()));
        };
        let edns = match &message.edns {
            None => None,
            Some(edns) if edns.version() != 0 => {
                return Err(DecodeError::BadVersion {
                    context: header.context(),
                    version: edns.version(),
                });
            }
            Some(edns) => Some(Edns {
                udp_payload_size: edns.max_payload(),
                dnssec_ok: edns.flags().dnssec_ok,
            }),
        };

        Ok(Query {
            id: message.metadata.id,
            recursion_desired: message.metadata.recursion_desired,
            checking_disabled: message.metadata.checking_disabled,
            authentic_data: message.metadata.authentic_data,
            question: Question {
                name: Name(question.name().clone()),
                qtype: RecordType(question.query_type().into()),
                qclass: RecordClass(question.query_class().into()),
            },
            edns,
        })
    }

    fn encode_query(&self, query: &Query, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let mut message = Message::new(query.id, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = query.recursion_desired;
        message.metadata.checking_disabled = query.checking_disabled;
        message.metadata.authentic_data = query.authentic_data;
        message.add_query(question_to_hickory(&query.question));
        if let Some(edns) = query.edns {
            message.set_edns(edns_to_hickory(edns));
        }
        emit(&message, out)
    }

    fn encode_response(
        &self,
        response: &Response,
        max_len: usize,
        out: &mut Vec<u8>,
    ) -> Result<(), EncodeError> {
        out.clear();
        check_representable(response)?;
        emit(&response_to_hickory(response, true), out)?;
        if out.len() <= max_len {
            return Ok(());
        }

        // Too big: send the header, question and OPT record with TC set so the
        // client retries over TCP.
        let mut truncated = response_to_hickory(response, false);
        truncated.metadata.truncation = true;
        emit(&truncated, out)?;
        if out.len() <= max_len {
            return Ok(());
        }
        let len = out.len();
        out.clear();
        Err(EncodeError::TooLarge { len, max_len })
    }
}

/// Walks the question and the additional records without building a message.
///
/// This classifies problems before hickory parses anything: an unreadable
/// question means the message is dropped, anything wrong after it gets
/// FORMERR. It also checks EDNS options, which hickory skips silently when
/// their lengths are wrong.
fn check_sections(wire: &[u8], header: &RawHeader) -> Result<(), DecodeError> {
    let mut decoder = BinDecoder::new(wire);
    op::Header::read(&mut decoder)
        .and_then(|_| op::Query::read(&mut decoder))
        .map_err(|e| DecodeError::Malformed(WireError::new(e)))?;
    for _ in 0..header.additional_count {
        check_record(&mut decoder).map_err(|source| DecodeError::MalformedAdditional {
            context: header.context(),
            source,
        })?;
    }
    Ok(())
}

/// Reads one resource record, checking the options if it is an OPT record.
fn check_record(decoder: &mut BinDecoder<'_>) -> Result<(), WireError> {
    rr::Name::read(decoder).map_err(WireError::new)?;
    let record_type = decoder.read_u16().map_err(WireError::new)?.unverified();
    decoder.read_u16().map_err(WireError::new)?; // class
    decoder.read_u32().map_err(WireError::new)?; // TTL
    let len = decoder.read_u16().map_err(WireError::new)?.unverified();
    let data = decoder
        .read_slice(usize::from(len))
        .map_err(WireError::new)?
        .unverified();
    if record_type == RecordType::OPT.0 {
        check_edns_options(data).map_err(WireError::new)?;
    }
    Ok(())
}

/// A malformed EDNS option.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct OptionError(&'static str);

/// EDNS Client Subnet (RFC 7871).
const OPTION_CLIENT_SUBNET: u16 = 8;
/// DNS cookie (RFC 7873).
const OPTION_COOKIE: u16 = 10;

/// Checks the option list in OPT record data: every option must fit, and the
/// options with length rules goethite knows must follow them.
fn check_edns_options(mut rest: &[u8]) -> Result<(), OptionError> {
    while !rest.is_empty() {
        let (header, tail) = rest
            .split_first_chunk::<4>()
            .ok_or(OptionError("truncated EDNS option header"))?;
        let [code0, code1, len0, len1] = *header;
        let len = usize::from(u16::from_be_bytes([len0, len1]));
        let (data, tail) = tail.split_at_checked(len).ok_or(OptionError(
            "EDNS option runs past the end of the OPT record",
        ))?;
        match u16::from_be_bytes([code0, code1]) {
            OPTION_COOKIE => check_cookie(data)?,
            OPTION_CLIENT_SUBNET => check_client_subnet(data)?,
            _ => {}
        }
        rest = tail;
    }
    Ok(())
}

/// RFC 7873 5.2.2: an 8-byte client cookie, optionally followed by an 8 to
/// 32-byte server cookie.
fn check_cookie(data: &[u8]) -> Result<(), OptionError> {
    if data.len() == 8 || (16..=40).contains(&data.len()) {
        Ok(())
    } else {
        Err(OptionError("COOKIE option has an invalid length"))
    }
}

/// RFC 7871 6: the address uses exactly the octets the source prefix needs,
/// and every bit past the prefix is zero.
fn check_client_subnet(data: &[u8]) -> Result<(), OptionError> {
    let (header, address) = data
        .split_first_chunk::<4>()
        .ok_or(OptionError("client-subnet option is too short"))?;
    let [family0, family1, source_prefix, _scope_prefix] = *header;
    let max_prefix = match u16::from_be_bytes([family0, family1]) {
        1 => 32,
        2 => 128,
        _ => return Err(OptionError("client-subnet option has an unknown family")),
    };
    if source_prefix > max_prefix {
        return Err(OptionError(
            "client-subnet prefix is longer than the address",
        ));
    }
    if address.len() != usize::from(source_prefix.div_ceil(8)) {
        return Err(OptionError(
            "client-subnet address has the wrong number of octets",
        ));
    }
    let used_bits = u32::from(source_prefix % 8);
    let spare_bits = u8::MAX.checked_shr(used_bits).unwrap_or(0);
    if used_bits != 0 && address.last().is_some_and(|last| last & spare_bits != 0) {
        return Err(OptionError(
            "client-subnet address has bits set past the prefix",
        ));
    }
    Ok(())
}

/// Rejects field values hickory would silently truncate on the wire.
fn check_representable(response: &Response) -> Result<(), EncodeError> {
    let reason = if response.opcode.0 > 0x0f {
        "opcode does not fit in 4 bits"
    } else if response.rcode.0 > 0x0fff {
        "response code does not fit in 12 bits"
    } else if response.rcode.0 > 0x0f && response.edns.is_none() {
        "an extended response code needs EDNS"
    } else {
        return Ok(());
    };
    Err(EncodeError::Unrepresentable { reason })
}

fn emit(message: &Message, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    out.clear();
    let mut encoder = BinEncoder::new(out);
    message.emit(&mut encoder).map_err(|e| {
        out.clear();
        EncodeError::Wire(WireError::new(e))
    })
}

fn question_to_hickory(question: &Question) -> op::Query {
    let mut query = op::Query::query(question.name.0.clone(), question.qtype.0.into());
    query.set_query_class(question.qclass.0.into());
    query
}

fn edns_to_hickory(edns: Edns) -> op::Edns {
    let mut out = op::Edns::new();
    out.set_max_payload(edns.udp_payload_size)
        .set_dnssec_ok(edns.dnssec_ok);
    out
}

fn record_to_hickory(record: &crate::Record) -> rr::Record {
    let data = match record.data {
        RecordData::A(addr) => RData::A(rdata::A(addr)),
        RecordData::Aaaa(addr) => RData::AAAA(rdata::AAAA(addr)),
    };
    let mut out = rr::Record::from_rdata(record.name.0.clone(), record.ttl, data);
    out.dns_class = DNSClass::IN;
    out
}

fn response_to_hickory(response: &Response, with_records: bool) -> Message {
    let opcode = OpCode::from_u8(response.opcode.0);
    let mut message = Message::new(response.id, MessageType::Response, opcode);
    let metadata = &mut message.metadata;
    metadata.authoritative = response.authoritative;
    metadata.recursion_desired = response.recursion_desired;
    metadata.recursion_available = response.recursion_available;
    metadata.authentic_data = response.authentic_data;
    metadata.checking_disabled = response.checking_disabled;
    metadata.response_code = response.rcode.0.into();
    if let Some(question) = &response.question {
        message.add_query(question_to_hickory(question));
    }
    if with_records {
        message.add_answers(response.answers.iter().map(record_to_hickory));
    }
    if let Some(edns) = response.edns {
        message.set_edns(edns_to_hickory(edns));
    }
    message
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::{Opcode, Record, ResponseCode};

    fn header(flags: [u8; 2], counts: [u16; 4]) -> Vec<u8> {
        let mut wire = vec![0xab, 0xcd, flags[0], flags[1]];
        for count in counts {
            wire.extend_from_slice(&count.to_be_bytes());
        }
        wire
    }

    fn sample_query() -> Query {
        Query {
            id: 0x1234,
            recursion_desired: true,
            checking_disabled: false,
            authentic_data: true,
            question: Question {
                name: "goethite.test.".parse().unwrap(),
                qtype: RecordType::A,
                qclass: RecordClass::IN,
            },
            edns: Some(Edns {
                udp_payload_size: 1232,
                dnssec_ok: true,
            }),
        }
    }

    fn encode(query: &Query) -> Vec<u8> {
        let mut out = Vec::new();
        HickoryCodec.encode_query(query, &mut out).unwrap();
        out
    }

    #[test]
    fn decodes_what_it_encodes() {
        let query = sample_query();
        assert_eq!(HickoryCodec.decode_query(&encode(&query)).unwrap(), query);
    }

    #[test]
    fn short_messages_are_dropped() {
        let err = HickoryCodec.decode_query(&[0; 11]).unwrap_err();
        assert!(matches!(err, DecodeError::TooShort { len: 11 }));
        assert!(err.response().is_none());
    }

    #[test]
    fn responses_are_dropped() {
        let err = HickoryCodec
            .decode_query(&header([0x80, 0], [1, 0, 0, 0]))
            .unwrap_err();
        assert!(matches!(err, DecodeError::NotAQuery));
        assert!(err.response().is_none());
    }

    #[test]
    fn other_opcodes_get_notimp() {
        // Opcode 5 (UPDATE) with RD set.
        let err = HickoryCodec
            .decode_query(&header([5 << 3 | 1, 0], [1, 0, 0, 0]))
            .unwrap_err();
        let response = err.response().unwrap();
        assert_eq!(response.rcode, ResponseCode::NOT_IMP);
        assert_eq!(response.opcode, Opcode::UPDATE);
        assert_eq!(response.id, 0xabcd);
        assert!(response.recursion_desired);
    }

    #[test]
    fn bad_section_counts_get_formerr_before_parsing() {
        for counts in [
            [0, 0, 0, 0],
            [2, 0, 0, 0],
            [u16::MAX, 0, 0, 0],
            [1, 1, 0, 0],
            [1, 0, 1, 0],
            [1, 0, 0, 3],
            [1, u16::MAX, u16::MAX, u16::MAX],
        ] {
            let err = HickoryCodec
                .decode_query(&header([0, 0], counts))
                .unwrap_err();
            assert!(matches!(err, DecodeError::FormatError(_)), "{counts:?}");
            assert_eq!(err.response().unwrap().rcode, ResponseCode::FORM_ERR);
        }
    }

    /// Header (12) + `goethite.test.` (15) + type and class (4).
    const SAMPLE_QUESTION_END: usize = 31;

    #[test]
    fn truncated_question_is_dropped() {
        let wire = encode(&sample_query());
        for len in 12..SAMPLE_QUESTION_END {
            let err = HickoryCodec.decode_query(&wire[..len]).unwrap_err();
            assert!(matches!(err, DecodeError::Malformed(_)), "len {len}");
            assert!(err.response().is_none());
        }
    }

    #[test]
    fn truncated_additional_section_gets_formerr() {
        let wire = encode(&sample_query());
        for len in SAMPLE_QUESTION_END..wire.len() {
            let err = HickoryCodec.decode_query(&wire[..len]).unwrap_err();
            assert!(
                matches!(err, DecodeError::MalformedAdditional { .. }),
                "len {len}"
            );
            assert_eq!(err.response().unwrap().rcode, ResponseCode::FORM_ERR);
        }
    }

    /// The sample query with ARCOUNT 2 and a second OPT record appended.
    fn with_extra_additional(record: &[u8]) -> Vec<u8> {
        let mut wire = encode(&sample_query());
        wire[11] = 2;
        wire.extend_from_slice(record);
        wire
    }

    #[test]
    fn duplicate_opt_records_get_formerr() {
        // RFC 6891 6.1.1: more than one OPT record MUST get FORMERR.
        let opt = [0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0];
        let err = HickoryCodec
            .decode_query(&with_extra_additional(&opt))
            .unwrap_err();
        assert!(matches!(err, DecodeError::MalformedAdditional { .. }));
        let response = err.response().unwrap();
        assert_eq!(response.rcode, ResponseCode::FORM_ERR);
        assert_eq!(response.id, 0x1234);
    }

    #[test]
    fn malformed_client_subnet_gets_formerr() {
        // RFC 7871 7.1.2: an inconsistent ECS option MUST get FORMERR. Source
        // prefix 40 is impossible for IPv4.
        let mut wire = encode(&Query {
            edns: None,
            ..sample_query()
        });
        wire[11] = 1;
        wire.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 12]);
        wire.extend_from_slice(&[0, 8, 0, 8, 0, 1, 40, 0, 192, 0, 2, 1]);
        let err = HickoryCodec.decode_query(&wire).unwrap_err();
        assert_eq!(err.response().unwrap().rcode, ResponseCode::FORM_ERR);
    }

    /// The sample query without EDNS, plus an OPT record carrying `options`.
    fn with_options(options: &[u8]) -> Vec<u8> {
        let mut wire = encode(&Query {
            edns: None,
            ..sample_query()
        });
        wire[11] = 1;
        wire.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0]);
        wire.extend_from_slice(&u16::try_from(options.len()).unwrap().to_be_bytes());
        wire.extend_from_slice(options);
        wire
    }

    fn option(code: u16, data: &[u8]) -> Vec<u8> {
        let mut out = code.to_be_bytes().to_vec();
        out.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    fn gets_formerr(wire: &[u8]) -> bool {
        match HickoryCodec.decode_query(wire) {
            Err(err @ DecodeError::MalformedAdditional { .. }) => {
                err.response().unwrap().rcode == ResponseCode::FORM_ERR
            }
            _ => false,
        }
    }

    #[test]
    fn edns_option_running_past_the_opt_record_gets_formerr() {
        // Claims 5 bytes, carries 2. hickory alone ignores this and answers.
        assert!(gets_formerr(&with_options(&[0, 10, 0, 5, 1, 2])));
        // A truncated option header.
        assert!(gets_formerr(&with_options(&[0, 10, 0])));
        // Well-formed options of unknown codes are fine.
        let unknown = [option(65_001, b"abc"), option(65_002, b"")].concat();
        assert!(HickoryCodec.decode_query(&with_options(&unknown)).is_ok());
    }

    #[test]
    fn cookie_length_is_checked() {
        for len in [8, 16, 40] {
            let wire = with_options(&option(OPTION_COOKIE, &vec![7; len]));
            assert!(HickoryCodec.decode_query(&wire).is_ok(), "len {len}");
        }
        for len in [0, 7, 9, 15, 41] {
            let wire = with_options(&option(OPTION_COOKIE, &vec![7; len]));
            assert!(gets_formerr(&wire), "len {len}");
        }
    }

    #[test]
    fn client_subnet_must_match_its_prefix() {
        let ecs = |family: u16, prefix: u8, address: &[u8]| {
            let mut data = family.to_be_bytes().to_vec();
            data.extend_from_slice(&[prefix, 0]);
            data.extend_from_slice(address);
            with_options(&option(OPTION_CLIENT_SUBNET, &data))
        };
        let ok = [
            ecs(1, 24, &[192, 0, 2]),
            ecs(1, 20, &[192, 0, 0x20]),
            ecs(1, 0, &[]),
            ecs(2, 56, &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0]),
        ];
        for wire in &ok {
            assert!(HickoryCodec.decode_query(wire).is_ok());
        }
        let bad = [
            ecs(1, 24, &[192, 0, 2, 1]), // an octet too many
            ecs(1, 24, &[192, 0]),       // an octet too few
            ecs(1, 20, &[192, 0, 0x21]), // a bit set past the prefix
            ecs(1, 33, &[0; 5]),         // prefix longer than IPv4
            ecs(3, 8, &[1]),             // unknown family
        ];
        for wire in &bad {
            assert!(gets_formerr(wire));
        }
    }

    #[test]
    fn unrepresentable_responses_are_rejected() {
        let query = Query {
            edns: None,
            ..sample_query()
        };
        let mut out = vec![1, 2, 3];
        for (rcode, opcode) in [(16, 0), (0x1000, 0), (0, 16)] {
            let mut response = Response::for_query(&query, ResponseCode(rcode));
            response.opcode = Opcode(opcode);
            let err = HickoryCodec
                .encode_response(&response, 512, &mut out)
                .unwrap_err();
            assert!(matches!(err, EncodeError::Unrepresentable { .. }), "{err}");
            assert_eq!(out, Vec::<u8>::new());
        }
    }

    #[test]
    fn unsupported_edns_version_gets_badvers() {
        let mut wire = encode(&sample_query());
        // The OPT record ends the message: name(1) type(2) class(2) then the
        // TTL field whose second byte is the version, then rdlength(2).
        let version_at = wire.len() - 2 - 4 + 1;
        wire[version_at] = 1;
        let err = HickoryCodec.decode_query(&wire).unwrap_err();
        assert!(matches!(err, DecodeError::BadVersion { version: 1, .. }));

        let response = err.response().unwrap();
        assert_eq!(response.rcode, ResponseCode::BAD_VERS);
        assert!(response.edns.is_some());

        let mut out = Vec::new();
        HickoryCodec
            .encode_response(&response, 512, &mut out)
            .unwrap();
        // RCODE 16 is both BADVERS (EDNS) and BADSIG (TSIG); hickory names it BADSIG.
        let decoded = Message::from_vec(&out).unwrap();
        assert_eq!(u16::from(decoded.metadata.response_code), 16);
        assert!(decoded.edns.is_some());
    }

    #[test]
    fn oversized_responses_are_truncated() {
        let query = sample_query();
        let mut response = Response::for_query(&query, ResponseCode::NO_ERROR);
        for i in 0..100 {
            response.answers.push(Record {
                name: query.question.name.clone(),
                ttl: 60,
                data: RecordData::A(Ipv4Addr::new(10, 0, 0, i)),
            });
        }

        let mut out = Vec::new();
        HickoryCodec
            .encode_response(&response, 4096, &mut out)
            .unwrap();
        let full = Message::from_vec(&out).unwrap();
        assert!(!full.metadata.truncation);
        assert_eq!(full.answers.len(), 100);

        HickoryCodec
            .encode_response(&response, 512, &mut out)
            .unwrap();
        assert!(out.len() <= 512);
        let truncated = Message::from_vec(&out).unwrap();
        assert!(truncated.metadata.truncation);
        assert_eq!(truncated.answers, vec![]);
        assert_eq!(truncated.queries.len(), 1);
        assert!(truncated.edns.is_some());

        let err = HickoryCodec
            .encode_response(&response, 20, &mut out)
            .unwrap_err();
        assert!(matches!(err, EncodeError::TooLarge { max_len: 20, .. }));
        assert_eq!(out, Vec::<u8>::new());
    }
}
