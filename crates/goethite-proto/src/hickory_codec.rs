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
        let message = Message::from_vec(wire).map_err(|e| {
            let source = WireError::new(e);
            if question_is_readable(wire) {
                DecodeError::MalformedAdditional {
                    context: header.context(),
                    source,
                }
            } else {
                DecodeError::Malformed(source)
            }
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

/// Whether the header and question parse, i.e. the problem is further on.
fn question_is_readable(wire: &[u8]) -> bool {
    let mut decoder = BinDecoder::new(wire);
    op::Header::read(&mut decoder).is_ok() && op::Query::read(&mut decoder).is_ok()
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
    let opcode = OpCode::from_u8(response.opcode.0 & 0x0f);
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
