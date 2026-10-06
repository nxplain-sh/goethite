//! The codec trait, its errors and the decode policy shared by implementations.

use std::fmt;

use crate::message::HEADER_LEN;
use crate::{Edns, Opcode, Query, Response, ResponseCode};

/// Converts between DNS wire format and goethite's message types.
///
/// This is the seam between goethite and the DNS wire-format implementation
/// (see `docs/adr/0001-hickory-proto-behind-trait.md`). Implementations must
/// never panic on any input and must apply the same validation policy, which
/// [`DecodeError`] documents.
pub trait DnsCodec: Send + Sync {
    /// Decodes a query received from a client.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`] if `wire` is not a query goethite can answer.
    /// [`DecodeError::response`] says whether to reply or drop it silently.
    fn decode_query(&self, wire: &[u8]) -> Result<Query, DecodeError>;

    /// Encodes `query` into `out`, replacing its contents.
    ///
    /// # Errors
    ///
    /// Returns an [`EncodeError`] if the query cannot be represented on the wire.
    fn encode_query(&self, query: &Query, out: &mut Vec<u8>) -> Result<(), EncodeError>;

    /// Encodes `response` into `out`, replacing its contents, using at most
    /// `max_len` bytes.
    ///
    /// If the full response does not fit, the answers are dropped and the `TC`
    /// bit is set so the client retries over TCP.
    ///
    /// # Errors
    ///
    /// Returns an [`EncodeError`] if the response cannot be encoded or does not
    /// fit in `max_len` bytes even after truncation. `out` is empty then.
    fn encode_response(
        &self,
        response: &Response,
        max_len: usize,
        out: &mut Vec<u8>,
    ) -> Result<(), EncodeError>;
}

/// Why a message could not be decoded as a query.
///
/// The decode policy, applied before any expensive parsing:
///
/// - shorter than a header, a response (`QR` set), or unparseable: drop it
///   ([`DecodeError::response`] is `None`). Never answering responses
///   prevents reflection loops between servers.
/// - opcode other than `QUERY`: answer `NOTIMP`.
/// - not exactly one question, or any answer or authority records, or more
///   than two additional records: answer `FORMERR`. Checking the header
///   counts first also stops a 12-byte message from making the parser
///   allocate for 65,535 records.
/// - EDNS version other than 0: answer `BADVERS`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// The message is too short to contain a DNS header.
    #[error("message is {len} bytes, shorter than a DNS header")]
    TooShort {
        /// Length of the message in bytes.
        len: usize,
    },
    /// The message is a response, not a query.
    #[error("message is a response, not a query")]
    NotAQuery,
    /// The opcode is not `QUERY`.
    #[error("opcode {} is not implemented", .0.opcode)]
    NotImplemented(ErrorContext),
    /// The section counts are not those of a standard query.
    #[error(
        "query must have one question, no answer or authority records and at most two additional records"
    )]
    FormatError(ErrorContext),
    /// The query uses an EDNS version other than 0.
    #[error("EDNS version {version} is not supported")]
    BadVersion {
        /// Header fields of the query.
        context: ErrorContext,
        /// The EDNS version the query asked for.
        version: u8,
    },
    /// The message is not valid DNS wire format.
    #[error("malformed message: {0}")]
    Malformed(WireError),
}

impl DecodeError {
    /// The response to send for this error, or `None` to drop the message.
    pub fn response(&self) -> Option<Response> {
        let reply = |c: &ErrorContext, rcode, edns| {
            Response::header_only(c.id, c.opcode, c.recursion_desired, rcode, edns)
        };
        match self {
            Self::TooShort { .. } | Self::NotAQuery | Self::Malformed(_) => None,
            Self::NotImplemented(c) => Some(reply(c, ResponseCode::NOT_IMP, None)),
            Self::FormatError(c) => Some(reply(c, ResponseCode::FORM_ERR, None)),
            Self::BadVersion { context, .. } => {
                Some(reply(context, ResponseCode::BAD_VERS, Some(Edns::ours())))
            }
        }
    }
}

/// The header fields needed to answer a query that was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErrorContext {
    pub(crate) id: u16,
    pub(crate) opcode: Opcode,
    pub(crate) recursion_desired: bool,
}

/// Why a message could not be encoded.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EncodeError {
    /// The message does not fit in the allowed size even after truncation.
    #[error("message needs {len} bytes but at most {max_len} are allowed")]
    TooLarge {
        /// Size of the smallest encoding goethite could produce.
        len: usize,
        /// The size limit that was requested.
        max_len: usize,
    },
    /// The wire-format implementation rejected the message.
    #[error("cannot encode message: {0}")]
    Wire(WireError),
}

/// An error reported by the underlying wire-format implementation.
///
/// Opaque on purpose: which implementation produced it is not part of the API.
pub struct WireError(Box<dyn std::error::Error + Send + Sync>);

impl WireError {
    pub(crate) fn new(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self(Box::new(err))
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WireError({})", self.0)
    }
}

/// The fixed 12-byte header, read without trusting anything after it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RawHeader {
    pub(crate) id: u16,
    pub(crate) is_response: bool,
    pub(crate) opcode: Opcode,
    pub(crate) recursion_desired: bool,
    pub(crate) question_count: u16,
    pub(crate) answer_count: u16,
    pub(crate) authority_count: u16,
    pub(crate) additional_count: u16,
}

/// Queries may carry an OPT record plus at most a TSIG or SIG(0) record.
const MAX_QUERY_ADDITIONALS: u16 = 2;

impl RawHeader {
    pub(crate) fn parse(wire: &[u8]) -> Option<Self> {
        let header: &[u8; HEADER_LEN] = wire.first_chunk()?;
        let (words, _) = header.as_chunks::<2>();
        let &[id, [flags, _], qd, an, ns, ar] = words else {
            return None;
        };
        Some(Self {
            id: u16::from_be_bytes(id),
            is_response: flags & 0x80 != 0,
            opcode: Opcode((flags >> 3) & 0x0f),
            recursion_desired: flags & 0x01 != 0,
            question_count: u16::from_be_bytes(qd),
            answer_count: u16::from_be_bytes(an),
            authority_count: u16::from_be_bytes(ns),
            additional_count: u16::from_be_bytes(ar),
        })
    }

    pub(crate) fn context(&self) -> ErrorContext {
        ErrorContext {
            id: self.id,
            opcode: self.opcode,
            recursion_desired: self.recursion_desired,
        }
    }

    /// Applies the header part of the decode policy described on [`DecodeError`].
    pub(crate) fn check_query(wire: &[u8]) -> Result<Self, DecodeError> {
        let header = Self::parse(wire).ok_or(DecodeError::TooShort { len: wire.len() })?;
        if header.is_response {
            return Err(DecodeError::NotAQuery);
        }
        if header.opcode != Opcode::QUERY {
            return Err(DecodeError::NotImplemented(header.context()));
        }
        if header.question_count != 1
            || header.answer_count != 0
            || header.authority_count != 0
            || header.additional_count > MAX_QUERY_ADDITIONALS
        {
            return Err(DecodeError::FormatError(header.context()));
        }
        Ok(header)
    }
}
