//! DNS wire format for goethite.
//!
//! goethite's own small message vocabulary — [`Name`], [`Query`],
//! [`Response`], [`Record`] and the numeric code types — plus the
//! [`DnsCodec`] trait that converts it to and from wire format. The default
//! codec, [`HickoryCodec`], is built on hickory-proto, but no hickory-proto
//! type appears in this crate's public API, so the implementation can be
//! replaced without touching the rest of goethite (see
//! `docs/adr/0001-hickory-proto-behind-trait.md`).
//!
//! Decoding never panics, whatever the input, and rejects anything that is
//! not a well-formed standard query before parsing it in full. See
//! [`DecodeError`] for the exact policy.

#![forbid(unsafe_code)]

mod codec;
pub mod dnssec;
mod hickory_codec;
mod message;
mod name;
mod types;

pub use codec::{DecodeError, DnsCodec, EncodeError, ErrorContext, ResponseError, WireError};
pub use hickory_codec::HickoryCodec;
pub use message::{
    Edns, HEADER_LEN, MAX_UDP_PAYLOAD, MIN_UDP_PAYLOAD, QUERY_PADDING_BLOCK, Query, Question,
    RESPONSE_PADDING_BLOCK, Record, Response,
};
pub use name::{Name, NameError};
pub use types::{Opcode, RecordClass, RecordType, ResponseCode};
