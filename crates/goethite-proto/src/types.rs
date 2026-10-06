//! Small numeric DNS code types.
//!
//! Each type is a transparent newtype over its wire value, so every value
//! round-trips (including ones goethite has never heard of) and conversion is
//! free. Well-known values are associated constants.

use std::fmt;

/// Writes `known` if present, otherwise the RFC 3597 style `{prefix}{value}`.
fn fmt_code(
    f: &mut fmt::Formatter<'_>,
    known: Option<&str>,
    prefix: &str,
    value: impl fmt::Display,
) -> fmt::Result {
    match known {
        Some(mnemonic) => f.write_str(mnemonic),
        None => write!(f, "{prefix}{value}"),
    }
}

/// A resource record type (`QTYPE` / `TYPE`), e.g. `A` or `AAAA`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecordType(pub u16);

impl RecordType {
    /// IPv4 host address.
    pub const A: Self = Self(1);
    /// Authoritative name server.
    pub const NS: Self = Self(2);
    /// Canonical name (alias).
    pub const CNAME: Self = Self(5);
    /// Start of a zone of authority.
    pub const SOA: Self = Self(6);
    /// Domain name pointer (reverse lookups).
    pub const PTR: Self = Self(12);
    /// Mail exchange.
    pub const MX: Self = Self(15);
    /// Text strings.
    pub const TXT: Self = Self(16);
    /// IPv6 host address.
    pub const AAAA: Self = Self(28);
    /// Service locator.
    pub const SRV: Self = Self(33);
    /// EDNS(0) pseudo-record.
    pub const OPT: Self = Self(41);
    /// Delegation signer.
    pub const DS: Self = Self(43);
    /// DNSSEC signature.
    pub const RRSIG: Self = Self(46);
    /// DNSSEC public key.
    pub const DNSKEY: Self = Self(48);
    /// General-purpose service binding.
    pub const SVCB: Self = Self(64);
    /// HTTPS service binding.
    pub const HTTPS: Self = Self(65);
    /// Any type (query-only meta type).
    pub const ANY: Self = Self(255);

    fn mnemonic(self) -> Option<&'static str> {
        Some(match self {
            Self::A => "A",
            Self::NS => "NS",
            Self::CNAME => "CNAME",
            Self::SOA => "SOA",
            Self::PTR => "PTR",
            Self::MX => "MX",
            Self::TXT => "TXT",
            Self::AAAA => "AAAA",
            Self::SRV => "SRV",
            Self::OPT => "OPT",
            Self::DS => "DS",
            Self::RRSIG => "RRSIG",
            Self::DNSKEY => "DNSKEY",
            Self::SVCB => "SVCB",
            Self::HTTPS => "HTTPS",
            Self::ANY => "ANY",
            _ => return None,
        })
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_code(f, self.mnemonic(), "TYPE", self.0)
    }
}

/// A resource record class (`QCLASS` / `CLASS`). In practice always `IN`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecordClass(pub u16);

impl RecordClass {
    /// The Internet.
    pub const IN: Self = Self(1);
    /// Chaos (used for server identification queries such as `version.bind`).
    pub const CH: Self = Self(3);
    /// Hesiod.
    pub const HS: Self = Self(4);
    /// No class (dynamic update only).
    pub const NONE: Self = Self(254);
    /// Any class (query-only).
    pub const ANY: Self = Self(255);

    fn mnemonic(self) -> Option<&'static str> {
        Some(match self {
            Self::IN => "IN",
            Self::CH => "CH",
            Self::HS => "HS",
            Self::NONE => "NONE",
            Self::ANY => "ANY",
            _ => return None,
        })
    }
}

impl fmt::Display for RecordClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_code(f, self.mnemonic(), "CLASS", self.0)
    }
}

/// A message opcode (4 bits on the wire).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Opcode(pub u8);

impl Opcode {
    /// A standard query, the only opcode goethite answers.
    pub const QUERY: Self = Self(0);
    /// Zone change notification.
    pub const NOTIFY: Self = Self(4);
    /// Dynamic update.
    pub const UPDATE: Self = Self(5);
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let known = match *self {
            Self::QUERY => Some("QUERY"),
            Self::NOTIFY => Some("NOTIFY"),
            Self::UPDATE => Some("UPDATE"),
            _ => None,
        };
        fmt_code(f, known, "OPCODE", self.0)
    }
}

/// A response code, including the EDNS extended range (12 bits in total).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResponseCode(pub u16);

impl ResponseCode {
    /// No error.
    pub const NO_ERROR: Self = Self(0);
    /// The server could not interpret the query.
    pub const FORM_ERR: Self = Self(1);
    /// The server failed to process the query.
    pub const SERV_FAIL: Self = Self(2);
    /// The name does not exist.
    pub const NX_DOMAIN: Self = Self(3);
    /// The server does not support this kind of query.
    pub const NOT_IMP: Self = Self(4);
    /// The server refuses to answer for policy reasons.
    pub const REFUSED: Self = Self(5);
    /// The query's EDNS version is not supported (requires EDNS to convey).
    pub const BAD_VERS: Self = Self(16);

    fn mnemonic(self) -> Option<&'static str> {
        Some(match self {
            Self::NO_ERROR => "NOERROR",
            Self::FORM_ERR => "FORMERR",
            Self::SERV_FAIL => "SERVFAIL",
            Self::NX_DOMAIN => "NXDOMAIN",
            Self::NOT_IMP => "NOTIMP",
            Self::REFUSED => "REFUSED",
            Self::BAD_VERS => "BADVERS",
            _ => return None,
        })
    }
}

impl fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_code(f, self.mnemonic(), "RCODE", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_codes_use_mnemonics() {
        assert_eq!(RecordType::AAAA.to_string(), "AAAA");
        assert_eq!(RecordClass::IN.to_string(), "IN");
        assert_eq!(Opcode::QUERY.to_string(), "QUERY");
        assert_eq!(ResponseCode::REFUSED.to_string(), "REFUSED");
    }

    #[test]
    fn unknown_codes_use_rfc3597_style() {
        assert_eq!(RecordType(65_280).to_string(), "TYPE65280");
        assert_eq!(RecordClass(42).to_string(), "CLASS42");
        assert_eq!(Opcode(9).to_string(), "OPCODE9");
        assert_eq!(ResponseCode(23).to_string(), "RCODE23");
    }
}
