//! DNSSEC records and the checks on them (RFC 4033 to 4035, RFC 5155), in
//! goethite's own types over hickory-proto's DNSSEC support. Only the wire
//! details and the cryptography live here; what to trust is the resolver's
//! decision. Nothing here panics on data from the network.

use std::cmp::Ordering;

use hickory_proto::dnssec::rdata::{DNSKEY, DNSSECRData, DS, NSEC, NSEC3, RRSIG};
use hickory_proto::dnssec::{Algorithm, DigestType, Nsec3HashAlgorithm, TBS, Verifier};
use hickory_proto::rr::{DNSClass, RData};

use crate::{Name, Record, RecordType};

/// Whether signatures of `algorithm` are checked: RSA/SHA-256 (8), RSA/SHA-512
/// (10), ECDSA P-256 (13) and P-384 (14), and Ed25519 (15). The SHA-1 RSA
/// algorithms (5 and 7) are deprecated and count as unsupported, so a zone
/// signed only with them is treated as unsigned rather than trusted.
pub fn algorithm_supported(algorithm: u8) -> bool {
    matches!(algorithm, 8 | 10 | 13 | 14 | 15)
}

/// Whether DS digests of `digest_type` are checked: SHA-1 (1), SHA-256 (2)
/// and SHA-384 (4).
pub fn digest_supported(digest_type: u8) -> bool {
    matches!(digest_type, 1 | 2 | 4)
}

/// An RRSIG record's fields, without the signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rrsig {
    /// The type of the records it signs.
    pub type_covered: RecordType,
    /// The signature algorithm.
    pub algorithm: u8,
    /// Labels in the signed owner name, not counting a leading `*`: fewer
    /// than the owner's for an answer from a wildcard.
    pub labels: u8,
    /// The records' TTL when signed.
    pub original_ttl: u32,
    /// Valid until, in seconds since 1970, modulo 2^32.
    pub expiration: u32,
    /// Valid from, the same way.
    pub inception: u32,
    /// The key tag of the DNSKEY that signed.
    pub key_tag: u16,
    /// The zone that signed.
    pub signer: Name,
}

/// A DNSKEY record's fields, without the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dnskey {
    /// The flags: zone key, secure entry point, revoked.
    pub flags: u16,
    /// The algorithm.
    pub algorithm: u8,
    /// Its key tag (RFC 4034, appendix B).
    pub key_tag: u16,
}

impl Dnskey {
    /// A zone key (flag 7): one that may sign the zone's records.
    pub fn zone_key(self) -> bool {
        self.flags & 0x0100 != 0
    }

    /// Revoked (flag 8, RFC 5011): never to be used.
    pub fn revoked(self) -> bool {
        self.flags & 0x0080 != 0
    }
}

/// A DS record's fields, without the digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ds {
    /// The key tag of the DNSKEY it is a digest of.
    pub key_tag: u16,
    /// That key's algorithm.
    pub algorithm: u8,
    /// The digest type.
    pub digest_type: u8,
}

/// An NSEC record: the next name in the zone, and the types at its owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nsec {
    /// The next owner name in canonical order.
    pub next: Name,
    /// The types at the owner name.
    pub types: Vec<RecordType>,
}

/// An NSEC3 record (RFC 5155).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nsec3 {
    /// The hash algorithm: 1 is SHA-1, the only one defined.
    pub hash_algorithm: u8,
    /// Whether unsigned delegations may lie in the span it covers.
    pub opt_out: bool,
    /// Extra hash iterations.
    pub iterations: u16,
    /// The salt.
    pub salt: Vec<u8>,
    /// The next hashed owner name, as a raw hash.
    pub next_hashed: Vec<u8>,
    /// The types at the owner name.
    pub types: Vec<RecordType>,
}

fn dnssec(record: &Record) -> Option<&DNSSECRData> {
    match &record.data {
        RData::DNSSEC(data) => Some(data),
        _ => None,
    }
}

fn rrsig_data(record: &Record) -> Option<&RRSIG> {
    match dnssec(record)? {
        DNSSECRData::RRSIG(rrsig) => Some(rrsig),
        _ => None,
    }
}

fn dnskey_data(record: &Record) -> Option<&DNSKEY> {
    match dnssec(record)? {
        DNSSECRData::DNSKEY(dnskey) => Some(dnskey),
        _ => None,
    }
}

fn ds_data(record: &Record) -> Option<&DS> {
    match dnssec(record)? {
        DNSSECRData::DS(ds) => Some(ds),
        _ => None,
    }
}

fn types(set: impl Iterator<Item = hickory_proto::rr::RecordType>) -> Vec<RecordType> {
    set.map(|t| RecordType(t.into())).collect()
}

impl Record {
    /// A DS record, such as a trust anchor: the digest of the DNSKEY with
    /// `key_tag` and `algorithm` owned by `owner`.
    pub fn ds_record(
        owner: Name,
        ttl: u32,
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
    ) -> Self {
        let ds = DS::new(
            key_tag,
            Algorithm::from_u8(algorithm),
            DigestType::from(digest_type),
            digest,
        );
        Self::from_parts(
            owner,
            crate::RecordClass::IN,
            ttl,
            RData::DNSSEC(DNSSECRData::DS(ds)),
        )
    }

    /// An RRSIG record's fields.
    pub fn rrsig(&self) -> Option<Rrsig> {
        let input = rrsig_data(self)?.input();
        Some(Rrsig {
            type_covered: RecordType(input.type_covered.into()),
            algorithm: input.algorithm.into(),
            labels: input.num_labels,
            original_ttl: input.original_ttl,
            expiration: input.sig_expiration.get(),
            inception: input.sig_inception.get(),
            key_tag: input.key_tag,
            signer: Name(input.signer_name.clone()),
        })
    }

    /// A DNSKEY record's fields.
    pub fn dnskey(&self) -> Option<Dnskey> {
        let key = dnskey_data(self)?;
        Some(Dnskey {
            flags: key.flags(),
            algorithm: key.algorithm().into(),
            key_tag: key.calculate_key_tag().ok()?,
        })
    }

    /// A DS record's fields.
    pub fn ds(&self) -> Option<Ds> {
        let ds = ds_data(self)?;
        Some(Ds {
            key_tag: ds.key_tag(),
            algorithm: ds.algorithm().into(),
            digest_type: ds.digest_type().into(),
        })
    }

    /// An NSEC record.
    pub fn nsec(&self) -> Option<Nsec> {
        let nsec: &NSEC = match dnssec(self)? {
            DNSSECRData::NSEC(nsec) => nsec,
            _ => return None,
        };
        Some(Nsec {
            next: Name(nsec.next_domain_name().clone()),
            types: types(nsec.type_bit_maps()),
        })
    }

    /// An NSEC3 record.
    pub fn nsec3(&self) -> Option<Nsec3> {
        let nsec3: &NSEC3 = match dnssec(self)? {
            DNSSECRData::NSEC3(nsec3) => nsec3,
            _ => return None,
        };
        Some(Nsec3 {
            hash_algorithm: nsec3.hash_algorithm().into(),
            opt_out: nsec3.opt_out(),
            iterations: nsec3.iterations(),
            salt: nsec3.salt().to_vec(),
            next_hashed: nsec3.next_hashed_owner_name().to_vec(),
            types: types(nsec3.type_bit_maps()),
        })
    }

    /// The target of a DNAME record (RFC 6672).
    pub fn dname_target(&self) -> Option<Name> {
        // hickory-proto has no DNAME type: it arrives as unknown data, a
        // name in uncompressed wire format (RFC 6672 forbids compression).
        let RData::Unknown { code, rdata } = &self.data else {
            return None;
        };
        if u16::from(*code) != RecordType::DNAME.0 {
            return None;
        }
        let mut labels: Vec<&[u8]> = Vec::new();
        let mut rest = rdata.anything.as_slice();
        loop {
            let (&len, tail) = rest.split_first()?;
            if len == 0 {
                return tail
                    .is_empty()
                    .then(|| Name::from_labels(labels).ok())
                    .flatten();
            }
            if len > 63 {
                return None;
            }
            let (label, tail) = tail.split_at_checked(usize::from(len))?;
            labels.push(label);
            rest = tail;
        }
    }
}

impl Name {
    /// The canonical DNS name order of RFC 4034, section 6.1: label by
    /// label from the right, case-insensitively, as unsigned bytes.
    pub fn canonical_cmp(&self, other: &Name) -> Ordering {
        self.0.cmp(&other.0)
    }
}

/// Why a signature is not good.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DnssecError {
    /// Not an RRSIG, or not a DNSKEY.
    #[error("not an RRSIG and a DNSKEY")]
    WrongRecords,
    /// The records cannot be put into the signed form.
    #[error("cannot encode the signed data")]
    Encoding,
    /// The signature does not verify.
    #[error("the signature does not verify")]
    Signature,
}

/// Checks the signature in `rrsig` over `rrset` (the records it covers;
/// others are ignored) with the key in `dnskey`. Only the cryptography:
/// times, names, key tags and algorithms are the caller's to check.
///
/// # Errors
///
/// If they are not an RRSIG and a DNSKEY, or the signature is not good.
pub fn verify(rrset: &[Record], rrsig: &Record, dnskey: &Record) -> Result<(), DnssecError> {
    let sig = rrsig_data(rrsig).ok_or(DnssecError::WrongRecords)?;
    let key = dnskey_data(dnskey).ok_or(DnssecError::WrongRecords)?;
    let records: Vec<hickory_proto::rr::Record> = rrset
        .iter()
        .map(|record| {
            let mut converted = hickory_proto::rr::Record::from_rdata(
                record.name().0.clone(),
                record.ttl(),
                record.data.clone(),
            );
            converted.dns_class = DNSClass::from(record.class().0);
            converted
        })
        .collect();
    let tbs = TBS::from_input(&rrsig.name().0, DNSClass::IN, sig.input(), records.iter())
        .map_err(|_| DnssecError::Encoding)?;
    key.verify(tbs.as_ref(), sig.sig())
        .map_err(|_| DnssecError::Signature)
}

/// Whether `ds` is a digest of `dnskey`, a zone key owned by `zone`.
pub fn ds_matches(ds: &Record, dnskey: &Record, zone: &Name) -> bool {
    match (ds_data(ds), dnskey_data(dnskey)) {
        (Some(ds), Some(key)) => ds.covers(&zone.0, key).unwrap_or(false),
        _ => false,
    }
}

/// The NSEC3 hash (SHA-1, with `salt` and `iterations`) of `name`.
pub fn nsec3_hash(name: &Name, salt: &[u8], iterations: u16) -> Option<Vec<u8>> {
    Nsec3HashAlgorithm::SHA1
        .hash(salt, &name.0.to_lowercase(), iterations)
        .ok()
        .map(|digest| digest.as_ref().to_vec())
}

/// The hash in an NSEC3 owner name's first label: its base32hex
/// encoding (RFC 4648, section 7), without padding, either case.
pub fn nsec3_owner_hash(owner: &Name) -> Option<Vec<u8>> {
    base32hex(owner.labels().next()?)
}

fn base32hex(text: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len().saturating_mul(5) / 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &c in text {
        let value = match c {
            b'0'..=b'9' => c.wrapping_sub(b'0'),
            b'a'..=b'v' => c.wrapping_sub(b'a').wrapping_add(10),
            b'A'..=b'V' => c.wrapping_sub(b'A').wrapping_add(10),
            _ => return None,
        };
        buffer = (buffer << 5) | u32::from(value);
        bits = bits.saturating_add(5);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            out.push(u8::try_from((buffer >> bits) & 0xff).ok()?);
        }
    }
    // Leftover bits must be zero padding, fewer than a byte.
    (buffer.trailing_zeros() >= bits).then_some(out)
}

/// Making signed records, for tests elsewhere: Ed25519 keys and RRSIGs.
#[cfg(any(test, feature = "signing"))]
#[allow(
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test helpers"
)]
pub mod signing {
    use hickory_proto::dnssec::crypto::Ed25519SigningKey;
    use hickory_proto::dnssec::rdata::sig::SigInput;
    use hickory_proto::dnssec::rdata::{DNSKEY, DNSSECRData, DS, NSEC, NSEC3, RRSIG};
    use hickory_proto::dnssec::{
        Algorithm, DigestType, Nsec3HashAlgorithm, PublicKeyBuf, SigningKey, TBS,
    };
    use hickory_proto::rr::{DNSClass, RData, SerialNumber};

    use crate::{Name, Record, RecordClass, RecordType};

    /// A zone's Ed25519 key.
    pub struct Key {
        zone: Name,
        signing: Ed25519SigningKey,
        dnskey: DNSKEY,
    }

    // The signing key stays out of the output.
    impl std::fmt::Debug for Key {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Key")
                .field("zone", &self.zone)
                .finish_non_exhaustive()
        }
    }

    impl Key {
        /// A new key for `zone`, a zone key and a secure entry point.
        ///
        /// # Panics
        ///
        /// If the system cannot make one.
        pub fn generate(zone: &Name) -> Self {
            let pkcs8 = Ed25519SigningKey::generate_pkcs8().expect("key");
            let signing = Ed25519SigningKey::from_pkcs8(&pkcs8).expect("key");
            let public: PublicKeyBuf = signing.to_public_key().expect("public key");
            let dnskey = DNSKEY::with_flags(0x0101, public);
            Self {
                zone: zone.clone(),
                signing,
                dnskey,
            }
        }

        /// Its DNSKEY record.
        pub fn dnskey(&self, ttl: u32) -> Record {
            Record::from_parts(
                self.zone.clone(),
                RecordClass::IN,
                ttl,
                RData::DNSSEC(DNSSECRData::DNSKEY(self.dnskey.clone())),
            )
        }

        /// The DS record for it, SHA-256, owned by the zone.
        ///
        /// # Panics
        ///
        /// If the digest cannot be made.
        pub fn ds(&self, ttl: u32) -> Record {
            let digest = self
                .dnskey
                .to_digest(&self.zone.0, DigestType::SHA256)
                .expect("digest");
            let ds = DS::new(
                self.dnskey.calculate_key_tag().expect("key tag"),
                Algorithm::ED25519,
                DigestType::SHA256,
                digest.as_ref().to_vec(),
            );
            Record::from_parts(
                self.zone.clone(),
                RecordClass::IN,
                ttl,
                RData::DNSSEC(DNSSECRData::DS(ds)),
            )
        }

        /// An RRSIG over `rrset` (all one owner and type), valid from
        /// `inception` to `expiration`.
        ///
        /// # Panics
        ///
        /// If `rrset` is empty or cannot be signed.
        pub fn sign(&self, rrset: &[Record], inception: u32, expiration: u32) -> Record {
            let first = rrset.first().expect("records");
            let owner = first.name();
            let labels = owner.labels().filter(|label| *label != b"*").count();
            let input = SigInput {
                type_covered: hickory_proto::rr::RecordType::from(first.record_type().0),
                algorithm: Algorithm::ED25519,
                num_labels: u8::try_from(labels).expect("labels"),
                original_ttl: first.ttl(),
                sig_expiration: SerialNumber::new(expiration),
                sig_inception: SerialNumber::new(inception),
                key_tag: self.dnskey.calculate_key_tag().expect("key tag"),
                signer_name: self.zone.0.clone(),
            };
            let records: Vec<hickory_proto::rr::Record> = rrset
                .iter()
                .map(|record| {
                    hickory_proto::rr::Record::from_rdata(
                        record.name().0.clone(),
                        record.ttl(),
                        record.data.clone(),
                    )
                })
                .collect();
            let tbs = TBS::from_input(&owner.0, DNSClass::IN, &input, records.iter()).expect("TBS");
            let signature = self.signing.sign(&tbs).expect("signature");
            Record::from_parts(
                owner.clone(),
                RecordClass::IN,
                first.ttl(),
                RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, signature))),
            )
        }
    }

    /// An NSEC record at `owner` pointing at `next`, with `types`.
    pub fn nsec(owner: &Name, ttl: u32, next: &Name, types: &[RecordType]) -> Record {
        let types = types
            .iter()
            .map(|t| hickory_proto::rr::RecordType::from(t.0));
        Record::from_parts(
            owner.clone(),
            RecordClass::IN,
            ttl,
            RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(next.0.clone(), types))),
        )
    }

    /// An NSEC3 record for `name` in `zone` (SHA-1, no salt, no extra
    /// iterations), pointing at the hash `next`.
    ///
    /// # Panics
    ///
    /// If the hash cannot be made.
    pub fn nsec3(
        zone: &Name,
        name: &Name,
        ttl: u32,
        next: &[u8],
        opt_out: bool,
        types: &[RecordType],
    ) -> Record {
        let hash = Nsec3HashAlgorithm::SHA1
            .hash(&[], &name.0.to_lowercase(), 0)
            .expect("hash");
        let label = base32hex_encode(hash.as_ref());
        let owner = Name::from_labels(std::iter::once(label.as_bytes()).chain(zone.labels()))
            .expect("owner");
        let types = types
            .iter()
            .map(|t| hickory_proto::rr::RecordType::from(t.0));
        Record::from_parts(
            owner,
            RecordClass::IN,
            ttl,
            RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
                Nsec3HashAlgorithm::SHA1,
                opt_out,
                0,
                Vec::new(),
                next.to_vec(),
                types,
            ))),
        )
    }

    /// A DNAME record from `owner` to `target`, as hickory-proto keeps one:
    /// unknown data holding the target in wire format.
    pub fn dname(owner: &Name, ttl: u32, target: &Name) -> Record {
        let mut wire = Vec::new();
        for label in target.labels() {
            wire.push(u8::try_from(label.len()).expect("label"));
            wire.extend_from_slice(label);
        }
        wire.push(0);
        Record::from_parts(
            owner.clone(),
            RecordClass::IN,
            ttl,
            RData::Unknown {
                code: hickory_proto::rr::RecordType::DNAME,
                rdata: hickory_proto::rr::rdata::NULL::with(wire),
            },
        )
    }

    /// base32hex without padding, lowercase.
    pub fn base32hex_encode(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
        let mut out = String::new();
        let mut buffer: u32 = 0;
        let mut bits = 0;
        for &byte in bytes {
            buffer = (buffer << 8) | u32::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(char::from(DIGITS[((buffer >> bits) & 31) as usize]));
            }
        }
        if bits > 0 {
            out.push(char::from(DIGITS[((buffer << (5 - bits)) & 31) as usize]));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32hex_decodes() {
        // RFC 4648, section 10: "foobar" is CPNMUOJ1E8======.
        assert_eq!(base32hex(b"CPNMUOJ1E8").unwrap(), b"foobar");
        assert_eq!(base32hex(b"cpnmuoj1e8").unwrap(), b"foobar");
        assert_eq!(base32hex(b"CO").unwrap(), b"f");
        assert!(base32hex(b"CPNMUOJ1E9").is_none(), "non-zero padding bits");
        assert!(base32hex(b"WXYZ").is_none());
        assert_eq!(base32hex(b"").unwrap(), b"");
    }

    #[test]
    fn canonical_order() {
        // RFC 4034, section 6.1.
        let ordered: [&[&[u8]]; 9] = [
            &[b"example"],
            &[b"a", b"example"],
            &[b"yljkjljk", b"a", b"example"],
            &[b"Z", b"a", b"example"],
            &[b"zABC", b"a", b"EXAMPLE"],
            &[b"z", b"example"],
            &[b"\x01", b"z", b"example"],
            &[b"*", b"z", b"example"],
            &[b"\x80", b"z", b"example"],
        ];
        let names: Vec<Name> = ordered
            .iter()
            .map(|labels| Name::from_labels(labels.iter().copied()).unwrap())
            .collect();
        for pair in names.windows(2) {
            assert_eq!(
                pair[0].canonical_cmp(&pair[1]),
                Ordering::Less,
                "{} < {}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn nsec3_hashes_as_rfc_5155_says() {
        // RFC 5155, appendix A: salt aabbccdd, 12 iterations.
        let salt = [0xaa, 0xbb, 0xcc, 0xdd];
        for (name, hashed) in [
            ("example.", "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"),
            ("a.example.", "35mthgpgcu1qg68fab165klnsnk3dpvl"),
            ("ns1.example.", "2t7b4g4vsa5smi47k61mv5bv1a22bojr"),
        ] {
            let hash = nsec3_hash(&name.parse().unwrap(), &salt, 12).unwrap();
            assert_eq!(signing::base32hex_encode(&hash), hashed, "{name}");
            let owner: Name = format!("{hashed}.example.").parse().unwrap();
            assert_eq!(nsec3_owner_hash(&owner).unwrap(), hash);
        }
    }

    #[test]
    fn signatures_verify_and_tampering_shows() {
        let zone: Name = "example.".parse().unwrap();
        let key = signing::Key::generate(&zone);
        let dnskey = key.dnskey(3600);
        let owner: Name = "www.example.".parse().unwrap();
        let rrset = vec![
            Record::a(owner.clone(), 300, std::net::Ipv4Addr::new(192, 0, 2, 1)),
            Record::a(owner.clone(), 300, std::net::Ipv4Addr::new(192, 0, 2, 2)),
        ];
        let rrsig = key.sign(&rrset, 1_000, 2_000_000_000);
        let fields = rrsig.rrsig().unwrap();
        assert_eq!(fields.type_covered, RecordType::A);
        assert_eq!(
            (fields.labels, fields.algorithm, fields.signer.clone()),
            (2, 15, zone.clone())
        );
        assert_eq!(fields.key_tag, dnskey.dnskey().unwrap().key_tag);
        assert!(dnskey.dnskey().unwrap().zone_key() && !dnskey.dnskey().unwrap().revoked());
        assert_eq!(verify(&rrset, &rrsig, &dnskey), Ok(()));
        // In any order, in any case, with any TTL left.
        let mut shuffled: Vec<Record> = rrset.iter().rev().cloned().collect();
        shuffled[0].set_name("WWW.Example.".parse().unwrap());
        shuffled[1].set_ttl(17);
        assert_eq!(verify(&shuffled, &rrsig, &dnskey), Ok(()));
        let forged = vec![Record::a(
            owner.clone(),
            300,
            std::net::Ipv4Addr::new(6, 6, 6, 6),
        )];
        assert_eq!(
            verify(&forged, &rrsig, &dnskey),
            Err(DnssecError::Signature)
        );
        let other = signing::Key::generate(&zone).dnskey(3600);
        assert_eq!(verify(&rrset, &rrsig, &other), Err(DnssecError::Signature));
        assert_eq!(
            verify(&rrset, &rrset[0], &dnskey),
            Err(DnssecError::WrongRecords)
        );
        // The DS is a digest of this key, at this name only.
        let ds = key.ds(86_400);
        assert!(ds_matches(&ds, &dnskey, &zone));
        assert!(!ds_matches(&ds, &other, &zone));
        assert!(!ds_matches(&ds, &dnskey, &"other.".parse().unwrap()));
        assert_eq!(ds.ds().unwrap().digest_type, 2);
    }

    #[test]
    fn denial_records_round_trip_through_the_wire() {
        use crate::{
            DnsCodec, Edns, HickoryCodec, Query, Question, RecordClass, Response, ResponseCode,
        };
        let zone: Name = "example.".parse().unwrap();
        let nsec = signing::nsec(
            &"a.example.".parse().unwrap(),
            300,
            &"c.example.".parse().unwrap(),
            &[RecordType::A, RecordType::NSEC, RecordType::RRSIG],
        );
        let nsec3 = signing::nsec3(
            &zone,
            &"b.example.".parse().unwrap(),
            300,
            &[1; 20],
            true,
            &[RecordType::TXT],
        );
        let query = Query {
            id: 1,
            recursion_desired: false,
            checking_disabled: false,
            authentic_data: false,
            question: Question {
                name: "b.example.".parse().unwrap(),
                qtype: RecordType::A,
                qclass: RecordClass::IN,
            },
            edns: Some(Edns::ours()),
        };
        let mut response = Response::for_query(&query, ResponseCode::NX_DOMAIN);
        response.authority = vec![nsec, nsec3];
        let mut wire = Vec::new();
        HickoryCodec
            .encode_response(&response, 4096, &mut wire)
            .unwrap();
        let decoded = HickoryCodec.decode_response(&wire).unwrap();
        let nsec = decoded.authority[0].nsec().unwrap();
        assert_eq!(nsec.next, "c.example.".parse().unwrap());
        assert!(nsec.types.contains(&RecordType::A) && !nsec.types.contains(&RecordType::TXT));
        let nsec3 = decoded.authority[1].nsec3().unwrap();
        assert!(nsec3.opt_out);
        assert_eq!(
            (
                nsec3.hash_algorithm,
                nsec3.iterations,
                nsec3.next_hashed.as_slice()
            ),
            (1, 0, &[1_u8; 20][..])
        );
        assert_eq!(nsec3.types, [RecordType::TXT]);
        let owner_hash = nsec3_owner_hash(decoded.authority[1].name()).unwrap();
        assert_eq!(
            owner_hash,
            nsec3_hash(&"b.example.".parse().unwrap(), &[], 0).unwrap()
        );
    }

    #[test]
    fn supported_algorithms() {
        for supported in [8, 10, 13, 14, 15] {
            assert!(algorithm_supported(supported));
        }
        for unsupported in [1, 3, 5, 6, 7, 12, 16, 253] {
            assert!(!algorithm_supported(unsupported));
        }
        assert!(digest_supported(2) && digest_supported(4) && digest_supported(1));
        assert!(!digest_supported(3));
    }
}
