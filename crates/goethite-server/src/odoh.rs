//! Oblivious DNS over HTTPS (RFC 9230), as the target: reading the
//! messages a proxy forwards, decrypting queries and encrypting answers,
//! and the keys they are encrypted to. No I/O; every function here takes
//! data straight from the network and never panics.
//!
//! The keys use the cipher suite every ODoH implementation supports:
//! DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-128-GCM. They live in
//! memory only, are rotated every [`ROTATION`], and the previous key is
//! accepted for one more period, so a client with a cached configuration
//! keeps working. A query for any other key gets a 401, which tells the
//! client to fetch the configuration again (section 4.3).
//!
//! [`client`] is the other side, for tests and tools.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use hpke::aead::AesGcm128;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as _, OpModeR, Serializable};
use ring::rand::{SecureRandom, SystemRandom};
use ring::{aead, hkdf};

/// The media type of ODoH messages.
pub const MEDIA_TYPE: &str = "application/oblivious-dns-message";

/// Where the target's configurations (its public keys) are served.
pub const CONFIGS_PATH: &str = "/.well-known/odohconfigs";

/// How often the keys change; the previous key is accepted for as long
/// again. RFC 9230 recommends a day.
pub const ROTATION: Duration = Duration::from_hours(24);

/// The ODoH version this module speaks.
const VERSION: u16 = 0x0001;
/// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-128-GCM (RFC 9180).
const KEM_ID: u16 = 0x0020;
const KDF_ID: u16 = 0x0001;
const AEAD_ID: u16 = 0x0001;

/// Message types.
const QUERY: u8 = 0x01;
const RESPONSE: u8 = 0x02;

/// The HPKE `info` for queries.
const QUERY_INFO: &[u8] = b"odoh query";

/// A key ID's length: HKDF-SHA256's output, Nh.
const KEY_ID_LEN: usize = 32;
/// An X25519 public or encapsulated key's length.
const KEY_LEN: usize = 32;
/// AES-128-GCM's key (Nk), nonce (Nn) and tag lengths.
const NK: usize = 16;
const NN: usize = 12;
const TAG_LEN: usize = 16;
/// A response nonce's length: max(Nn, Nk).
const RESPONSE_NONCE_LEN: usize = 16;

/// The largest query message the target reads: one for a key it has.
pub const MAX_MESSAGE_LEN: usize = 1 + 2 + KEY_ID_LEN + 2 + u16::MAX as usize;

/// The largest DNS response that fits in a response message: its
/// encrypted part is at most 65,535 bytes, tag and length fields included.
pub const MAX_RESPONSE_LEN: usize = u16::MAX as usize - TAG_LEN - 4;

/// Responses are padded to a multiple of this many bytes, the block size
/// RFC 8467 recommends for responses, so their length says less.
const RESPONSE_BLOCK: usize = 468;

/// Why a message cannot be handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OdohError {
    /// It is not an ODoH message, or its lengths do not add up.
    #[error("not an Oblivious DoH message")]
    Malformed,
    /// A response where a query belongs, or the other way round.
    #[error("wrong message type")]
    WrongType,
    /// It is for a key this target does not have (any more): HTTP 401.
    #[error("unknown key")]
    UnknownKey,
    /// It does not decrypt.
    #[error("cannot decrypt")]
    Decrypt,
    /// The padding is not all zeros.
    #[error("padding is not zeros")]
    Padding,
    /// No configuration with a suite this module supports.
    #[error("no usable configuration")]
    NoConfig,
    /// The system's random number generator failed.
    #[error("no random numbers")]
    Random,
    /// The answer cannot be encrypted.
    #[error("cannot encrypt")]
    Encrypt,
}

/// An ODoH message, as read from the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message<'a> {
    /// `QUERY` (1) or `RESPONSE` (2).
    pub message_type: u8,
    /// The key's ID for a query, the response nonce for a response.
    pub key_id: &'a [u8],
    /// The encrypted message.
    pub encrypted: &'a [u8],
}

/// Reads a `u16`-length-prefixed field from the front of `wire`.
fn field(wire: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = wire.split_first_chunk::<2>()?;
    rest.split_at_checked(usize::from(u16::from_be_bytes(*len)))
}

/// Reads an ODoH message: a type, a key ID and an encrypted message,
/// filling `wire` exactly.
///
/// # Errors
///
/// [`OdohError::Malformed`] if the lengths do not add up, the encrypted
/// message is empty or bytes are left over.
pub fn parse_message(wire: &[u8]) -> Result<Message<'_>, OdohError> {
    let (&message_type, rest) = wire.split_first().ok_or(OdohError::Malformed)?;
    let (key_id, rest) = field(rest).ok_or(OdohError::Malformed)?;
    let (encrypted, rest) = field(rest).ok_or(OdohError::Malformed)?;
    if encrypted.is_empty() || !rest.is_empty() {
        return Err(OdohError::Malformed);
    }
    Ok(Message {
        message_type,
        key_id,
        encrypted,
    })
}

/// Reads a decrypted message: a DNS message and padding, filling `plain`
/// exactly. Returns the DNS message.
///
/// # Errors
///
/// [`OdohError::Malformed`] if the lengths do not add up or the DNS
/// message is empty, [`OdohError::Padding`] if the padding is not zeros.
pub fn parse_plaintext(plain: &[u8]) -> Result<&[u8], OdohError> {
    let (dns, rest) = field(plain).ok_or(OdohError::Malformed)?;
    let (padding, rest) = field(rest).ok_or(OdohError::Malformed)?;
    if dns.is_empty() || !rest.is_empty() {
        return Err(OdohError::Malformed);
    }
    if padding.iter().any(|&byte| byte != 0) {
        return Err(OdohError::Padding);
    }
    Ok(dns)
}

/// `bytes`' length as a `u16` length prefix.
fn len16(bytes: &[u8]) -> Result<[u8; 2], OdohError> {
    u16::try_from(bytes.len())
        .map(u16::to_be_bytes)
        .map_err(|_| OdohError::Encrypt)
}

/// An HKDF output length, for ring.
struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF-Expand of `prk` with `info`, filling `out`.
fn expand(prk: &hkdf::Prk, info: &[u8], out: &mut [u8]) -> Result<(), OdohError> {
    let info = [info];
    prk.expand(&info, Len(out.len()))
        .and_then(|okm| okm.fill(out))
        .map_err(|_| OdohError::Encrypt)
}

/// A configuration's key ID: Expand(Extract("", contents), "odoh key id").
fn key_id(contents: &[u8]) -> Result<[u8; KEY_ID_LEN], OdohError> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(contents);
    let mut id = [0; KEY_ID_LEN];
    expand(&prk, b"odoh key id", &mut id)?;
    Ok(id)
}

/// The additional data of a message: its type and length-prefixed key ID
/// or nonce.
fn aad(message_type: u8, key_id: &[u8]) -> Result<Vec<u8>, OdohError> {
    let mut aad = Vec::with_capacity(key_id.len().saturating_add(3));
    aad.push(message_type);
    aad.extend_from_slice(&len16(key_id)?);
    aad.extend_from_slice(key_id);
    Ok(aad)
}

/// The AES-128-GCM key and nonce of a response:
/// `derive_secrets(context, Q_plain, resp_nonce)` of section 6.2.
fn response_key(
    secret: &[u8; NK],
    query: &[u8],
    nonce: &[u8; RESPONSE_NONCE_LEN],
) -> Result<(aead::LessSafeKey, aead::Nonce), OdohError> {
    let mut salt = Vec::with_capacity(query.len().saturating_add(2 + RESPONSE_NONCE_LEN));
    salt.extend_from_slice(query);
    salt.extend_from_slice(&len16(nonce)?);
    salt.extend_from_slice(nonce);
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt).extract(secret);
    let mut key = [0; NK];
    let mut aead_nonce = [0; NN];
    expand(&prk, b"odoh key", &mut key)?;
    expand(&prk, b"odoh nonce", &mut aead_nonce)?;
    let key = aead::UnboundKey::new(&aead::AES_128_GCM, &key).map_err(|_| OdohError::Encrypt)?;
    Ok((
        aead::LessSafeKey::new(key),
        aead::Nonce::assume_unique_for_key(aead_nonce),
    ))
}

/// A DNS message and padding, length-prefixed: an
/// `ObliviousDoHMessagePlaintext`.
fn plaintext(dns: &[u8], padding: usize) -> Result<Vec<u8>, OdohError> {
    let pad = vec![0; padding];
    let mut plain = Vec::with_capacity(dns.len().saturating_add(padding).saturating_add(4));
    plain.extend_from_slice(&len16(dns)?);
    plain.extend_from_slice(dns);
    plain.extend_from_slice(&len16(&pad)?);
    plain.extend_from_slice(&pad);
    Ok(plain)
}

/// An ODoH message of `message_type` with `key_id` and `encrypted`.
fn message(message_type: u8, key_id: &[u8], encrypted: &[u8]) -> Result<Vec<u8>, OdohError> {
    let mut wire = aad(message_type, key_id)?;
    wire.extend_from_slice(&len16(encrypted)?);
    wire.extend_from_slice(encrypted);
    Ok(wire)
}

/// One key pair, with its configuration.
struct Key {
    id: [u8; KEY_ID_LEN],
    private: <X25519HkdfSha256 as hpke::Kem>::PrivateKey,
    /// Its `ObliviousDoHConfigContents`.
    contents: Vec<u8>,
}

impl Key {
    /// A new key pair, from the system's random number generator.
    fn generate(random: &SystemRandom) -> Result<Self, OdohError> {
        let mut ikm = [0; KEY_LEN];
        random.fill(&mut ikm).map_err(|_| OdohError::Random)?;
        let key = Self::derive(&ikm);
        ikm.fill(0);
        key
    }

    /// The key pair HPKE's `DeriveKeyPair` makes of `ikm`.
    fn derive(ikm: &[u8]) -> Result<Self, OdohError> {
        let (private, public) = X25519HkdfSha256::derive_keypair(ikm);
        let public = public.to_bytes();
        let mut contents = Vec::with_capacity(8_usize.saturating_add(public.len()));
        for id in [KEM_ID, KDF_ID, AEAD_ID] {
            contents.extend_from_slice(&id.to_be_bytes());
        }
        contents.extend_from_slice(&len16(&public)?);
        contents.extend_from_slice(&public);
        Ok(Self {
            id: key_id(&contents)?,
            private,
            contents,
        })
    }
}

/// The keys in use: the current one first.
struct Keys {
    keys: Vec<Key>,
    /// The current key's `ObliviousDoHConfigs`.
    configs: Arc<[u8]>,
}

impl Keys {
    fn new(keys: Vec<Key>) -> Result<Self, OdohError> {
        let current = keys.first().ok_or(OdohError::NoConfig)?;
        let mut config = VERSION.to_be_bytes().to_vec();
        config.extend_from_slice(&len16(&current.contents)?);
        config.extend_from_slice(&current.contents);
        let mut configs = len16(&config)?.to_vec();
        configs.extend_from_slice(&config);
        Ok(Self {
            keys,
            configs: configs.into(),
        })
    }
}

/// The target's keys, swapped atomically when they rotate.
pub struct OdohKeys {
    random: SystemRandom,
    keys: ArcSwap<Keys>,
}

impl std::fmt::Debug for OdohKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OdohKeys").finish_non_exhaustive()
    }
}

impl OdohKeys {
    /// A first key.
    ///
    /// # Errors
    ///
    /// [`OdohError::Random`] if the system's random number generator fails.
    pub fn new() -> Result<Self, OdohError> {
        let random = SystemRandom::new();
        let keys = Keys::new(vec![Key::generate(&random)?])?;
        Ok(Self {
            random,
            keys: ArcSwap::from_pointee(keys),
        })
    }

    /// Makes a new key the current one; the current one is still accepted
    /// until the next rotation, older ones no more.
    ///
    /// # Errors
    ///
    /// [`OdohError::Random`] if the system's random number generator fails;
    /// the keys stay as they are.
    pub fn rotate(&self) -> Result<(), OdohError> {
        let new = Key::generate(&self.random)?;
        let old = self.keys.load();
        let mut keys = vec![new];
        if let Some(current) = old.keys.first() {
            keys.push(Key {
                id: current.id,
                private: current.private.clone(),
                contents: current.contents.clone(),
            });
        }
        self.keys.store(Arc::new(Keys::new(keys)?));
        Ok(())
    }

    /// The `ObliviousDoHConfigs` clients encrypt to: the current key.
    pub fn configs(&self) -> Arc<[u8]> {
        Arc::clone(&self.keys.load().configs)
    }

    /// Decrypts the query in `wire`.
    ///
    /// # Errors
    ///
    /// [`OdohError::UnknownKey`] for a key this target does not have, which
    /// is an HTTP 401; any other error is a 400.
    pub fn open(&self, wire: &[u8]) -> Result<Opened, OdohError> {
        let message = parse_message(wire)?;
        if message.message_type != QUERY {
            return Err(OdohError::WrongType);
        }
        let keys = self.keys.load();
        let key = keys
            .keys
            .iter()
            .find(|key| key.id.as_slice() == message.key_id)
            .ok_or(OdohError::UnknownKey)?;
        let (enc, ciphertext) = message
            .encrypted
            .split_at_checked(KEY_LEN)
            .ok_or(OdohError::Decrypt)?;
        let enc = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(enc)
            .map_err(|_| OdohError::Decrypt)?;
        let mut context = hpke::setup_receiver::<AesGcm128, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &key.private,
            &enc,
            QUERY_INFO,
        )
        .map_err(|_| OdohError::Decrypt)?;
        let plain = context
            .open(ciphertext, &aad(QUERY, message.key_id)?)
            .map_err(|_| OdohError::Decrypt)?;
        let dns_len = parse_plaintext(&plain)?.len();
        let mut secret = [0; NK];
        context
            .export(b"odoh response", &mut secret)
            .map_err(|_| OdohError::Decrypt)?;
        Ok(Opened {
            plain,
            dns_len,
            secret,
        })
    }

    /// Encrypts `dns`, the answer to `query`, padded to a multiple of 468
    /// bytes as far as it fits.
    ///
    /// # Errors
    ///
    /// [`OdohError::Encrypt`] if `dns` is longer than [`MAX_RESPONSE_LEN`],
    /// [`OdohError::Random`] if the system's random number generator fails.
    pub fn seal(&self, query: &Opened, dns: &[u8]) -> Result<Vec<u8>, OdohError> {
        let room = MAX_RESPONSE_LEN
            .checked_sub(dns.len())
            .ok_or(OdohError::Encrypt)?;
        let padding = dns
            .len()
            .div_ceil(RESPONSE_BLOCK)
            .checked_mul(RESPONSE_BLOCK)
            .and_then(|block| block.checked_sub(dns.len()))
            .unwrap_or(0)
            .min(room);
        let mut nonce = [0; RESPONSE_NONCE_LEN];
        self.random
            .fill(&mut nonce)
            .map_err(|_| OdohError::Random)?;
        seal_with(query, dns, padding, &nonce)
    }
}

/// Encrypts `dns` with `padding`, the answer to `query`, under `nonce`.
fn seal_with(
    query: &Opened,
    dns: &[u8],
    padding: usize,
    nonce: &[u8; RESPONSE_NONCE_LEN],
) -> Result<Vec<u8>, OdohError> {
    let (key, aead_nonce) = response_key(&query.secret, &query.plain, nonce)?;
    let mut sealed = plaintext(dns, padding)?;
    key.seal_in_place_append_tag(
        aead_nonce,
        aead::Aad::from(aad(RESPONSE, nonce)?),
        &mut sealed,
    )
    .map_err(|_| OdohError::Encrypt)?;
    message(RESPONSE, nonce, &sealed)
}

/// A decrypted query, kept to encrypt its answer.
pub struct Opened {
    /// The `ObliviousDoHMessagePlaintext`.
    plain: Vec<u8>,
    dns_len: usize,
    /// The secret exported from the query's HPKE context.
    secret: [u8; NK],
}

impl Opened {
    /// The DNS query.
    pub fn dns(&self) -> &[u8] {
        self.plain
            .get(2..self.dns_len.saturating_add(2))
            .unwrap_or_default()
    }
}

/// The client's side: encrypting queries to a target and decrypting its
/// answers, for tests and tools. It uses the thread's random number
/// generator.
pub mod client {
    use hpke::OpModeS;

    use super::{
        AEAD_ID, AesGcm128, Deserializable, HkdfSha256, KDF_ID, KEM_ID, KEY_LEN, NK, OdohError,
        QUERY, QUERY_INFO, RESPONSE, RESPONSE_NONCE_LEN, VERSION, X25519HkdfSha256, aad, field,
        key_id, message, parse_message, parse_plaintext, plaintext, response_key,
    };

    /// A target's key, from its configurations.
    #[derive(Clone, Debug)]
    pub struct Config {
        key_id: [u8; 32],
        public: Vec<u8>,
    }

    impl Config {
        /// The public key.
        pub fn public_key(&self) -> &[u8] {
            &self.public
        }

        /// The key's ID, which queries to it carry.
        pub fn key_id(&self) -> &[u8] {
            &self.key_id
        }
    }

    /// The first configuration in `configs` (an `ObliviousDoHConfigs`) with
    /// version 1 and the X25519, HKDF-SHA256, AES-128-GCM suite.
    ///
    /// # Errors
    ///
    /// [`OdohError::Malformed`] if the lengths do not add up,
    /// [`OdohError::NoConfig`] if none is usable.
    pub fn parse_configs(configs: &[u8]) -> Result<Config, OdohError> {
        let (mut list, rest) = field(configs).ok_or(OdohError::Malformed)?;
        if list.is_empty() || !rest.is_empty() {
            return Err(OdohError::Malformed);
        }
        let mut found = None;
        while let Some((version, rest)) = list.split_first_chunk::<2>() {
            let (contents, rest) = field(rest).ok_or(OdohError::Malformed)?;
            list = rest;
            if found.is_some() || u16::from_be_bytes(*version) != VERSION {
                continue;
            }
            let Some((suite, key)) = contents.split_first_chunk::<6>() else {
                continue;
            };
            let Some((public, rest)) = field(key) else {
                continue;
            };
            let ours = [KEM_ID, KDF_ID, AEAD_ID]
                .iter()
                .flat_map(|id| id.to_be_bytes())
                .eq(suite.iter().copied());
            if ours && public.len() == KEY_LEN && rest.is_empty() {
                found = Some(Config {
                    key_id: key_id(contents)?,
                    public: public.to_vec(),
                });
            }
        }
        if !list.is_empty() {
            return Err(OdohError::Malformed);
        }
        found.ok_or(OdohError::NoConfig)
    }

    /// What a client keeps to read the answer to its query.
    pub struct Pending {
        plain: Vec<u8>,
        secret: [u8; NK],
    }

    /// Encrypts `dns`, with `padding` zero bytes, to `config`.
    ///
    /// # Errors
    ///
    /// [`OdohError::Malformed`] if `dns` is empty, [`OdohError::Encrypt`]
    /// if it is too long or the key is invalid.
    pub fn seal_query(
        config: &Config,
        dns: &[u8],
        padding: usize,
    ) -> Result<(Vec<u8>, Pending), OdohError> {
        if dns.is_empty() {
            return Err(OdohError::Malformed);
        }
        let public = <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(&config.public)
            .map_err(|_| OdohError::Encrypt)?;
        let (enc, mut context) = hpke::setup_sender_with_rng::<
            AesGcm128,
            HkdfSha256,
            X25519HkdfSha256,
        >(&OpModeS::Base, &public, QUERY_INFO, &mut rand::rng())
        .map_err(|_| OdohError::Encrypt)?;
        let plain = plaintext(dns, padding)?;
        let sealed = context
            .seal(&plain, &aad(QUERY, &config.key_id)?)
            .map_err(|_| OdohError::Encrypt)?;
        let mut encrypted = hpke::Serializable::to_bytes(&enc).to_vec();
        encrypted.extend_from_slice(&sealed);
        let mut secret = [0; NK];
        context
            .export(b"odoh response", &mut secret)
            .map_err(|_| OdohError::Encrypt)?;
        Ok((
            message(QUERY, &config.key_id, &encrypted)?,
            Pending { plain, secret },
        ))
    }

    impl Pending {
        /// The DNS answer in `wire`, the target's response.
        ///
        /// # Errors
        ///
        /// If it is not a response, does not decrypt or is malformed.
        pub fn open(&self, wire: &[u8]) -> Result<Vec<u8>, OdohError> {
            let message = parse_message(wire)?;
            if message.message_type != RESPONSE {
                return Err(OdohError::WrongType);
            }
            let nonce: &[u8; RESPONSE_NONCE_LEN] = message
                .key_id
                .try_into()
                .map_err(|_| OdohError::Malformed)?;
            let (key, aead_nonce) = response_key(&self.secret, &self.plain, nonce)?;
            let mut buffer = message.encrypted.to_vec();
            let plain = key
                .open_in_place(
                    aead_nonce,
                    ring::aead::Aad::from(aad(RESPONSE, nonce)?),
                    &mut buffer,
                )
                .map_err(|_| OdohError::Decrypt)?;
            Ok(parse_plaintext(plain)?.to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::client::{parse_configs, seal_query};
    use super::*;

    fn query() -> Vec<u8> {
        // ID 0x1234, RD, one question: example.com. A IN.
        let mut wire = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        wire.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        wire
    }

    /// A transaction of Cloudflare's ODoH test vectors (odoh-go 1.0.0,
    /// test-vectors.json; MIT, copyright 2019-2020 Cloudflare, Inc. and
    /// Apple, Inc.), from an implementation with its own HPKE (circl).
    struct Vector {
        query: &'static str,
        response: &'static str,
        response_padding: usize,
        oblivious_query: &'static str,
        oblivious_response: &'static str,
    }

    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text
            .chars()
            .filter_map(|digit| digit.to_digit(16))
            .map(|digit| u8::try_from(digit).unwrap())
            .collect();
        digits
            .chunks(2)
            .map(|pair| pair[0] << 4 | pair[1])
            .collect()
    }

    #[test]
    fn cloudflares_test_vectors() {
        let key = Key::derive(&hex(
            "c9d84d04e6369fccb8a4d5a264001491221f1b97d9b80dd32c35834bb4462383",
        ))
        .unwrap();
        assert_eq!(
            key.id.to_vec(),
            hex("9265d14d640ff991b31892f36326ab601ea84d61964fc7a9c7f981a5313e58b9")
        );
        let keys = OdohKeys {
            random: SystemRandom::new(),
            keys: ArcSwap::from_pointee(Keys::new(vec![key]).unwrap()),
        };
        assert_eq!(
            keys.configs().to_vec(),
            hex(
                "002c000100280020000100010020c6a793bedbd601c25970b1cc46bea80f\
                 db1a8ec51540d79e4f9f17b8baa9da33"
            )
        );
        for vector in [
            // Transaction 0: 0 bytes of query padding, 0 of response padding.
            Vector {
                query: "9db1072b0ab473d1e4b74b09637d5f8f253ad4047426ab4dfcc58350bb67b60c",
                response: "9db1072b0ab473d1e4b74b09637d5f8f253ad4047426ab4dfcc58350bb67b60c\
                 9db1072b0ab473d1e4b74b09637d5f8f253ad4047426ab4dfcc58350bb67b60c",
                response_padding: 0,
                oblivious_query: "0100209265d14d640ff991b31892f36326ab601ea84d61964fc7a9c7f981a531\
                 3e58b90054655d2fa2b2271e40b5a78745e41e6d6c5c181fd1fcffcc30fc451d\
                 5ec7fdcc5a6ae0da1cba2bd379da93d02d0e42a3849ec6ba53a54c7c8216f0d3\
                 cc2cef30ac54f824f5d8b57657d8c7b95e2c0276580b3851d9",
                oblivious_response: "0200100f474d14998a841b15f84388a8af1881005413556bcd8d86194fb47a51\
                 982b715b7f253f4f3ea14d89a5dd9d2b67e6c13b0b7eb7ae740c09d915ef7746\
                 1956ba8acac5c5f1d8965ca0888b1c0aa2a0084b4c2c375b74e1c3d4e51ad3fe\
                 8080b7941fd5719df5",
            },
            // Transaction 5: 32 bytes of query padding, 64 of response padding.
            Vector {
                query: "6537c42600c6a3c6db735f8fb9e8e3618acf7508bb315a8862360c4b18dc83b8",
                response: "6537c42600c6a3c6db735f8fb9e8e3618acf7508bb315a8862360c4b18dc83b8\
                 6537c42600c6a3c6db735f8fb9e8e3618acf7508bb315a8862360c4b18dc83b8",
                response_padding: 64,
                oblivious_query: "0100209265d14d640ff991b31892f36326ab601ea84d61964fc7a9c7f981a531\
                 3e58b90074e743c3dcfadd8b146103a69f59544d25eeb7de64772910b4413c94\
                 c5716ae94743655e725a6d5e00e29e05fa812108b03d9913450b08b0ab04a7ee\
                 ec65e13ab52adcfac71b1ea280cbfd9c5865022835addc74f6f71d5c28358b12\
                 1fae3150470324d4f4ecd0e49b729b74e525bed627e2668aa0",
                oblivious_response: "0200104463598990890a8bf9051685d6694597009499a1d75c78516db57ef3ff\
                 cfddc137ac801acf4a8632a1238ca4b21facded26bc60fe132a1d44725f42fff\
                 07b11a10d00760592200c8aebd441a16b4902506c529a11e40af23634645e9d1\
                 be643274a5ab65cf4fff9346f9a47cc752b885d242b65ebf62b6ace2ae6d8544\
                 cbe64310fcfdb85ad0272b142d6a39de262577bdd6c7b573ccb6e9f194c91e10\
                 34b40b57e10700a130",
            },
            // Transaction 15: 96 bytes of query padding, 404 of response padding.
            Vector {
                query: "2486d426a22fd2d56fa027ea800e676cf15698792e878c8366aa35211f9faceb",
                response: "2486d426a22fd2d56fa027ea800e676cf15698792e878c8366aa35211f9faceb\
                 2486d426a22fd2d56fa027ea800e676cf15698792e878c8366aa35211f9faceb",
                response_padding: 404,
                oblivious_query: "0100209265d14d640ff991b31892f36326ab601ea84d61964fc7a9c7f981a531\
                 3e58b900b49f8ab654e033fcf4b421441f67c0a792690ef3fcafb26e8684c8bd\
                 335dc6d561d9355baf8b1365da53b4d39617e51ee7814831b02841b1c618dd93\
                 de6205f90adf312079a9b93ac57eaec5ffdd53c2354992f0f3231307e009380f\
                 171f2228c639bf4c1af262c0e41552d44f9a5a08cebc13df248cfddea8e77e6a\
                 c43cf99bdc18c46fff587141c57dd66b3723df4cfa03501693751ff19ee82aad\
                 5bcb3760080d871a83e3690a7a724f49816d2bcc6861a331b9",
                oblivious_response: "020010a1a577d296df4c780daecb27de39babc01e858e92949d238e774070c07\
                 fe36b9c479176ae8511ee6e5cccd0d653a5c5400bb8411488914db3c40cd808c\
                 746c1cf5cc0fde2f4eb966b02c823ec0282c30c9dcd5fc619505d163454f45a1\
                 89db3c1e7fda97dc55608c2adca39402f643f00f19a29aaa4975f8249f0804cb\
                 61231142c4ef93b6a06663db8bd55423f7c29c5a49fe7d510b9c1e2f5c81485c\
                 4bc4dd97b17983d45615b16c2f38719b8859a34d553d4e9e989b3dfbd063c89d\
                 e6139efdf6ceed9a5ed364237a283e6932420700d11da4cac143c49e5095b377\
                 2993f915d32c3db880040964b1fc0c4a69e14d40d3d8ee9c2f68dc1d836aae2b\
                 02b0cf3bcdd6896890d34c71291cc0e1cb44e60ab03e92713035a84da93d3427\
                 0077ecc3a735690f94a0ae698663ed53b713ba48c12d3167a46898b70ebfb1e6\
                 04454d0a77c7ae75cfe7dc7ca7b1ceca00df3ed35b43d75975d8ebc79a8d31be\
                 e409101bd3100ff55cfa9eb3e5aee46b39fda19666d2587bd755c69e90beb93e\
                 ffb8214fe34f9551d67b083efdd9e4032fe0b8ba1549e07ea215611fd7a0bdb8\
                 7393cf28f5175a6e46a6ca65184ad161c79eba089522b5d60e510b85c60b130d\
                 9dd6359f0fe984cebf2b8943c1b5b6c96f0c9e8338c7d9d12b9986d2fa40b2d0\
                 866521c28bf43c5940d2a91d3da5630a5493ce574121ec504e3eb68d9f",
            },
        ] {
            let opened = keys.open(&hex(vector.oblivious_query)).unwrap();
            assert_eq!(opened.dns(), hex(vector.query));
            let wire = hex(vector.oblivious_response);
            let nonce: [u8; RESPONSE_NONCE_LEN] = wire[3..19].try_into().unwrap();
            let sealed = seal_with(
                &opened,
                &hex(vector.response),
                vector.response_padding,
                &nonce,
            )
            .unwrap();
            assert_eq!(sealed, wire, "the response, byte for byte");
        }
    }

    #[test]
    fn a_query_and_its_answer_round_trip() {
        let keys = OdohKeys::new().unwrap();
        let config = parse_configs(&keys.configs()).unwrap();
        let (wire, pending) = seal_query(&config, &query(), 37).unwrap();
        let opened = keys.open(&wire).unwrap();
        assert_eq!(opened.dns(), query());
        let answer = b"an answer, as far as this test cares".to_vec();
        let sealed = keys.seal(&opened, &answer).unwrap();
        let response = parse_message(&sealed).unwrap();
        assert_eq!(response.message_type, RESPONSE);
        assert_eq!(response.key_id.len(), RESPONSE_NONCE_LEN);
        // 4 bytes of lengths, 468 of padded answer, the tag.
        assert_eq!(response.encrypted.len(), 4 + RESPONSE_BLOCK + TAG_LEN);
        assert_eq!(pending.open(&sealed).unwrap(), answer);
    }

    #[test]
    fn the_configuration_is_rfc_9230s() {
        let keys = OdohKeys::new().unwrap();
        let configs = keys.configs();
        // `ObliviousDoHConfigs`<..>: one config of version 1 whose contents
        // are three suite IDs and a length-prefixed 32-byte key.
        assert_eq!(&configs[..6], &[0, 44, 0, 1, 0, 40]);
        assert_eq!(&configs[6..14], &[0, 0x20, 0, 1, 0, 1, 0, 32]);
        assert_eq!(configs.len(), 46);
        let current = &keys.keys.load().keys[0];
        assert_eq!(current.id, key_id(&configs[6..]).unwrap());
    }

    #[test]
    fn keys_rotate_and_the_previous_one_still_works() {
        let keys = OdohKeys::new().unwrap();
        let first = parse_configs(&keys.configs()).unwrap();
        keys.rotate().unwrap();
        let second = parse_configs(&keys.configs()).unwrap();
        assert_ne!(first.public_key(), second.public_key());
        let (old, _) = seal_query(&first, &query(), 0).unwrap();
        assert!(keys.open(&old).is_ok(), "previous key");
        keys.rotate().unwrap();
        let (older, _) = seal_query(&first, &query(), 0).unwrap();
        assert_eq!(keys.open(&older).err(), Some(OdohError::UnknownKey));
        let (newer, _) = seal_query(&second, &query(), 0).unwrap();
        assert!(keys.open(&newer).is_ok());
    }

    #[test]
    fn bad_queries_are_refused() {
        let keys = OdohKeys::new().unwrap();
        let config = parse_configs(&keys.configs()).unwrap();
        let (wire, _) = seal_query(&config, &query(), 8).unwrap();

        let mut tampered = wire.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(keys.open(&tampered).err(), Some(OdohError::Decrypt));
        let mut response = wire.clone();
        response[0] = RESPONSE;
        assert_eq!(keys.open(&response).err(), Some(OdohError::WrongType));
        let mut other_key = wire.clone();
        other_key[5] ^= 1;
        assert_eq!(keys.open(&other_key).err(), Some(OdohError::UnknownKey));
        for cut in [0, 1, 3, 35, 37, wire.len() - 1] {
            assert!(keys.open(&wire[..cut]).is_err(), "cut at {cut}");
        }
        let mut longer = wire.clone();
        longer.push(0);
        assert_eq!(keys.open(&longer).err(), Some(OdohError::Malformed));

        // The padding must be zeros.
        let mut plain = plaintext(&query(), 4).unwrap();
        *plain.last_mut().unwrap() = 1;
        assert_eq!(parse_plaintext(&plain), Err(OdohError::Padding));
        assert_eq!(
            parse_plaintext(&[0, 0, 0, 0]),
            Err(OdohError::Malformed),
            "empty DNS message"
        );
    }

    #[test]
    fn responses_fit_and_pad() {
        let keys = OdohKeys::new().unwrap();
        let config = parse_configs(&keys.configs()).unwrap();
        let (wire, pending) = seal_query(&config, &query(), 0).unwrap();
        let opened = keys.open(&wire).unwrap();
        let largest = vec![7; MAX_RESPONSE_LEN];
        let sealed = keys.seal(&opened, &largest).unwrap();
        assert_eq!(pending.open(&sealed).unwrap(), largest);
        assert_eq!(
            keys.seal(&opened, &vec![7; MAX_RESPONSE_LEN + 1]).err(),
            Some(OdohError::Encrypt)
        );
        let exact = keys.seal(&opened, &[1; RESPONSE_BLOCK]).unwrap();
        assert_eq!(
            parse_message(&exact).unwrap().encrypted.len(),
            4 + RESPONSE_BLOCK + TAG_LEN,
            "no padding needed"
        );
    }

    #[test]
    fn configurations_are_read_carefully() {
        let keys = OdohKeys::new().unwrap();
        let configs = keys.configs();
        // Another version first, then ours: ours is used.
        let mut two = vec![0, 0];
        two.extend_from_slice(&[0xff, 0x01, 0, 3, 1, 2, 3]);
        two.extend_from_slice(&configs[2..]);
        let total = u16::try_from(two.len() - 2).unwrap().to_be_bytes();
        two[..2].copy_from_slice(&total);
        let config = parse_configs(&two).unwrap();
        assert_eq!(
            config.public_key(),
            parse_configs(&configs).unwrap().public_key()
        );
        for bad in [&configs[..configs.len() - 1], &[0, 0][..], &[][..]] {
            assert!(parse_configs(bad).is_err());
        }
        // Another suite only.
        let mut p256 = configs.to_vec();
        p256[7] = 0x10;
        assert_eq!(parse_configs(&p256).err(), Some(OdohError::NoConfig));
    }
}
