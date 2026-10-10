//! TOTP (RFC 6238) second factors, and recovery codes.
//!
//! A secret is 20 random bytes, shown to the user as 32 base32 characters
//! (RFC 4648, no padding) and hashed into QR codes and authenticator apps as
//! an `otpauth://` URI. Codes are the standard six digits over 30-second
//! steps, HMAC-SHA1; SHA-1 is what RFC 6238 and every authenticator app use.
//!
//! Recovery codes are one-time passwords for a user who lost their
//! authenticator: ten codes of ten characters, stored as their SHA-256, each
//! removed when used.

use std::fmt::Write as _;

use ring::digest::{SHA256, digest};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};

/// How long one code is valid, in seconds.
pub(crate) const STEP_SECONDS: u64 = 30;
/// How many digits a code has.
pub(crate) const DIGITS: usize = 6;
/// How many bytes a secret has.
pub(crate) const SECRET_LEN: usize = 20;
/// How many recovery codes a user gets at a time.
pub(crate) const RECOVERY_CODES: usize = 10;
/// How many characters a recovery code has.
pub(crate) const RECOVERY_LEN: usize = 10;

/// The characters recovery codes use: no 0/O, 1/I/L or other lookalikes.
const RECOVERY_ALPHABET: &[u8] = b"23456789abcdefghjkmnpqrstuvwxyz";
/// The RFC 4648 base32 alphabet.
const BASE32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// A new secret, or `None` if the system's random source fails.
pub(crate) fn new_secret() -> Option<[u8; SECRET_LEN]> {
    let mut secret = [0_u8; SECRET_LEN];
    SystemRandom::new().fill(&mut secret).ok()?;
    Some(secret)
}

/// `secret` as base32 characters, as an authenticator app wants it: 20
/// bytes become 32 characters.
pub fn encode_secret(secret: &[u8]) -> String {
    let mut text = String::with_capacity(secret.len().div_ceil(5).saturating_mul(8));
    let mut buffer = 0_u32;
    let mut bits = 0_u32;
    for byte in secret {
        buffer = buffer.wrapping_shl(8) | u32::from(*byte);
        bits = bits.saturating_add(8);
        while bits >= 5 {
            bits = bits.saturating_sub(5);
            push_base32(&mut text, buffer.wrapping_shr(bits) & 0x1f);
        }
    }
    if bits > 0 {
        push_base32(
            &mut text,
            buffer.wrapping_shl(5_u32.saturating_sub(bits)) & 0x1f,
        );
    }
    text
}

fn push_base32(text: &mut String, value: u32) {
    if let Ok(index) = usize::try_from(value)
        && let Some(byte) = BASE32.get(index)
    {
        text.push(char::from(*byte));
    }
}

/// The bytes of base32 `text` (RFC 4648, no padding), or `None` if `text`
/// is not canonical base32: bad characters, a length no base32 string has,
/// or a leftover that is not zero bits.
pub fn decode_secret(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || text.len() > 64 || !matches!(text.len() % 8, 0 | 2 | 4 | 5 | 7) {
        return None;
    }
    let mut bytes = Vec::with_capacity(text.len().saturating_mul(5) / 8);
    let mut buffer = 0_u32;
    let mut bits = 0_u32;
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => u32::from(byte.saturating_sub(b'A')),
            b'2'..=b'7' => u32::from(byte.saturating_sub(b'2')).saturating_add(26),
            _ => return None,
        };
        buffer = buffer.wrapping_shl(5) | value;
        bits = bits.saturating_add(5);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            bytes.push(u8::try_from(buffer.wrapping_shr(bits) & 0xff).unwrap_or(0));
        }
    }
    // What a canonical encoding leaves over is zero bits, fewer than five.
    let leftover = (1_u32.wrapping_shl(bits)).wrapping_sub(1);
    (bits < 5 && buffer & leftover == 0).then_some(bytes)
}

/// The six-digit code for `time`, seconds since the Unix epoch.
pub fn code(secret: &[u8], time: u64) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let counter = time / STEP_SECONDS;
    let tag = hmac::sign(&key, &counter.to_be_bytes());
    let mac = tag.as_ref();
    // Dynamic truncation, RFC 4226 section 5.4. A SHA-1 HMAC is 20 bytes,
    // so the offset (at most 15) always leaves four bytes to read.
    let offset = mac.last().copied().unwrap_or(0) & 0x0f;
    let value = mac
        .get(usize::from(offset)..usize::from(offset).saturating_add(4))
        .and_then(|bytes| bytes.try_into().ok())
        .map_or(0_u32, u32::from_be_bytes)
        & 0x7fff_ffff;
    format!("{:06}", value % 1_000_000)
}

/// Whether `code` is valid for `time`, one 30-second step either side of it.
pub(crate) fn verify(secret: &[u8], code: &str, time: u64) -> bool {
    if code.len() != DIGITS || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let mut accepted = false;
    for step in [
        time.saturating_sub(STEP_SECONDS),
        time,
        time.saturating_add(STEP_SECONDS),
    ] {
        // No early return: every candidate is compared, always.
        accepted |= same(code.as_bytes(), self::code(secret, step).as_bytes());
    }
    accepted
}

/// The `otpauth://` URI an authenticator app reads to set the factor up.
/// `account` is a validated user name, so it needs no escaping.
pub(crate) fn uri(secret_b32: &str, account: &str) -> String {
    format!(
        "otpauth://totp/goethite:{account}?secret={secret_b32}&issuer=goethite\
         &algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"
    )
}

/// New recovery codes, as the user sees them once.
pub(crate) fn new_recovery_codes() -> Option<Vec<String>> {
    let mut codes = Vec::with_capacity(RECOVERY_CODES);
    let rng = SystemRandom::new();
    for _ in 0..RECOVERY_CODES {
        let mut code = String::with_capacity(RECOVERY_LEN);
        for _ in 0..RECOVERY_LEN {
            let mut random = [0_u8; 1];
            rng.fill(&mut random).ok()?;
            let index = usize::from(random.first().copied().unwrap_or(0))
                .checked_rem(RECOVERY_ALPHABET.len())
                .unwrap_or(0);
            if let Some(byte) = RECOVERY_ALPHABET.get(index) {
                code.push(char::from(*byte));
            }
        }
        codes.push(code);
    }
    Some(codes)
}

/// A typed recovery code, as it is stored: its SHA-256, in hexadecimal.
/// Case, dashes and spaces are ignored.
pub fn hash_recovery_code(code: &str) -> String {
    let mut normalised = String::with_capacity(code.len());
    for byte in code.bytes() {
        match byte {
            b'-' | b' ' | b'\t' => {}
            b'A'..=b'Z' => normalised.push(char::from(byte.saturating_add(32))),
            _ => normalised.push(char::from(byte)),
        }
    }
    let mut hash = String::with_capacity(64);
    for byte in digest(&SHA256, normalised.as_bytes()).as_ref() {
        // Writing to a String cannot fail.
        let _ = write!(hash, "{byte:02x}");
    }
    hash
}

/// Whether `a` and `b` are equal, without stopping at the first difference.
pub(crate) fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0_u8, |diff, (a, b)| diff | (a ^ b)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238's SHA-1 test secret: "12345678901234567890".
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn base32_round_trips() {
        for secret in [
            [0_u8; SECRET_LEN],
            [0xff_u8; SECRET_LEN],
            RFC_SECRET.try_into().unwrap(),
            new_secret().unwrap(),
        ] {
            let text = encode_secret(&secret);
            assert_eq!(text.len(), 32, "{text}");
            assert_eq!(decode_secret(&text).as_deref(), Some(secret.as_slice()));
        }
        assert_eq!(encode_secret(b"foo"), "MZXW6");
        assert_eq!(decode_secret("MZXW6").as_deref(), Some(b"foo".as_slice()));
        for bad in [
            "",
            "MZXW",
            "MZXW6====",
            "mzxw6",
            "MZXW7",
            "MZXW6/Z",
            &"A".repeat(33),
            &"A".repeat(65),
        ] {
            assert_eq!(decode_secret(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn rfc6238_vectors() {
        // The last six digits of RFC 6238's SHA-1 column, with each time.
        for (time, digits) in [
            (59_u64, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
            (20_000_000_000, "353130"),
        ] {
            assert_eq!(code(RFC_SECRET, time), digits, "t={time}");
            assert!(verify(RFC_SECRET, digits, time), "t={time}");
            assert!(
                verify(RFC_SECRET, digits, time + STEP_SECONDS),
                "t+1={time}"
            );
            assert!(!verify(RFC_SECRET, digits, time + 2 * STEP_SECONDS));
        }
    }

    #[test]
    fn codes_are_checked_strictly() {
        assert!(!verify(RFC_SECRET, "", 59));
        assert!(!verify(RFC_SECRET, "28708", 59));
        assert!(!verify(RFC_SECRET, "2870821", 59));
        assert!(!verify(RFC_SECRET, "28708x", 59));
        assert!(!verify(RFC_SECRET, "287083", 59));
        let uri = uri(&encode_secret(&[7_u8; SECRET_LEN]), "admin");
        assert!(
            uri.starts_with("otpauth://totp/goethite:admin?secret="),
            "{uri}"
        );
        assert!(uri.contains("&issuer=goethite"), "{uri}");
    }

    #[test]
    fn recovery_codes_are_stored_hashed() {
        let codes = new_recovery_codes().unwrap();
        assert_eq!(codes.len(), RECOVERY_CODES);
        for code in &codes {
            assert_eq!(code.len(), RECOVERY_LEN);
            let hash = hash_recovery_code(code);
            assert_eq!(hash.len(), 64);
            assert!(!hash.contains(code.as_str()));
        }
        assert_eq!(
            hash_recovery_code("ABCD-EFGH"),
            hash_recovery_code("abcdefgh"),
            "case, dashes and spaces do not matter"
        );
        assert_ne!(hash_recovery_code(&codes[0]), hash_recovery_code(&codes[1]));
    }
}
