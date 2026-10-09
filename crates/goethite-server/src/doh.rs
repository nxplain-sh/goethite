//! Reading DNS over HTTPS requests (RFC 8484), without I/O: the request
//! target, the `dns` parameter of a `GET` and its base64url encoding, and
//! the client ID in the path or the TLS server name. Every function here
//! takes data straight from the network and never panics.

use goethite_resolver::is_client_id;

/// The path DNS over HTTPS answers on, as RFC 8484 suggests.
pub const PATH: &str = "/dns-query";

/// The largest DNS message, in bytes: what TCP framing allows.
pub const MAX_MESSAGE_LEN: usize = 65_535;

/// The longest `dns` parameter: [`MAX_MESSAGE_LEN`] bytes in base64url.
pub const MAX_PARAM_LEN: usize = 87_380;

/// Why a request cannot be answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DohError {
    /// The path is not [`PATH`] or below it.
    #[error("not found")]
    NotFound,
    /// The client ID in the path is not a valid client ID.
    #[error("invalid client ID")]
    InvalidClientId,
    /// A `GET` without the `dns` parameter.
    #[error("missing dns parameter")]
    MissingParam,
    /// The `dns` parameter is longer than [`MAX_PARAM_LEN`].
    #[error("dns parameter too long")]
    ParamTooLong,
    /// The `dns` parameter is not base64url.
    #[error("dns parameter is not base64url")]
    InvalidBase64,
}

/// The client ID of a request for `path` (the path alone, without the
/// query string): `None` for [`PATH`], the ID for `PATH/<id>`.
///
/// # Errors
///
/// [`DohError::NotFound`] for any other path, and
/// [`DohError::InvalidClientId`] if `<id>` is not a valid client ID.
pub fn client_id_from_path(path: &str) -> Result<Option<&str>, DohError> {
    let rest = path.strip_prefix(PATH).ok_or(DohError::NotFound)?;
    if rest.is_empty() || rest == "/" {
        return Ok(None);
    }
    let id = rest.strip_prefix('/').ok_or(DohError::NotFound)?;
    let id = id.strip_suffix('/').unwrap_or(id);
    if is_client_id(id) {
        Ok(Some(id))
    } else {
        Err(DohError::InvalidClientId)
    }
}

/// The DNS message in the `dns` parameter of `query`, a `GET` request's
/// query string, decoded into `out`.
///
/// # Errors
///
/// If there is no `dns` parameter, or it is too long or not base64url.
pub fn decode_get(query: Option<&str>, out: &mut Vec<u8>) -> Result<(), DohError> {
    let param = query
        .unwrap_or_default()
        .split('&')
        .find_map(|pair| pair.strip_prefix("dns="))
        .ok_or(DohError::MissingParam)?;
    if param.len() > MAX_PARAM_LEN {
        return Err(DohError::ParamTooLong);
    }
    decode_base64url(param, out)
}

/// The value of one base64url character (RFC 4648, section 5).
fn sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte.wrapping_sub(b'A')),
        b'a'..=b'z' => Some(byte.wrapping_sub(b'a').wrapping_add(26)),
        b'0'..=b'9' => Some(byte.wrapping_sub(b'0').wrapping_add(52)),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Decodes base64url `text` into `out`. RFC 8484 leaves the padding out;
/// up to two `=` at the end are accepted anyway, and nothing else outside
/// the alphabet.
///
/// # Errors
///
/// [`DohError::InvalidBase64`] for a character outside the alphabet, or a
/// length no encoding has.
pub fn decode_base64url(text: &str, out: &mut Vec<u8>) -> Result<(), DohError> {
    let text = text
        .strip_suffix("==")
        .or_else(|| text.strip_suffix('='))
        .unwrap_or(text);
    if text.len() % 4 == 1 {
        return Err(DohError::InvalidBase64);
    }
    out.clear();
    out.reserve(text.len().saturating_mul(3) / 4);
    // Fewer than 8 bits are held between characters, so nothing overflows.
    let mut bits: u32 = 0;
    let mut held: u32 = 0;
    for &byte in text.as_bytes() {
        let value = sextet(byte).ok_or(DohError::InvalidBase64)?;
        bits = bits.wrapping_shl(6) | u32::from(value);
        held = held.wrapping_add(6);
        if held >= 8 {
            held = held.wrapping_sub(8);
            out.push(u8::try_from(bits.wrapping_shr(held) & 0xff).unwrap_or_default());
            bits &= 1_u32.wrapping_shl(held).wrapping_sub(1);
        }
    }
    Ok(())
}

/// The client ID in a TLS server name `sni`, such as
/// `anna-phone.dns.example` when goethite is reached as `server_name`
/// (`dns.example`): the single label in front, lowercased, if it is a valid
/// client ID. Server names that are not one label below `server_name`
/// carry none.
pub fn client_id_from_server_name(sni: &str, server_name: &str) -> Option<String> {
    let sni = sni.strip_suffix('.').unwrap_or(sni);
    let server_name = server_name.strip_suffix('.').unwrap_or(server_name);
    let split = sni
        .len()
        .checked_sub(server_name.len())?
        .checked_sub(1)
        .filter(|split| *split > 0)?;
    let (label, rest) = sni.split_at_checked(split)?;
    let rest = rest.strip_prefix('.')?;
    if server_name.is_empty() || !rest.eq_ignore_ascii_case(server_name) {
        return None;
    }
    let label = label.to_ascii_lowercase();
    is_client_id(&label).then_some(label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(client_id_from_path("/dns-query"), Ok(None));
        assert_eq!(client_id_from_path("/dns-query/"), Ok(None));
        assert_eq!(
            client_id_from_path("/dns-query/anna-phone"),
            Ok(Some("anna-phone"))
        );
        assert_eq!(
            client_id_from_path("/dns-query/anna-phone/"),
            Ok(Some("anna-phone"))
        );
        assert_eq!(
            client_id_from_path("/dns-query/Anna"),
            Err(DohError::InvalidClientId)
        );
        assert_eq!(
            client_id_from_path("/dns-query/a/b"),
            Err(DohError::InvalidClientId)
        );
        assert_eq!(client_id_from_path("/"), Err(DohError::NotFound));
        assert_eq!(client_id_from_path("/dns-queryx"), Err(DohError::NotFound));
        assert_eq!(client_id_from_path("/api/v1"), Err(DohError::NotFound));
    }

    /// RFC 4648, section 10, in the URL alphabet.
    #[test]
    fn base64url() {
        let mut out = Vec::new();
        for (text, expected) in [
            ("", ""),
            ("Zg", "f"),
            ("Zg==", "f"),
            ("Zm8", "fo"),
            ("Zm8=", "fo"),
            ("Zm9v", "foo"),
            ("Zm9vYg", "foob"),
            ("Zm9vYmE", "fooba"),
            ("Zm9vYmFy", "foobar"),
        ] {
            decode_base64url(text, &mut out).unwrap();
            assert_eq!(out, expected.as_bytes(), "{text}");
        }
        decode_base64url("-_8", &mut out).unwrap();
        assert_eq!(out, [0xfb, 0xff]);
        for invalid in ["Z", "Zm9vY", "Zm+v", "Zm/v", "Zm9v===", "Zm 9", "Zé"] {
            assert_eq!(
                decode_base64url(invalid, &mut out),
                Err(DohError::InvalidBase64),
                "{invalid}"
            );
        }
    }

    /// The example in RFC 8484, section 4.1.1: `www.example.com` `A`.
    #[test]
    fn get_requests() {
        let mut out = Vec::new();
        decode_get(
            Some("dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"),
            &mut out,
        )
        .unwrap();
        assert_eq!(out.len(), 33);
        assert_eq!(out.get(12..17), Some(&b"\x03www\x07"[..]));
        decode_get(Some("ct=x&dns=AAAB"), &mut out).unwrap();
        assert_eq!(out, [0, 0, 1]);
        assert_eq!(decode_get(None, &mut out), Err(DohError::MissingParam));
        assert_eq!(
            decode_get(Some("name=example.com"), &mut out),
            Err(DohError::MissingParam)
        );
        let long = format!("dns={}", "A".repeat(MAX_PARAM_LEN + 1));
        assert_eq!(
            decode_get(Some(&long), &mut out),
            Err(DohError::ParamTooLong)
        );
    }

    #[test]
    fn server_names() {
        let id = |sni: &str| client_id_from_server_name(sni, "dns.example");
        assert_eq!(id("anna-phone.dns.example").as_deref(), Some("anna-phone"));
        assert_eq!(id("Anna-Phone.DNS.example.").as_deref(), Some("anna-phone"));
        assert_eq!(id("dns.example"), None);
        assert_eq!(id(".dns.example"), None);
        assert_eq!(id("a.b.dns.example"), None);
        assert_eq!(id("anna.other.example"), None);
        assert_eq!(id("annadns.example"), None);
        assert_eq!(id("-x.dns.example"), None);
        assert_eq!(id("example"), None);
        assert_eq!(client_id_from_server_name("x.", ""), None);
    }
}
