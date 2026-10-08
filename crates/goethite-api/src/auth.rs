//! The admin token, and who is making a request.
//!
//! The config file holds only the SHA-256 hash of the token, so it can be
//! read by anyone without giving the token away. A token is 32 random bytes,
//! so its hash cannot be reversed or guessed. Without a token configured,
//! the API answers loopback clients only.
//!
//! Browsers need two more checks, done by [`guard`] for every request: a web
//! page must not reach the API through DNS rebinding (a hostile name that
//! resolves to 127.0.0.1) or by sending a cross-site request.

use std::fmt::{self, Write as _};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::header::{AUTHORIZATION, HOST, ORIGIN};
use axum::http::uri::Authority;
use axum::middleware::Next;
use axum::response::Response;
use goethite_store::{Actor, ActorKind};
use ring::digest::{SHA256, digest};

use crate::Api;
use crate::error::ApiError;

/// Tokens start with this, so they are easy to recognize (and to find if
/// one leaks into a repository).
pub const TOKEN_PREFIX: &str = "gth_";

/// The SHA-256 hash of the admin token.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TokenHash([u8; 32]);

impl TokenHash {
    /// Whether `token` hashes to this. The comparison does not stop at the
    /// first difference.
    pub fn matches(&self, token: &str) -> bool {
        let presented = hash_token(token);
        presented
            .0
            .iter()
            .zip(&self.0)
            .fold(0_u8, |diff, (a, b)| diff | (a ^ b))
            == 0
    }
}

impl fmt::Debug for TokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenHash(…)")
    }
}

impl fmt::Display for TokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A token hash that is not 64 hexadecimal digits.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("a token hash is 64 hexadecimal digits (the output of `goethite token`)")]
pub struct TokenHashError;

impl FromStr for TokenHash {
    type Err = TokenHashError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0_u8; 32];
        if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(TokenHashError);
        }
        let (pairs, _) = text.as_bytes().as_chunks::<2>();
        for (byte, pair) in bytes.iter_mut().zip(pairs) {
            let pair = std::str::from_utf8(pair).map_err(|_| TokenHashError)?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| TokenHashError)?;
        }
        Ok(Self(bytes))
    }
}

/// The SHA-256 hash of `token`.
pub fn hash_token(token: &str) -> TokenHash {
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(digest(&SHA256, token.as_bytes()).as_ref());
    TokenHash(bytes)
}

/// A new random token and its hash.
pub fn generate_token() -> (String, TokenHash) {
    let random: [u8; 32] = rand::random();
    let mut token = String::from(TOKEN_PREFIX);
    for byte in random {
        let _ = write!(token, "{byte:02x}");
    }
    let hash = hash_token(&token);
    (token, hash)
}

/// The address a request came from; the server adds it to every request.
#[derive(Clone, Copy, Debug)]
pub struct PeerAddr(pub SocketAddr);

/// Checks the admin token (or, without one, that the client is on
/// loopback) and adds the [`Actor`] to the request.
pub(crate) async fn authenticate(
    State(api): State<Arc<Api>>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let peer = request
        .extensions()
        .get::<PeerAddr>()
        .map(|peer| peer.0)
        .ok_or_else(|| ApiError::forbidden("unknown client address"))?;
    let address = Some(peer.ip().to_string());
    let actor = match &api.config.token {
        Some(hash) => {
            let presented = request
                .headers()
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("Bearer "))
                .map(str::trim);
            match presented {
                Some(token) if hash.matches(token) => Actor {
                    kind: ActorKind::Token,
                    address,
                    node: None,
                },
                _ => return Err(ApiError::unauthorized()),
            }
        }
        None if peer.ip().is_loopback() => Actor {
            kind: ActorKind::Unauthenticated,
            address,
            node: None,
        },
        None => {
            return Err(ApiError::forbidden(
                "no admin token is configured, so the API only answers loopback clients",
            ));
        }
    };
    request.extensions_mut().insert(actor);
    Ok(next.run(request).await)
}

/// Refuses requests a browser could be tricked into sending.
///
/// - **DNS rebinding.** Without an admin token, the API answers only to
///   loopback names (`localhost`, `127.0.0.1`, `[::1]`), so a page on a
///   hostile domain that resolves to 127.0.0.1 gets nothing. With a token,
///   any name works: such a page does not have the token.
/// - **Cross-site requests.** A request with an `Origin` header must come
///   from the API's own origin. Browsers send `Origin` with every request
///   that can change something; programs like curl send none.
pub(crate) async fn guard(
    State(api): State<Arc<Api>>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let authority = request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .or_else(|| request.uri().authority().map(Authority::as_str));
    if api.config.token.is_none() && !authority.is_some_and(is_loopback_authority) {
        return Err(ApiError::forbidden(
            "without an admin token, the API only answers requests for localhost, 127.0.0.1 or [::1]",
        ));
    }
    if let Some(origin) = request.headers().get(ORIGIN) {
        let same = origin
            .to_str()
            .ok()
            .and_then(origin_authority)
            .zip(authority)
            .is_some_and(|(origin, authority)| origin.eq_ignore_ascii_case(authority));
        if !same {
            return Err(ApiError::forbidden(
                "requests from other web sites are not accepted",
            ));
        }
    }
    Ok(next.run(request).await)
}

/// `host[:port]` from an `Origin` such as `https://dns.example.lan:8053`.
pub fn origin_authority(origin: &str) -> Option<&str> {
    origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
        .filter(|rest| !rest.is_empty() && !rest.contains('/'))
}

/// Whether a `Host` value names this machine: `localhost` (or a name under
/// `.localhost`, which browsers always resolve to loopback) or a loopback
/// address, with or without a port.
pub fn is_loopback_authority(authority: &str) -> bool {
    let (host, port) = match authority.strip_prefix('[') {
        Some(rest) => match rest.split_once(']') {
            Some((host, "")) => (host, None),
            Some((host, port)) => match port.strip_prefix(':') {
                Some(port) => (host, Some(port)),
                None => return false,
            },
            None => return false,
        },
        None => match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        },
    };
    // A port, if any, is a number: nothing else may follow the name.
    if port.is_some_and(|port| {
        port.bytes().any(|b| !b.is_ascii_digit()) || port.parse::<u16>().is_err()
    }) {
        return false;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return ip.to_canonical().is_loopback();
    }
    let lower = host.to_ascii_lowercase();
    (lower == "localhost" || lower.ends_with(".localhost"))
        && lower.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_authorities() {
        for good in [
            "localhost",
            "localhost:8053",
            "LOCALHOST:8053",
            "ui.localhost:5173",
            "127.0.0.1",
            "127.0.0.1:8053",
            "127.1.2.3:8053",
            "[::1]",
            "[::1]:8053",
            "[::ffff:127.0.0.1]:8053",
        ] {
            assert!(is_loopback_authority(good), "{good}");
        }
        for bad in [
            "",
            "goethite.test",
            "evil.example:8053",
            "localhost.evil.example",
            "127.0.0.1.evil.example",
            "10.0.0.1:8053",
            "[::2]:8053",
            "[::1",
            "[::1]x",
            "[::1]:",
            "::1",
            "localhost:",
            "localhost:80/x",
            "localhost:99999",
            "localhost:+80",
            "localhost:80:80",
            "ui/l.localhost:517",
            "a..localhost",
            ".localhost",
            "a_b.localhost",
        ] {
            assert!(!is_loopback_authority(bad), "{bad}");
        }
    }

    #[test]
    fn origins() {
        assert_eq!(
            origin_authority("http://localhost:8053"),
            Some("localhost:8053")
        );
        assert_eq!(origin_authority("https://dns.lan"), Some("dns.lan"));
        for bad in ["null", "file://", "http://", "http://a/b", "ftp://a"] {
            assert_eq!(origin_authority(bad), None, "{bad}");
        }
    }

    #[test]
    fn tokens_and_hashes() {
        let (token, hash) = generate_token();
        assert!(token.starts_with(TOKEN_PREFIX));
        assert_eq!(token.len(), TOKEN_PREFIX.len() + 64);
        assert!(hash.matches(&token));
        let mut other = token.clone();
        let last = if other.ends_with('0') { '1' } else { '0' };
        other.pop();
        other.push(last);
        assert!(!hash.matches(&other));
        assert!(!hash.matches(""));
        let parsed: TokenHash = hash.to_string().parse().unwrap();
        assert_eq!(parsed, hash);
        assert_ne!(generate_token().0, token);
    }

    #[test]
    fn hashes_are_strict_hex() {
        let plus = format!("+{}", "f".repeat(63));
        for bad in [
            "",
            "abc",
            &"g".repeat(64),
            &"a".repeat(63),
            &"é".repeat(32),
            &plus,
        ] {
            assert_eq!(bad.parse::<TokenHash>(), Err(TokenHashError), "{bad}");
        }
        // SHA-256 of "goethite".
        let hash = hash_token("goethite");
        assert_eq!(
            hash.to_string(),
            "09ef8af54d2ab7ee8af92583f8efd34037613c0209572423b7a3154c4696b6dd"
        );
        assert_eq!(format!("{hash:?}"), "TokenHash(…)", "never printed in logs");
    }
}
