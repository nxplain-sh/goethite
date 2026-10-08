//! The admin token, and who is making a request.
//!
//! The config file holds only the SHA-256 hash of the token, so it can be
//! read by anyone without giving the token away. A token is 32 random bytes,
//! so its hash cannot be reversed or guessed. Without a token configured,
//! the API answers loopback clients only.

use std::fmt::{self, Write as _};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::header::AUTHORIZATION;
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
                },
                _ => return Err(ApiError::unauthorized()),
            }
        }
        None if peer.ip().is_loopback() => Actor {
            kind: ActorKind::Unauthenticated,
            address,
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

#[cfg(test)]
mod tests {
    use super::*;

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
