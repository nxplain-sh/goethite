//! Browser sessions: one per sign-in, held in memory on the node that
//! answered the sign-in.
//!
//! The session token travels in an `HttpOnly` cookie, so page scripts
//! cannot read it; only its SHA-256 is held, so a memory dump does not hand
//! one over. A session stops working when it expires, when the user signs
//! out, or when the user's record changes at all: each request compares the
//! revision the session was made at with the user's current one, so a
//! password change, a new role or a disable takes effect on every node.
//!
//! Sessions do not replicate. After a failover the user signs in again,
//! which costs one sign-in and no configuration write.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Mutex, PoisonError};

use axum::http::HeaderMap;
use axum::http::header::COOKIE;
use ring::digest::{SHA256, digest};

/// How long a session lasts, in seconds: twelve hours.
pub(crate) const SESSION_TTL_SECONDS: i64 = 12 * 60 * 60;
/// The most sessions one node holds.
const MAX_SESSIONS: usize = 1024;
/// The cookie the session token travels in.
pub(crate) const COOKIE_NAME: &str = "gth_session";
/// The longest cookie value accepted.
const MAX_COOKIE_VALUE: usize = 128;
/// What a session token starts with.
pub(crate) const TOKEN_PREFIX: &str = "gths_";

/// One signed-in browser.
#[derive(Clone)]
pub(crate) struct Session {
    /// The user's ID.
    pub(crate) user: String,
    /// The user's revision when the session was made.
    pub(crate) revision: u64,
    /// When it stops working, in seconds since the Unix epoch.
    pub(crate) expires: i64,
}

/// The sessions this node holds.
#[derive(Default)]
pub(crate) struct Sessions {
    inner: Mutex<HashMap<[u8; 32], Session>>,
}

impl Sessions {
    /// Starts a session and returns its token.
    pub(crate) fn create(&self, user: &str, revision: u64, now: i64) -> String {
        let random: [u8; 32] = rand::random();
        let mut token = String::from(TOKEN_PREFIX);
        for byte in random {
            let _ = write!(token, "{byte:02x}");
        }
        let session = Session {
            user: user.to_owned(),
            revision,
            expires: now.saturating_add(SESSION_TTL_SECONDS),
        };
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.retain(|_, held| held.expires > now);
        if inner.len() >= MAX_SESSIONS
            && let Some(oldest) = inner
                .iter()
                .min_by_key(|(_, held)| held.expires)
                .map(|(key, _)| *key)
        {
            inner.remove(&oldest);
        }
        inner.insert(key(&token), session);
        token
    }

    /// The session `token` names, if it is this node's and has not expired.
    pub(crate) fn get(&self, token: &str, now: i64) -> Option<Session> {
        let inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner
            .get(&key(token))
            .filter(|session| session.expires > now)
            .cloned()
    }

    /// Forgets the session `token` names.
    pub(crate) fn remove(&self, token: &str) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.remove(&key(token));
    }

    /// Forgets every session of `user` except the one `token` names: a
    /// password or second-factor change signs the other tabs out.
    pub(crate) fn remove_others(&self, user: &str, token: &str) {
        let keep = key(token);
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.retain(|token, session| *token == keep || session.user != user);
    }
}

/// The lookup key of `token`: its SHA-256, so memory never holds the token
/// itself.
fn key(token: &str) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(digest(&SHA256, token.as_bytes()).as_ref());
    bytes
}

/// The `Set-Cookie` value that hands `token` to the browser.
pub(crate) fn cookie_set(token: &str, secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!(
        "{COOKIE_NAME}={token}; Path=/api; Max-Age={SESSION_TTL_SECONDS}; HttpOnly; \
         SameSite=Strict{secure}"
    )
}

/// The `Set-Cookie` value that takes the cookie away again.
pub(crate) fn cookie_clear(secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!("{COOKIE_NAME}=; Path=/api; Max-Age=0; HttpOnly; SameSite=Strict{secure}")
}

/// The session token in the request's cookies, if it carries one.
pub(crate) fn cookie_value(headers: &HeaderMap) -> Option<String> {
    for header in headers.get_all(COOKIE) {
        let Ok(text) = header.to_str() else {
            continue;
        };
        for part in text.split(';') {
            let Some((name, value)) = part.trim().split_once('=') else {
                continue;
            };
            if name == COOKIE_NAME
                && !value.is_empty()
                && value.len() <= MAX_COOKIE_VALUE
                && value.bytes().all(|byte| byte.is_ascii_graphic())
            {
                return Some(value.to_owned());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_live_and_die() {
        let sessions = Sessions::default();
        let token = sessions.create("us_1", 3, 1_000);
        assert!(token.starts_with(TOKEN_PREFIX), "{token}");
        assert_eq!(token.len(), TOKEN_PREFIX.len() + 64);
        let session = sessions.get(&token, 1_000).unwrap();
        assert_eq!(session.user, "us_1");
        assert_eq!(session.revision, 3);
        assert!(sessions.get(&token, 1_000 + SESSION_TTL_SECONDS).is_none());
        assert!(sessions.get("gths_0000", 1_000).is_none());

        let second = sessions.create("us_1", 3, 1_000);
        let third = sessions.create("us_2", 1, 1_000);
        sessions.remove_others("us_1", &token);
        assert!(sessions.get(&token, 1_000).is_some());
        assert!(sessions.get(&second, 1_000).is_none());
        assert!(sessions.get(&third, 1_000).is_some());
        sessions.remove(&token);
        assert!(sessions.get(&token, 1_000).is_none());
    }

    #[test]
    fn cookies_are_strict_and_parse() {
        let set = cookie_set("gths_ab", true);
        assert!(set.contains("HttpOnly"), "{set}");
        assert!(set.contains("SameSite=Strict"), "{set}");
        assert!(set.contains("; Secure"), "{set}");
        assert!(cookie_clear(false).contains("Max-Age=0"));

        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            "other=1; gth_session=gths_ab; more=2".parse().unwrap(),
        );
        assert_eq!(cookie_value(&headers).as_deref(), Some("gths_ab"));
        headers.insert(COOKIE, "gth_session=".parse().unwrap());
        assert_eq!(cookie_value(&headers), None);
        headers.insert(COOKIE, "malformed".parse().unwrap());
        assert_eq!(cookie_value(&headers), None);
        assert_eq!(cookie_value(&HeaderMap::new()), None);
    }
}
