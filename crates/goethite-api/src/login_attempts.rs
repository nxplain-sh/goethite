//! A small, bounded record of failed sign-ins, per client address and per
//! user name, so guessing passwords or codes runs out of tries.
//!
//! It is deliberately per node and in memory: the next request can come
//! from another node, but a failed guess is cheap to repeat anywhere, so a
//! limiter that fails over with the cluster buys little. Success forgets
//! the failures; the window also expires them.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

/// How long failures count, in seconds.
const WINDOW_SECONDS: i64 = 300;
/// The most keys tracked at once.
const MAX_KEYS: usize = 4096;

struct Entry {
    failures: u32,
    until: i64,
}

/// Failed sign-ins by key (`ip:…` or `user:…`).
#[derive(Default)]
pub(crate) struct Attempts {
    inner: Mutex<HashMap<String, Entry>>,
}

impl Attempts {
    /// Whether `key` may try again: it has not used up `max` failures in
    /// the window.
    pub(crate) fn allowed(&self, key: &str, max: u32, now: i64) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        match inner.get(key) {
            Some(entry) if entry.until > now => entry.failures < max,
            Some(_) => {
                inner.remove(key);
                true
            }
            None => true,
        }
    }

    /// Records one failure of `key`.
    pub(crate) fn fail(&self, key: &str, now: i64) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = inner.get_mut(key)
            && entry.until > now
        {
            entry.failures = entry.failures.saturating_add(1);
            return;
        }
        if inner.len() >= MAX_KEYS {
            inner.retain(|_, entry| entry.until > now);
            if inner.len() >= MAX_KEYS
                && let Some(oldest) = inner
                    .iter()
                    .min_by_key(|(_, entry)| entry.until)
                    .map(|(key, _)| key.clone())
            {
                inner.remove(&oldest);
            }
        }
        inner.insert(
            key.to_owned(),
            Entry {
                failures: 1,
                until: now.saturating_add(WINDOW_SECONDS),
            },
        );
    }

    /// Forgets `key`'s failures: the sign-in worked.
    pub(crate) fn clear(&self, key: &str) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failures_run_out_and_expire() {
        let attempts = Attempts::default();
        assert!(attempts.allowed("ip:1", 2, 0));
        attempts.fail("ip:1", 0);
        assert!(attempts.allowed("ip:1", 2, 0));
        attempts.fail("ip:1", 0);
        assert!(!attempts.allowed("ip:1", 2, 0));
        assert!(attempts.allowed("ip:1", 2, WINDOW_SECONDS + 1));
        attempts.clear("ip:1");
        assert!(
            attempts.allowed("ip:1", 0, 0),
            "after a success, any limit passes"
        );
    }

    #[test]
    fn the_map_stays_bounded() {
        let attempts = Attempts::default();
        for index in 0..(MAX_KEYS + 10) {
            attempts.fail(&format!("user:{index}"), 0);
        }
        let inner = attempts.inner.lock().unwrap();
        assert!(inner.len() <= MAX_KEYS, "{}", inner.len());
    }
}
