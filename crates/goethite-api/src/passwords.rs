//! Password hashing for API users: Argon2id, in PHC form.
//!
//! The hash of a password, never the password, is what the store holds; the
//! parameters are the `argon2` crate's defaults, which are the OWASP
//! recommendation (19 MiB of memory, 2 rounds, one lane). Hashing is slow on
//! purpose and runs on a blocking thread.

use std::sync::LazyLock;

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use ring::rand::{SecureRandom, SystemRandom};

/// The shortest password accepted, in characters.
pub(crate) const MIN_PASSWORD_LEN: usize = 12;
/// The longest password accepted, in bytes: hashing takes work per byte.
pub(crate) const MAX_PASSWORD_LEN: usize = 256;

/// Why a new password was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PasswordError {
    /// Shorter than 12 characters.
    #[error("a password is at least 12 characters")]
    TooShort,
    /// Longer than 256 bytes.
    #[error("a password is at most 256 bytes")]
    TooLong,
}

/// Checks a new password; what the rules are is in [`PasswordError`].
///
/// # Errors
///
/// [`PasswordError::TooShort`] or [`PasswordError::TooLong`].
pub fn check_new(password: &str) -> Result<(), PasswordError> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(PasswordError::TooShort);
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(PasswordError::TooLong);
    }
    Ok(())
}

/// The Argon2id hash of `password`, in PHC form; `None` if the salt cannot
/// be gathered, which should not happen.
pub fn hash_password(password: &str) -> Option<String> {
    let mut salt_bytes = [0_u8; 16];
    SystemRandom::new().fill(&mut salt_bytes).ok()?;
    let salt = SaltString::encode_b64(&salt_bytes).ok()?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .ok()
        .map(|hash| hash.to_string())
}

/// Whether `password` is the one with the Argon2id hash `hash`.
pub fn verify_password(hash: &str, password: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// A generated password: 25 characters in five groups, from letters and
/// digits without lookalikes, about 123 bits. Shown once by `goethite user
/// add` and meant to be written down.
pub fn new_password() -> Option<String> {
    let alphabet = b"23456789abcdefghjkmnpqrstuvwxyz";
    let rng = SystemRandom::new();
    let mut password = String::with_capacity(29);
    for group in 0..5 {
        if group > 0 {
            password.push('-');
        }
        for _ in 0..5 {
            let mut random = [0_u8; 1];
            rng.fill(&mut random).ok()?;
            let index = usize::from(random.first().copied().unwrap_or(0))
                .checked_rem(alphabet.len())
                .unwrap_or(0);
            password.push(char::from(*alphabet.get(index)?));
        }
    }
    Some(password)
}

/// A hash of a password nobody knows: verifying against it costs the same
/// as verifying a real one, so a sign-in with an unknown name takes as long
/// as one with a known name.
pub(crate) fn dummy_hash() -> &'static str {
    static DUMMY: LazyLock<String> = LazyLock::new(|| {
        hash_password("this password is nobody's; it only costs the hasher some work")
            .unwrap_or_default()
    });
    LazyLock::force(&DUMMY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_verify_and_do_not_leak() {
        let stored = hash_password("correct horse battery staple").unwrap();
        assert!(stored.starts_with("$argon2id$"), "{stored}");
        assert!(verify_password(&stored, "correct horse battery staple"));
        assert!(!verify_password(&stored, "correct horse battery stapl"));
        assert!(!verify_password(&stored, ""));
        assert!(!verify_password(
            "not a hash",
            "correct horse battery staple"
        ));
        assert!(
            !stored.contains("correct horse"),
            "the password is not in the hash"
        );
        let again = hash_password("correct horse battery staple").unwrap();
        assert_ne!(stored, again, "a fresh salt every time");
    }

    #[test]
    fn new_passwords_are_bounded() {
        assert_eq!(check_new(&"x".repeat(11)), Err(PasswordError::TooShort));
        assert_eq!(check_new(&"x".repeat(12)), Ok(()));
        assert_eq!(check_new(&"x".repeat(256)), Ok(()));
        assert_eq!(check_new(&"x".repeat(257)), Err(PasswordError::TooLong));
        assert_eq!(check_new(&"é".repeat(12)), Ok(()), "counted in characters");
        assert_eq!(dummy_hash(), dummy_hash());
        assert!(!verify_password(dummy_hash(), "not that password"));
        let generated = new_password().unwrap();
        assert!(check_new(&generated).is_ok(), "{generated}");
        assert!(generated.contains('-'));
        assert_eq!(generated.len(), 29);
        assert_ne!(new_password().unwrap(), generated);
    }
}
