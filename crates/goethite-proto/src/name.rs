//! Domain names.

use std::fmt::{self, Write as _};
use std::str::FromStr;

use crate::codec::Escaped;

/// An absolute (fully qualified) domain name.
///
/// Every `Name` is valid on the wire: labels are 1 to 63 bytes and the encoded
/// name is at most 255 bytes. Equality and hashing ignore ASCII case, as DNS
/// requires; the original case is kept for display and re-encoding.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Name(pub(crate) hickory_proto::rr::Name);

/// Why a string or label sequence is not a valid [`Name`].
#[derive(Debug, thiserror::Error)]
#[error("invalid domain name: {}", Escaped(.reason))]
pub struct NameError {
    reason: String,
}

impl NameError {
    fn new(reason: impl fmt::Display) -> Self {
        Self {
            reason: reason.to_string(),
        }
    }
}

impl Name {
    /// The root name, `.`.
    pub fn root() -> Self {
        Self(hickory_proto::rr::Name::root())
    }

    /// Builds a name from raw labels, most specific first, without the root.
    ///
    /// Labels may contain any bytes, as on the wire.
    ///
    /// # Errors
    ///
    /// Returns [`NameError`] if a label is empty or longer than 63 bytes, or
    /// the whole name is longer than 255 bytes.
    pub fn from_labels<'a, I>(labels: I) -> Result<Self, NameError>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let mut name = hickory_proto::rr::Name::from_labels(labels).map_err(NameError::new)?;
        name.set_fqdn(true);
        Ok(Self(name))
    }

    /// Returns `true` for the root name.
    pub fn is_root(&self) -> bool {
        self.0.is_root()
    }

    /// Whether both names are equal including the case of every letter.
    pub fn eq_exact(&self, other: &Name) -> bool {
        self.0.eq_case(&other.0)
    }

    /// A copy with the case of each letter flipped when `flip` returns true.
    ///
    /// Used for 0x20 randomization (draft-vixie-dnsext-dns0x20): the upstream
    /// must echo the exact case, which an off-path attacker cannot guess.
    #[must_use]
    pub fn with_random_case(&self, mut flip: impl FnMut() -> bool) -> Name {
        let labels: Vec<Vec<u8>> = self
            .0
            .iter()
            .map(|label| {
                label
                    .iter()
                    .map(|&b| match b {
                        b'a'..=b'z' if flip() => b.to_ascii_uppercase(),
                        b'A'..=b'Z' if flip() => b.to_ascii_lowercase(),
                        _ => b,
                    })
                    .collect()
            })
            .collect();
        // Same label lengths as `self`, so this cannot fail.
        Self::from_labels(labels.iter().map(Vec::as_slice)).unwrap_or_else(|_| self.clone())
    }

    /// The number of labels, not counting the root.
    pub fn label_count(&self) -> usize {
        // Not hickory's `num_labels`, which leaves out a leading `*`.
        self.0.iter().count()
    }
}

impl FromStr for Name {
    type Err = NameError;

    /// Parses a host-style name such as `goethite.test.`.
    ///
    /// Labels may contain only ASCII letters, digits, `-` and `_`; escapes and
    /// wildcards are rejected. The trailing dot is optional (the name is
    /// always absolute), `.` is the root and the empty string is an error.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "." {
            return Ok(Self::root());
        }
        let relative = s.strip_suffix('.').unwrap_or(s);
        if relative.is_empty() {
            return Err(NameError::new("empty name"));
        }
        let mut labels = Vec::new();
        for label in relative.split('.') {
            if label.is_empty() {
                return Err(NameError::new(format!("empty label in {s:?}")));
            }
            if !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(NameError::new(format!(
                    "label {label:?} may only contain letters, digits, '-' and '_'"
                )));
            }
            labels.push(label.as_bytes());
        }
        Self::from_labels(labels)
    }
}

impl fmt::Display for Name {
    /// Writes the name in RFC 1035 presentation format with a trailing dot.
    ///
    /// Letters, digits, `-` and `_` are written as they are, other printable
    /// ASCII as `\c`, and every other byte as a decimal `\DDD` escape, so names
    /// taken from the wire cannot inject control characters or newlines into
    /// logs. The output reads back the same way in `dig` and zone files.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return f.write_char('.');
        }
        for label in &self.0 {
            for &byte in label {
                match byte {
                    b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' => {
                        f.write_char(char::from(byte))?;
                    }
                    0x21..=0x7e => {
                        f.write_char('\\')?;
                        f.write_char(char::from(byte))?;
                    }
                    _ => write!(f, "\\{byte:03}")?,
                }
            }
            f.write_char('.')?;
        }
        Ok(())
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_absolute_and_relative_forms_as_absolute() {
        let a: Name = "goethite.test.".parse().unwrap();
        let b: Name = "goethite.test".parse().unwrap();
        assert_eq!(a, b);
        assert_eq!(a.to_string(), "goethite.test.");
        assert_eq!(a.label_count(), 2);
        assert_eq!("_dns.x-1.test".parse::<Name>().unwrap().label_count(), 3);
    }

    #[test]
    fn equality_ignores_ascii_case_but_display_keeps_it() {
        let a: Name = "GoEtHiTe.TeSt.".parse().unwrap();
        let b: Name = "goethite.test.".parse().unwrap();
        assert_eq!(a, b);
        assert_eq!(a.to_string(), "GoEtHiTe.TeSt.");
    }

    #[test]
    fn rejects_invalid_names() {
        for bad in [
            "",
            "..",
            "a..test",
            ".test",
            "bad label.test.",
            "*.test",
            "a\\.b.test",
            "\\065.test",
            "caf\u{e9}.test",
        ] {
            assert!(bad.parse::<Name>().is_err(), "{bad:?}");
        }
        assert!(format!("{}.test.", "a".repeat(64)).parse::<Name>().is_err());
        assert!(Name::from_labels([&b""[..]]).is_err());
        let long = [&[b'a'; 63][..]; 4];
        assert!(Name::from_labels(long).is_err());
    }

    #[test]
    fn display_uses_rfc1035_decimal_escapes() {
        let name = Name::from_labels([&b"evil\nlog"[..], b"te.st", b"\xff \\"]).unwrap();
        let shown = name.to_string();
        assert_eq!(shown, "evil\\010log.te\\.st.\\255\\032\\\\.");
        assert!(shown.chars().all(|c| c.is_ascii_graphic()));
    }

    #[test]
    fn error_text_is_escaped() {
        let err = "evil\n\u{1b}[31m.test".parse::<Name>().unwrap_err();
        let shown = err.to_string();
        assert!(
            shown.chars().all(|c| c == ' ' || c.is_ascii_graphic()),
            "{shown}"
        );
    }

    #[test]
    fn exact_equality_and_case_randomization() {
        let name: Name = "goethite.test.".parse().unwrap();
        let upper = name.with_random_case(|| true);
        assert_eq!(upper.to_string(), "GOETHITE.TEST.");
        assert_eq!(upper, name);
        assert!(!upper.eq_exact(&name));
        assert!(name.with_random_case(|| false).eq_exact(&name));
        let mut toggle = false;
        let mixed = name.with_random_case(|| {
            toggle = !toggle;
            toggle
        });
        assert_eq!(mixed.to_string(), "GoEtHiTe.TeSt.");
    }

    #[test]
    fn label_count_includes_wildcards() {
        let name = Name::from_labels([&b"*"[..], b"goethite", b"test"]).unwrap();
        assert_eq!(name.label_count(), 3);
    }

    #[test]
    fn root() {
        assert!(Name::root().is_root());
        assert_eq!(Name::root().to_string(), ".");
        assert_eq!(".".parse::<Name>().unwrap(), Name::root());
        assert_eq!(Name::from_labels([]).unwrap(), Name::root());
    }
}
