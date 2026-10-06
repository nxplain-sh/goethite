//! Domain names.

use std::fmt;
use std::str::FromStr;

/// An absolute (fully qualified) domain name.
///
/// Every `Name` is valid on the wire: labels are 1 to 63 bytes and the encoded
/// name is at most 255 bytes. Equality and hashing ignore ASCII case, as DNS
/// requires; the original case is kept for display and re-encoding.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Name(pub(crate) hickory_proto::rr::Name);

/// Why a string or label sequence is not a valid [`Name`].
#[derive(Debug, thiserror::Error)]
#[error("invalid domain name: {reason}")]
pub struct NameError {
    reason: String,
}

impl NameError {
    fn new(err: &hickory_proto::ProtoError) -> Self {
        Self {
            reason: err.to_string(),
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
        let mut name =
            hickory_proto::rr::Name::from_labels(labels).map_err(|e| NameError::new(&e))?;
        name.set_fqdn(true);
        Ok(Self(name))
    }

    /// Returns `true` for the root name.
    pub fn is_root(&self) -> bool {
        self.0.is_root()
    }

    /// The number of labels, not counting the root.
    pub fn label_count(&self) -> u8 {
        self.0.num_labels()
    }
}

impl FromStr for Name {
    type Err = NameError;

    /// Parses a name in presentation format, e.g. `goethite.test.`.
    ///
    /// Only letters, digits, `-` and `_` are accepted in labels; the name is
    /// treated as absolute whether or not it ends with a dot.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut name = hickory_proto::rr::Name::from_ascii(s).map_err(|e| NameError::new(&e))?;
        name.set_fqdn(true);
        Ok(Self(name))
    }
}

impl fmt::Display for Name {
    /// Writes the name in ASCII presentation format with a trailing dot.
    ///
    /// Bytes outside letters, digits, `-` and `_` are escaped (`\.` or `\DDD`),
    /// so names taken from the wire cannot inject control characters or
    /// newlines into logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_ascii())
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
        assert!("bad label.test.".parse::<Name>().is_err());
        assert!(format!("{}.test.", "a".repeat(64)).parse::<Name>().is_err());
        assert!(Name::from_labels([&b""[..]]).is_err());
        let long = [&[b'a'; 63][..]; 4];
        assert!(Name::from_labels(long).is_err());
    }

    #[test]
    fn display_escapes_unsafe_bytes() {
        let name = Name::from_labels([&b"evil\nlog"[..], b"te.st"]).unwrap();
        let shown = name.to_string();
        assert!(!shown.contains('\n'));
        assert_eq!(shown, "evil\\012log.te\\.st.");
    }

    #[test]
    fn root() {
        assert!(Name::root().is_root());
        assert_eq!(Name::root().to_string(), ".");
        assert_eq!(Name::from_labels([]).unwrap(), Name::root());
    }
}
