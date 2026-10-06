//! The bootstrap configuration file.
//!
//! TOML is only for bootstrapping a node; once the replicated config store
//! exists it becomes the source of truth. Unknown keys are rejected so a typo
//! never silently falls back to a default.

use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

/// Config files larger than this many bytes are rejected.
const MAX_CONFIG_LEN: usize = 1024 * 1024;

/// The whole configuration file.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The `[server]` table.
    #[serde(default)]
    pub server: ServerSection,
}

/// The `[server]` table.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    /// Address for DNS over UDP and TCP.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            listen: default_listen(),
        }
    }
}

/// Development default: an unprivileged port on loopback, so no root is needed.
/// Not 5353, which is multicast DNS (mDNSResponder, Avahi) on most desktops.
fn default_listen() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 15353))
}

impl Config {
    /// Reads and parses the configuration file at `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("cannot open config file {}", path.display()))?;
        let limit = u64::try_from(MAX_CONFIG_LEN)?.saturating_add(1);
        let mut text = String::new();
        let len = file
            .take(limit)
            .read_to_string(&mut text)
            .with_context(|| format!("cannot read config file {}", path.display()))?;
        if len > MAX_CONFIG_LEN {
            bail!(
                "config file {} is larger than {MAX_CONFIG_LEN} bytes",
                path.display()
            );
        }
        Self::parse(&text).with_context(|| format!("invalid config file {}", path.display()))
    }

    /// Parses configuration from TOML text.
    pub fn parse(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_is_valid() {
        let example = include_str!("../../../config/goethite.example.toml");
        let config = Config::parse(example).unwrap();
        assert_eq!(config.server.listen, "127.0.0.1:15353".parse().unwrap());
    }

    #[test]
    fn everything_has_a_default() {
        assert_eq!(Config::parse("").unwrap(), Config::default());
        assert_eq!(Config::parse("[server]").unwrap(), Config::default());
    }

    #[test]
    fn listen_accepts_ipv6() {
        let config = Config::parse("[server]\nlisten = \"[::1]:53\"").unwrap();
        assert_eq!(config.server.listen, "[::1]:53".parse().unwrap());
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = Config::parse("[server]\nlisen = \"127.0.0.1:53\"").unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
        assert!(Config::parse("[sever]").is_err());
    }

    #[test]
    fn bad_addresses_are_rejected() {
        assert!(Config::parse("[server]\nlisten = \"localhost:53\"").is_err());
        assert!(Config::parse("[server]\nlisten = \"127.0.0.1\"").is_err());
        assert!(Config::parse("[server]\nlisten = 53").is_err());
    }

    #[test]
    fn oversized_files_are_rejected() {
        let path = std::env::temp_dir().join(format!("goethite-big-{}.toml", std::process::id()));
        std::fs::write(&path, "#".repeat(MAX_CONFIG_LEN + 1)).unwrap();
        let err = Config::load(&path).unwrap_err();
        std::fs::remove_file(&path).unwrap();
        assert!(err.to_string().contains("larger than"), "{err:#}");
    }
}
