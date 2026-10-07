//! The bootstrap configuration file.
//!
//! TOML is only for bootstrapping a node; once the replicated config store
//! exists it becomes the source of truth. Unknown keys are rejected so a typo
//! never silently falls back to a default.

use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result, bail};
use goethite_resolver::{MAX_UPSTREAMS, Transport, UpstreamConfig};
use serde::{Deserialize, Deserializer};

/// Config files larger than this many bytes are rejected.
const MAX_CONFIG_LEN: usize = 1024 * 1024;

/// The whole configuration file.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The `[server]` table.
    #[serde(default)]
    pub server: ServerSection,
    /// The `[[upstream]]` tables, in order of preference.
    #[serde(default)]
    pub upstream: Vec<UpstreamSection>,
}

/// One `[[upstream]]` table: a resolver goethite forwards to.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpstreamSection {
    /// IP address, with an optional port (default 53). Hostnames are not
    /// accepted: resolving them would need the resolver being configured.
    #[serde(deserialize_with = "address_with_default_port")]
    pub address: SocketAddr,
    /// How the upstream is reached.
    #[serde(default)]
    pub protocol: Protocol,
    /// 0x20 case randomization of query names.
    #[serde(default = "enabled")]
    pub randomize_case: bool,
}

/// The `protocol` of an upstream.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// Plain DNS over UDP, retried over TCP when the answer is truncated.
    #[default]
    Udp,
    /// Plain DNS over TCP only.
    Tcp,
}

impl UpstreamSection {
    /// The resolver's view of this upstream.
    pub fn to_upstream(&self) -> UpstreamConfig {
        UpstreamConfig {
            address: self.address,
            transport: match self.protocol {
                Protocol::Udp => Transport::Udp,
                Protocol::Tcp => Transport::Tcp,
            },
            randomize_case: self.randomize_case,
        }
    }
}

fn enabled() -> bool {
    true
}

/// Accepts `9.9.9.9`, `9.9.9.9:53`, `2620:fe::fe` and `[2620:fe::fe]:53`.
fn address_with_default_port<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<SocketAddr, D::Error> {
    let text = String::deserialize(deserializer)?;
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Ok(addr);
    }
    text.parse::<IpAddr>()
        .map(|ip| SocketAddr::new(ip, 53))
        .map_err(|_| {
            serde::de::Error::custom(format!(
                "{text:?} is not an IP address with an optional port"
            ))
        })
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
        let config = Self::parse(&text)
            .with_context(|| format!("invalid config file {}", path.display()))?;
        if config.upstream.is_empty() {
            bail!(
                "no upstream resolvers configured in {}: add at least one [[upstream]] table, \
                 for example\n\n[[upstream]]\naddress = \"9.9.9.9\"",
                path.display()
            );
        }
        if config.upstream.len() > MAX_UPSTREAMS {
            bail!(
                "{} lists {} upstreams; at most {MAX_UPSTREAMS} are supported",
                path.display(),
                config.upstream.len()
            );
        }
        Ok(config)
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
        assert_eq!(config.upstream.len(), 2);
        assert_eq!(config.upstream[0].address, "9.9.9.9:53".parse().unwrap());
    }

    #[test]
    fn upstreams() {
        let config = Config::parse(
            r#"
            [[upstream]]
            address = "9.9.9.9"

            [[upstream]]
            address = "[2620:fe::fe]:5353"
            protocol = "tcp"
            randomize_case = false
            "#,
        )
        .unwrap();
        let [first, second] = &config.upstream[..] else {
            panic!("two upstreams expected");
        };
        assert_eq!(first.address, "9.9.9.9:53".parse().unwrap());
        assert_eq!(first.protocol, Protocol::Udp);
        assert!(first.randomize_case);
        assert_eq!(second.address, "[2620:fe::fe]:5353".parse().unwrap());
        assert_eq!(second.to_upstream().transport, Transport::Tcp);
        assert!(!second.randomize_case);
    }

    #[test]
    fn bad_upstreams_are_rejected() {
        for bad in [
            "[[upstream]]\naddress = \"dns.quad9.net\"",
            "[[upstream]]\naddress = \"9.9.9.9\"\nprotocol = \"quic\"",
            "[[upstream]]\naddres = \"9.9.9.9\"",
            "[[upstream]]",
        ] {
            assert!(Config::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn missing_upstreams_are_an_error_when_loading() {
        let path = std::env::temp_dir().join(format!("goethite-none-{}.toml", std::process::id()));
        std::fs::write(&path, "[server]\n").unwrap();
        let err = Config::load(&path).unwrap_err();
        std::fs::remove_file(&path).unwrap();
        assert!(err.to_string().contains("no upstream resolvers"), "{err:#}");
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
