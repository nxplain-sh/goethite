//! The bootstrap configuration file.
//!
//! TOML is only for bootstrapping a node; once the replicated config store
//! exists it becomes the source of truth. Unknown keys are rejected so a typo
//! never silently falls back to a default.

use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use goethite_resolver::{
    BlockResponse, CacheConfig, MAX_ENTRIES, MAX_UPSTREAMS, Transport, UpstreamConfig,
};
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
    /// The `[cache]` table.
    #[serde(default)]
    pub cache: CacheSection,
    /// The `[filter]` table.
    #[serde(default)]
    pub filter: FilterSection,
}

/// The most `[[filter.list]]` tables accepted.
const MAX_LISTS: usize = 64;

/// The most inline `filter.rules` accepted.
const MAX_INLINE_RULES: usize = 10_000;

/// The `[filter]` table.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct FilterSection {
    /// Whether filtering is on at all.
    pub enabled: bool,
    /// How blocked names are answered.
    pub block_response: BlockResponseSetting,
    /// Time to live of the `0.0.0.0` / `::` records for blocked names.
    pub blocked_ttl: u32,
    /// Rules written directly in the config, in any supported syntax.
    pub rules: Vec<String>,
    /// The `[[filter.list]]` tables: rule list files and URLs.
    pub list: Vec<ListSection>,
    /// Where downloaded lists are kept. Required if any list has a `url`.
    pub cache_dir: Option<PathBuf>,
    /// How often downloaded lists are refreshed, in hours.
    pub update_hours: u32,
}

impl Default for FilterSection {
    fn default() -> Self {
        Self {
            enabled: true,
            block_response: BlockResponseSetting::default(),
            blocked_ttl: 10,
            rules: Vec::new(),
            list: Vec::new(),
            cache_dir: None,
            update_hours: 24,
        }
    }
}

impl FilterSection {
    fn validate(&self) -> Result<()> {
        if self.list.len() > MAX_LISTS {
            bail!(
                "{} filter lists configured; at most {MAX_LISTS} are supported",
                self.list.len()
            );
        }
        if self.rules.len() > MAX_INLINE_RULES {
            bail!(
                "{} inline filter rules; at most {MAX_INLINE_RULES} are supported (use a list file)",
                self.rules.len()
            );
        }
        if self.blocked_ttl > MAX_NEGATIVE_TTL_LIMIT {
            bail!(
                "filter.blocked_ttl is {}; at most {MAX_NEGATIVE_TTL_LIMIT} is supported",
                self.blocked_ttl
            );
        }
        if !(1..=168).contains(&self.update_hours) {
            bail!(
                "filter.update_hours is {}; it must be between 1 and 168 (a week)",
                self.update_hours
            );
        }
        for (index, list) in self.list.iter().enumerate() {
            let number = index.saturating_add(1);
            match (&list.path, &list.url) {
                (Some(_), Some(_)) => {
                    bail!("[[filter.list]] number {number} has both path and url")
                }
                (None, None) => bail!("[[filter.list]] number {number} needs a path or a url"),
                (None, Some(url)) => {
                    crate::download::https_uri(url)
                        .with_context(|| format!("[[filter.list]] number {number}"))?;
                }
                (Some(_), None) => {}
            }
        }
        if self.cache_dir.is_none() && self.list.iter().any(|list| list.url.is_some()) {
            bail!("filter.cache_dir is required to download lists from a url");
        }
        Ok(())
    }

    /// Makes relative paths relative to `base`, the config file's directory.
    fn resolve_paths(&mut self, base: &Path) {
        let resolve = |path: &mut PathBuf| {
            if path.is_relative() {
                *path = base.join(&*path);
            }
        };
        if let Some(dir) = &mut self.cache_dir {
            resolve(dir);
        }
        for list in &mut self.list {
            if let Some(path) = &mut list.path {
                resolve(path);
            }
        }
    }
}

/// One `[[filter.list]]` table: exactly one of `path` and `url`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ListSection {
    /// A local list file (hosts, domains or AdGuard syntax, mixed freely).
    pub path: Option<PathBuf>,
    /// An `https://` URL to download the list from, every `update_hours`.
    pub url: Option<String>,
}

/// `filter.block_response`.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BlockResponseSetting {
    /// `0.0.0.0` / `::`, empty for other types.
    #[default]
    NullIp,
    /// `NXDOMAIN`.
    Nxdomain,
    /// `REFUSED`.
    Refused,
}

impl BlockResponseSetting {
    /// The resolver's view of this setting.
    pub fn to_block_response(self) -> BlockResponse {
        match self {
            Self::NullIp => BlockResponse::NullIp,
            Self::Nxdomain => BlockResponse::NxDomain,
            Self::Refused => BlockResponse::Refused,
        }
    }
}

/// The longest `max_ttl` accepted: one week.
const MAX_TTL_LIMIT: u32 = 7 * 86_400;

/// The longest `max_negative_ttl` accepted: one day.
const MAX_NEGATIVE_TTL_LIMIT: u32 = 86_400;

/// The `[cache]` table.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct CacheSection {
    /// Most cached answers; 0 turns the cache off.
    pub max_entries: usize,
    /// Keep positive answers at least this many seconds.
    pub min_ttl: u32,
    /// Keep positive answers at most this many seconds.
    pub max_ttl: u32,
    /// Keep negative answers (NXDOMAIN, NODATA) at most this many seconds.
    pub max_negative_ttl: u32,
}

impl Default for CacheSection {
    fn default() -> Self {
        let defaults = CacheConfig::default();
        Self {
            max_entries: defaults.max_entries,
            min_ttl: defaults.min_ttl,
            max_ttl: defaults.max_ttl,
            max_negative_ttl: defaults.max_negative_ttl,
        }
    }
}

impl CacheSection {
    /// The resolver's view of this table.
    pub fn to_cache_config(&self) -> CacheConfig {
        CacheConfig {
            max_entries: self.max_entries,
            min_ttl: self.min_ttl,
            max_ttl: self.max_ttl,
            max_negative_ttl: self.max_negative_ttl,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.max_entries > MAX_ENTRIES {
            bail!(
                "cache.max_entries is {}; at most {MAX_ENTRIES} is supported",
                self.max_entries
            );
        }
        if self.min_ttl > self.max_ttl {
            bail!(
                "cache.min_ttl ({}) is larger than cache.max_ttl ({})",
                self.min_ttl,
                self.max_ttl
            );
        }
        if self.max_ttl > MAX_TTL_LIMIT {
            bail!(
                "cache.max_ttl is {}; at most {MAX_TTL_LIMIT} (one week) is supported",
                self.max_ttl
            );
        }
        if self.max_negative_ttl > MAX_NEGATIVE_TTL_LIMIT {
            bail!(
                "cache.max_negative_ttl is {}; at most {MAX_NEGATIVE_TTL_LIMIT} (one day) is supported",
                self.max_negative_ttl
            );
        }
        Ok(())
    }
}

/// One `[[upstream]]` table: a resolver goethite forwards to.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpstreamSection {
    /// IP address, with an optional port (the protocol's standard port
    /// otherwise). Hostnames are not accepted: resolving them would need the
    /// resolver being configured.
    pub address: Address,
    /// How the upstream is reached.
    #[serde(default)]
    pub protocol: Protocol,
    /// For `tls`: the name the server's certificate must be valid for.
    pub tls_name: Option<String>,
    /// For `https`: the DoH query URL; its host is the certificate name.
    pub url: Option<String>,
    /// 0x20 case randomization of query names.
    #[serde(default = "enabled")]
    pub randomize_case: bool,
}

/// An upstream IP address with an optional port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    /// The IP address.
    pub ip: IpAddr,
    /// The port, if one was given.
    pub port: Option<u16>,
}

impl<'de> Deserialize<'de> for Address {
    /// Accepts `9.9.9.9`, `9.9.9.9:853`, `2620:fe::fe` and `[2620:fe::fe]:853`.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if let Ok(addr) = text.parse::<SocketAddr>() {
            return Ok(Self {
                ip: addr.ip(),
                port: Some(addr.port()),
            });
        }
        text.parse::<IpAddr>()
            .map(|ip| Self { ip, port: None })
            .map_err(|_| {
                serde::de::Error::custom(format!(
                    "{text:?} is not an IP address with an optional port"
                ))
            })
    }
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
    /// DNS over TLS (RFC 7858), port 853 by default.
    Tls,
    /// DNS over HTTPS (RFC 8484), port 443 by default.
    Https,
}

impl Protocol {
    fn default_port(self) -> u16 {
        match self {
            Self::Udp | Self::Tcp => 53,
            Self::Tls => 853,
            Self::Https => 443,
        }
    }
}

impl UpstreamSection {
    /// The resolver's view of this upstream. Call [`Self::validate`] first.
    pub fn to_upstream(&self) -> UpstreamConfig {
        let port = self
            .address
            .port
            .unwrap_or_else(|| self.protocol.default_port());
        UpstreamConfig {
            address: SocketAddr::new(self.address.ip, port),
            transport: match self.protocol {
                Protocol::Udp => Transport::Udp,
                Protocol::Tcp => Transport::Tcp,
                Protocol::Tls => Transport::Tls {
                    server_name: self.tls_name.clone().unwrap_or_default(),
                },
                Protocol::Https => Transport::Https {
                    url: self.url.clone().unwrap_or_default(),
                },
            },
            randomize_case: self.randomize_case,
        }
    }

    /// Checks that `tls_name` and `url` are given exactly where they belong.
    fn validate(&self) -> Result<()> {
        match (self.protocol, &self.tls_name, &self.url) {
            (Protocol::Tls, None, _) => bail!("protocol \"tls\" needs tls_name"),
            (Protocol::Https, _, None) => bail!("protocol \"https\" needs url"),
            (Protocol::Udp | Protocol::Tcp | Protocol::Https, Some(_), _) => {
                bail!("tls_name only applies to protocol \"tls\"")
            }
            (Protocol::Udp | Protocol::Tcp | Protocol::Tls, _, Some(_)) => {
                bail!("url only applies to protocol \"https\"")
            }
            _ => Ok(()),
        }
    }
}

fn enabled() -> bool {
    true
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
        config
            .cache
            .validate()
            .and_then(|()| config.filter.validate())
            .with_context(|| format!("invalid config file {}", path.display()))?;
        let mut config = config;
        if let Some(base) = path.parent() {
            config.filter.resolve_paths(base);
        }
        if config.upstream.len() > MAX_UPSTREAMS {
            bail!(
                "{} lists {} upstreams; at most {MAX_UPSTREAMS} are supported",
                path.display(),
                config.upstream.len()
            );
        }
        for (index, upstream) in config.upstream.iter().enumerate() {
            upstream.validate().with_context(|| {
                format!(
                    "invalid [[upstream]] number {} in {}",
                    index.saturating_add(1),
                    path.display()
                )
            })?;
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
        let first = config.upstream[0].to_upstream();
        assert_eq!(first.address, "9.9.9.9:853".parse().unwrap());
        assert_eq!(
            first.transport,
            Transport::Tls {
                server_name: "dns.quad9.net".into()
            }
        );
        assert!(config.upstream.iter().all(|u| u.validate().is_ok()));
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

            [[upstream]]
            address = "9.9.9.9"
            protocol = "tls"
            tls_name = "dns.quad9.net"

            [[upstream]]
            address = "149.112.112.112:8443"
            protocol = "https"
            url = "https://dns.quad9.net/dns-query"
            "#,
        )
        .unwrap();
        let upstreams: Vec<_> = config
            .upstream
            .iter()
            .map(UpstreamSection::to_upstream)
            .collect();
        assert!(config.upstream.iter().all(|u| u.validate().is_ok()));
        assert_eq!(upstreams[0].address, "9.9.9.9:53".parse().unwrap());
        assert_eq!(upstreams[0].transport, Transport::Udp);
        assert!(upstreams[0].randomize_case);
        assert_eq!(upstreams[1].address, "[2620:fe::fe]:5353".parse().unwrap());
        assert_eq!(upstreams[1].transport, Transport::Tcp);
        assert!(!upstreams[1].randomize_case);
        assert_eq!(upstreams[2].address, "9.9.9.9:853".parse().unwrap());
        assert_eq!(
            upstreams[2].transport,
            Transport::Tls {
                server_name: "dns.quad9.net".into()
            }
        );
        assert_eq!(
            upstreams[3].address,
            "149.112.112.112:8443".parse().unwrap()
        );
        assert_eq!(
            upstreams[3].transport,
            Transport::Https {
                url: "https://dns.quad9.net/dns-query".into()
            }
        );
    }

    #[test]
    fn tls_name_and_url_belong_to_their_protocols() {
        for bad in [
            "protocol = \"tls\"",
            "protocol = \"https\"",
            "tls_name = \"dns.quad9.net\"",
            "url = \"https://dns.quad9.net/dns-query\"",
            "protocol = \"tls\"\nurl = \"https://dns.quad9.net/dns-query\"\ntls_name = \"x\"",
            "protocol = \"https\"\ntls_name = \"x\"\nurl = \"https://x/\"",
        ] {
            let config =
                Config::parse(&format!("[[upstream]]\naddress = \"9.9.9.9\"\n{bad}")).unwrap();
            assert!(config.upstream[0].validate().is_err(), "{bad}");
        }
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
    fn cache_settings() {
        let config = Config::parse("[cache]\nmax_entries = 500\nmax_ttl = 600").unwrap();
        assert_eq!(config.cache.max_entries, 500);
        assert_eq!(config.cache.max_ttl, 600);
        assert_eq!(
            config.cache.max_negative_ttl, 3_600,
            "unset keys keep their default"
        );
        assert!(config.cache.validate().is_ok());
        assert_eq!(Config::parse("").unwrap().cache, CacheSection::default());
        assert!(Config::parse("[cache]\nmax_entires = 1").is_err());

        for bad in [
            "max_entries = 1000001",
            "min_ttl = 600\nmax_ttl = 60",
            "max_ttl = 604801",
            "max_negative_ttl = 86401",
        ] {
            let config = Config::parse(&format!("[cache]\n{bad}")).unwrap();
            assert!(config.cache.validate().is_err(), "{bad}");
        }
    }

    #[test]
    fn filter_settings() {
        let config = Config::parse(
            r#"
            [filter]
            block_response = "nxdomain"
            rules = ["||ads.example^", "@@||ok.ads.example^"]

            [[filter.list]]
            path = "/var/lib/goethite/lists/hosts.txt"
            "#,
        )
        .unwrap();
        assert!(config.filter.enabled);
        assert_eq!(
            config.filter.block_response.to_block_response(),
            BlockResponse::NxDomain
        );
        assert_eq!(config.filter.blocked_ttl, 10);
        assert_eq!(config.filter.rules.len(), 2);
        assert_eq!(
            config.filter.list[0].path,
            Some(PathBuf::from("/var/lib/goethite/lists/hosts.txt"))
        );
        assert!(config.filter.validate().is_ok());
        assert_eq!(config.filter.update_hours, 24);
        assert!(Config::parse("[filter]\nblock_response = \"blackhole\"").is_err());
        let not_https = Config::parse("[[filter.list]]\nurl = \"x\"").unwrap();
        assert!(not_https.filter.validate().is_err());
        assert!(Config::parse("[[filter.list]]\nlink = \"x\"").is_err());
        let ttl = Config::parse("[filter]\nblocked_ttl = 999999").unwrap();
        assert!(ttl.filter.validate().is_err());
    }

    #[test]
    fn list_sources() {
        let config = Config::parse(
            r#"
            [filter]
            cache_dir = "lists"
            update_hours = 12

            [[filter.list]]
            url = "https://lists.example/hosts"

            [[filter.list]]
            path = "local.txt"
            "#,
        )
        .unwrap();
        assert!(config.filter.validate().is_ok());
        let mut filter = config.filter.clone();
        filter.resolve_paths(Path::new("/etc/goethite"));
        assert_eq!(filter.cache_dir, Some(PathBuf::from("/etc/goethite/lists")));
        assert_eq!(
            filter.list[1].path,
            Some(PathBuf::from("/etc/goethite/local.txt"))
        );

        for bad in [
            "[[filter.list]]\nurl = \"https://lists.example/hosts\"",
            "[filter]\ncache_dir = \"c\"\n[[filter.list]]\nurl = \"http://lists.example/hosts\"",
            "[filter]\ncache_dir = \"c\"\n[[filter.list]]\nurl = \"https://x/\"\npath = \"y\"",
            "[filter]\ncache_dir = \"c\"\n[[filter.list]]",
            "[filter]\nupdate_hours = 0",
            "[filter]\nupdate_hours = 169",
        ] {
            let config = Config::parse(bad).unwrap();
            assert!(config.filter.validate().is_err(), "{bad}");
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
