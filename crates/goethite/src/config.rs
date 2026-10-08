//! The bootstrap configuration file.
//!
//! TOML is only for bootstrapping a node; once the replicated config store
//! exists it becomes the source of truth. Unknown keys are rejected so a typo
//! never silently falls back to a default.

use std::collections::HashSet;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use goethite_filter::{LineKind, parse_line};
use goethite_proto::Name;
use goethite_resolver::{
    CacheConfig, DEFAULT_PRIVATE_DOMAINS, MAX_ENTRIES, MAX_UPSTREAMS, RebindingProtection,
    Transport, UpstreamConfig,
};
use goethite_server::{
    MAX_LISTEN_ADDRESSES, MAX_RATE_LIMITED_CLIENTS, MAX_UDP_SOCKETS, RateLimitConfig, ServerConfig,
};
use goethite_store::{
    BlockResponseKind, Import, ListSpec, ManagedBy, QueryLogConfig, RuleSpec, SettingsSpec,
    model::MAX_NAME_LEN,
};
use serde::de::{self, SeqAccess, Visitor};
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
    /// The `[security]` table.
    #[serde(default)]
    pub security: SecuritySection,
    /// The `[store]` table.
    #[serde(default)]
    pub store: StoreSection,
    /// The `[querylog]` table.
    #[serde(default)]
    pub querylog: QueryLogSection,
    /// The absolute directory of the config file, which relative paths are
    /// relative to. Set by [`Config::load`].
    #[serde(skip)]
    pub dir: PathBuf,
}

/// The `[querylog]` table.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct QueryLogSection {
    /// Whether queries are logged. Statistics are kept either way.
    pub enabled: bool,
    /// How long entries are kept, in days.
    pub retention_days: u32,
    /// The most entries kept.
    pub max_entries: u64,
    /// Whether client addresses are shortened to /24 or /56.
    pub anonymize_clients: bool,
}

impl Default for QueryLogSection {
    fn default() -> Self {
        let defaults = QueryLogConfig::default();
        Self {
            enabled: defaults.enabled,
            retention_days: 7,
            max_entries: defaults.max_entries,
            anonymize_clients: defaults.anonymize,
        }
    }
}

impl QueryLogSection {
    fn validate(&self) -> Result<()> {
        if !(1..=365).contains(&self.retention_days) {
            bail!("querylog.retention_days must be between 1 and 365");
        }
        if !(1_000..=50_000_000).contains(&self.max_entries) {
            bail!("querylog.max_entries must be between 1000 and 50000000");
        }
        Ok(())
    }

    /// The store's view of this table.
    pub fn to_config(&self) -> QueryLogConfig {
        QueryLogConfig {
            enabled: self.enabled,
            retention: std::time::Duration::from_hours(
                u64::from(self.retention_days).saturating_mul(24),
            ),
            max_entries: self.max_entries,
            anonymize: self.anonymize_clients,
        }
    }
}

/// The `[store]` table.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct StoreSection {
    /// The database file. Defaults to `goethite.redb` in the state
    /// directory.
    pub path: Option<PathBuf>,
}

impl Config {
    /// Where goethite keeps its state: systemd's `STATE_DIRECTORY` (the
    /// unit's `StateDirectory=`) if set, otherwise the config file's
    /// directory.
    pub fn state_dir(&self) -> PathBuf {
        std::env::var_os("STATE_DIRECTORY")
            .and_then(|dirs| {
                std::env::split_paths(&dirs)
                    .next()
                    .filter(|dir| dir.is_absolute())
            })
            .unwrap_or_else(|| self.dir.clone())
    }

    /// The store's database file.
    pub fn store_path(&self) -> PathBuf {
        self.store
            .path
            .clone()
            .unwrap_or_else(|| self.state_dir().join("goethite.redb"))
    }

    /// Where downloaded lists are kept.
    pub fn lists_dir(&self) -> PathBuf {
        self.filter
            .cache_dir
            .clone()
            .unwrap_or_else(|| self.state_dir().join("lists"))
    }
}

/// The `[security]` table.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct SecuritySection {
    /// Remove private addresses from answers for public names.
    pub rebinding_protection: bool,
    /// Names below these may resolve to private addresses.
    pub private_domains: Vec<String>,
}

impl Default for SecuritySection {
    fn default() -> Self {
        Self {
            rebinding_protection: true,
            private_domains: DEFAULT_PRIVATE_DOMAINS
                .iter()
                .map(|&domain| domain.to_owned())
                .collect(),
        }
    }
}

impl SecuritySection {
    /// The resolver's rebinding protection, if it is on.
    pub fn rebinding_protection(&self) -> Result<Option<RebindingProtection>> {
        if !self.rebinding_protection {
            return Ok(None);
        }
        let domains = self
            .private_domains
            .iter()
            .map(|domain| {
                domain
                    .parse::<Name>()
                    .with_context(|| format!("security.private_domains: {domain:?}"))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(RebindingProtection::new(domains)))
    }
}

/// The most `[[filter.list]]` tables accepted: the filter tells 64 sources
/// apart, and the config rules take one.
const MAX_LISTS: usize = 63;

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
        // Rules typed into the config are checked strictly: a typo here is an
        // error, not a skipped line as in a third-party list.
        for rule in &self.rules {
            match parse_line(rule, |_| {}) {
                LineKind::Rules(_) | LineKind::Ignored => {}
                LineKind::Unsupported(reason) => {
                    bail!("filter.rules: {rule:?} is not supported yet ({reason})")
                }
                LineKind::Invalid(reason) => {
                    bail!("filter.rules: {rule:?} is not a valid rule ({reason})")
                }
            }
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
        Ok(())
    }

    /// The table as resources to import into the store: config rules and
    /// lists become resources managed by the config file.
    pub fn to_import(&self) -> Import {
        let lists = self
            .list
            .iter()
            .filter_map(|list| {
                let (url, path) = match (&list.url, &list.path) {
                    (Some(url), _) => (Some(url.clone()), None),
                    (None, Some(path)) => (None, Some(path.display().to_string())),
                    (None, None) => return None,
                };
                let name = url.clone().unwrap_or_else(|| {
                    list.path
                        .as_ref()
                        .and_then(|path| path.file_name())
                        .map(|name| name.to_string_lossy().into_owned())
                        .unwrap_or_default()
                });
                Some(ListSpec {
                    name: name.chars().take(MAX_NAME_LEN).collect(),
                    url,
                    path,
                    enabled: true,
                    comment: String::new(),
                    managed_by: ManagedBy::ConfigFile,
                })
            })
            .collect();
        let rules = self
            .rules
            .iter()
            .filter(|rule| matches!(parse_line(rule, |_| {}), LineKind::Rules(_)))
            .map(|rule| RuleSpec {
                rule: rule.clone(),
                enabled: true,
                comment: String::new(),
                managed_by: ManagedBy::ConfigFile,
            })
            .collect();
        Import {
            settings: SettingsSpec {
                protection: self.enabled,
                block_response: match self.block_response {
                    BlockResponseSetting::NullIp => BlockResponseKind::NullIp,
                    BlockResponseSetting::Nxdomain => BlockResponseKind::Nxdomain,
                    BlockResponseSetting::Refused => BlockResponseKind::Refused,
                },
                blocked_ttl: self.blocked_ttl,
                list_update_hours: self.update_hours,
            },
            lists,
            rules,
        }
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
                de::Error::custom(format!(
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

/// The most TCP connections that can be configured.
const MAX_TCP_CONNECTIONS_LIMIT: usize = 100_000;

/// The `[server]` table.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct ServerSection {
    /// Addresses for DNS over UDP and TCP: one, or a list.
    #[serde(deserialize_with = "listen_addresses")]
    pub listen: Vec<SocketAddr>,
    /// UDP sockets per listen address on Linux; one per CPU core if unset.
    pub udp_sockets: Option<usize>,
    /// Most TCP connections at once.
    pub max_tcp_connections: usize,
    /// Most TCP connections at once from one client.
    pub max_tcp_connections_per_client: usize,
    /// The `[server.rate_limit]` table.
    pub rate_limit: RateLimitSection,
    /// The user to switch to after binding, when started as root (Linux).
    pub user: Option<String>,
}

impl Default for ServerSection {
    fn default() -> Self {
        let defaults = ServerConfig::new(Vec::new());
        Self {
            // Development default: an unprivileged port on loopback, so no
            // root is needed. Not 5353, which is multicast DNS (mDNSResponder,
            // Avahi) on most desktops.
            listen: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 15353))],
            udp_sockets: None,
            max_tcp_connections: defaults.max_tcp_connections,
            max_tcp_connections_per_client: defaults.max_tcp_connections_per_client,
            rate_limit: RateLimitSection::default(),
            user: None,
        }
    }
}

impl ServerSection {
    fn validate(&self) -> Result<()> {
        if self.listen.is_empty() {
            bail!("server.listen is empty; give at least one address");
        }
        if self.listen.len() > MAX_LISTEN_ADDRESSES {
            bail!("server.listen has more than {MAX_LISTEN_ADDRESSES} addresses");
        }
        let mut seen = HashSet::new();
        if let Some(duplicate) = self.listen.iter().find(|addr| !seen.insert(**addr)) {
            bail!("server.listen has {duplicate} twice");
        }
        if let Some(sockets) = self.udp_sockets
            && !(1..=MAX_UDP_SOCKETS).contains(&sockets)
        {
            bail!("server.udp_sockets is {sockets}; it must be between 1 and {MAX_UDP_SOCKETS}");
        }
        if !(1..=MAX_TCP_CONNECTIONS_LIMIT).contains(&self.max_tcp_connections) {
            bail!(
                "server.max_tcp_connections is {}; it must be between 1 and {MAX_TCP_CONNECTIONS_LIMIT}",
                self.max_tcp_connections
            );
        }
        if !(1..=self.max_tcp_connections).contains(&self.max_tcp_connections_per_client) {
            bail!(
                "server.max_tcp_connections_per_client is {}; it must be between 1 and \
                 server.max_tcp_connections ({})",
                self.max_tcp_connections_per_client,
                self.max_tcp_connections
            );
        }
        if let Some(user) = &self.user
            && (user.is_empty() || user.contains([':', '\n']))
        {
            bail!("server.user {user:?} is not a valid user name");
        }
        self.rate_limit.validate()
    }

    /// The listener settings.
    pub fn to_server_config(&self) -> ServerConfig {
        let mut config = ServerConfig::new(self.listen.clone());
        if let Some(sockets) = self.udp_sockets {
            config.udp_sockets = sockets;
        }
        config.max_tcp_connections = self.max_tcp_connections;
        config.max_tcp_connections_per_client = self.max_tcp_connections_per_client;
        config.rate_limit = self.rate_limit.to_rate_limit_config();
        config
    }
}

/// Reads `listen`: one address, or a list of them.
fn listen_addresses<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<SocketAddr>, D::Error> {
    struct Addresses;

    fn parse<E: de::Error>(text: &str) -> Result<SocketAddr, E> {
        text.parse().map_err(|_| {
            E::custom(format!(
                "invalid listen address {text:?}: expected an IP address and a port, \
                 such as \"0.0.0.0:53\" or \"[::]:53\""
            ))
        })
    }

    impl<'de> Visitor<'de> for Addresses {
        type Value = Vec<SocketAddr>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an address such as \"0.0.0.0:53\", or a list of them")
        }

        fn visit_str<E: de::Error>(self, text: &str) -> Result<Self::Value, E> {
            parse(text).map(|addr| vec![addr])
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut addresses = Vec::new();
            while let Some(text) = seq.next_element::<String>()? {
                if addresses.len() >= MAX_LISTEN_ADDRESSES {
                    return Err(de::Error::custom(format!(
                        "at most {MAX_LISTEN_ADDRESSES} listen addresses are supported"
                    )));
                }
                addresses.push(parse(&text)?);
            }
            Ok(addresses)
        }
    }

    deserializer.deserialize_any(Addresses)
}

/// The `[server.rate_limit]` table.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct RateLimitSection {
    /// Average UDP queries per second per client network; 0 turns it off.
    pub queries_per_second: u32,
    /// Queries a client network may send at once.
    pub burst: u32,
    /// Every `slip`-th limited query gets a truncated answer; 0 for none.
    pub slip: u32,
    /// Leading bits of an IPv4 address that make a client network.
    pub ipv4_prefix: u8,
    /// Leading bits of an IPv6 address that make a client network.
    pub ipv6_prefix: u8,
    /// Client networks tracked at once.
    pub max_clients: usize,
}

impl Default for RateLimitSection {
    fn default() -> Self {
        let defaults = RateLimitConfig::default();
        Self {
            queries_per_second: defaults.queries_per_second,
            burst: defaults.burst,
            slip: defaults.slip,
            ipv4_prefix: defaults.ipv4_prefix,
            ipv6_prefix: defaults.ipv6_prefix,
            max_clients: defaults.max_clients,
        }
    }
}

impl RateLimitSection {
    fn validate(&self) -> Result<()> {
        const MAX_RATE: u32 = 1_000_000;
        if self.queries_per_second > MAX_RATE {
            bail!("server.rate_limit.queries_per_second is above {MAX_RATE}");
        }
        if self.burst == 0 || self.burst > MAX_RATE {
            bail!("server.rate_limit.burst must be between 1 and {MAX_RATE}");
        }
        if self.slip > 10 {
            bail!("server.rate_limit.slip must be between 0 and 10");
        }
        if !(8..=32).contains(&self.ipv4_prefix) {
            bail!("server.rate_limit.ipv4_prefix must be between 8 and 32");
        }
        if !(16..=128).contains(&self.ipv6_prefix) {
            bail!("server.rate_limit.ipv6_prefix must be between 16 and 128");
        }
        if !(16..=MAX_RATE_LIMITED_CLIENTS).contains(&self.max_clients) {
            bail!(
                "server.rate_limit.max_clients must be between 16 and {MAX_RATE_LIMITED_CLIENTS}"
            );
        }
        Ok(())
    }

    fn to_rate_limit_config(&self) -> RateLimitConfig {
        RateLimitConfig {
            queries_per_second: self.queries_per_second,
            burst: self.burst,
            slip: self.slip,
            ipv4_prefix: self.ipv4_prefix,
            ipv6_prefix: self.ipv6_prefix,
            max_clients: self.max_clients,
            ..RateLimitConfig::default()
        }
    }
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
            .server
            .validate()
            .and_then(|()| config.cache.validate())
            .and_then(|()| config.querylog.validate())
            .and_then(|()| config.filter.validate())
            .and_then(|()| config.security.rebinding_protection().map(drop))
            .with_context(|| format!("invalid config file {}", path.display()))?;
        let mut config = config;
        let base = path
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        config.dir = std::path::absolute(base)
            .with_context(|| format!("cannot resolve the directory of {}", path.display()))?;
        let dir = config.dir.clone();
        config.filter.resolve_paths(&dir);
        if let Some(store) = &mut config.store.path
            && store.is_relative()
        {
            *store = dir.join(&*store);
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
        assert_eq!(config.server.listen, ["127.0.0.1:15353".parse().unwrap()]);
        assert!(config.server.validate().is_ok());
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
        assert_eq!(config.filter.block_response, BlockResponseSetting::Nxdomain);
        let import = config.filter.to_import();
        assert_eq!(import.settings.block_response, BlockResponseKind::Nxdomain);
        assert_eq!(import.rules.len(), 2);
        assert_eq!(import.lists[0].name, "hosts.txt");
        assert_eq!(
            import.lists[0].path.as_deref(),
            Some("/var/lib/goethite/lists/hosts.txt")
        );
        assert!(
            import
                .lists
                .iter()
                .all(|l| l.managed_by == ManagedBy::ConfigFile)
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
    fn inline_rules_are_checked() {
        let ok = "[filter]\nrules = [\"||ads.example^\", \"@@||good.example^\", \"! a comment\"]";
        assert!(Config::parse(ok).unwrap().filter.validate().is_ok());
        for bad in [
            "rules = [\"||ads.example^$important\"]",
            "rules = [\"/ads[0-9]+/\"]",
            "rules = [\"not a rule!\"]",
            "rules = [\"a.example\\nb.example\"]",
        ] {
            let config = Config::parse(&format!("[filter]\n{bad}")).unwrap();
            let err = config.filter.validate().unwrap_err();
            assert!(err.to_string().contains("filter.rules"), "{bad}: {err:#}");
        }
    }

    #[test]
    fn querylog_settings() {
        let config = Config::parse("").unwrap().querylog;
        assert_eq!(config.to_config(), QueryLogConfig::default());
        let custom = Config::parse(
            "[querylog]\nenabled = false\nretention_days = 30\nanonymize_clients = true",
        )
        .unwrap()
        .querylog;
        let store = custom.to_config();
        assert!(!store.enabled && store.anonymize);
        assert_eq!(store.retention, std::time::Duration::from_hours(720));
        for bad in [
            "retention_days = 0",
            "retention_days = 366",
            "max_entries = 10",
        ] {
            let config = Config::parse(&format!("[querylog]\n{bad}")).unwrap();
            assert!(config.querylog.validate().is_err(), "{bad}");
        }
    }

    #[test]
    fn security_settings() {
        let default = Config::parse("").unwrap().security;
        assert!(default.rebinding_protection);
        assert!(default.private_domains.iter().any(|d| d == "home.arpa"));
        assert!(default.rebinding_protection().unwrap().is_some());

        let off = Config::parse("[security]\nrebinding_protection = false").unwrap();
        assert!(off.security.rebinding_protection().unwrap().is_none());

        let bad = Config::parse("[security]\nprivate_domains = [\"not a name\"]").unwrap();
        assert!(bad.security.rebinding_protection().is_err());
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
        assert_eq!(config.server.listen, ["[::1]:53".parse().unwrap()]);
    }

    #[test]
    fn listen_accepts_a_list() {
        let config = Config::parse("[server]\nlisten = [\"0.0.0.0:53\", \"[::]:53\"]").unwrap();
        assert_eq!(
            config.server.listen,
            ["0.0.0.0:53".parse().unwrap(), "[::]:53".parse().unwrap()]
        );
        assert!(config.server.validate().is_ok());
        let err =
            Config::parse("[server]\nlisten = [\"0.0.0.0:53\", \"localhost:53\"]").unwrap_err();
        assert!(err.to_string().contains("\"localhost:53\""), "{err}");
        let many = (0..17)
            .map(|i| format!("\"127.0.0.1:{}\"", 1000 + i))
            .collect::<Vec<_>>();
        let err = Config::parse(&format!("[server]\nlisten = [{}]", many.join(", "))).unwrap_err();
        assert!(err.to_string().contains("at most 16"), "{err}");
    }

    #[test]
    fn server_limits_are_checked() {
        for (bad, expected) in [
            ("listen = []", "server.listen is empty"),
            (
                "listen = [\"127.0.0.1:53\", \"127.0.0.1:53\"]",
                "127.0.0.1:53 twice",
            ),
            ("udp_sockets = 0", "server.udp_sockets"),
            ("udp_sockets = 65", "server.udp_sockets"),
            ("max_tcp_connections = 0", "server.max_tcp_connections"),
            (
                "max_tcp_connections = 8\nmax_tcp_connections_per_client = 9",
                "max_tcp_connections_per_client",
            ),
            ("rate_limit.burst = 0", "burst"),
            ("rate_limit.slip = 11", "slip"),
            ("rate_limit.ipv4_prefix = 33", "ipv4_prefix"),
            ("rate_limit.ipv6_prefix = 8", "ipv6_prefix"),
            ("rate_limit.max_clients = 1", "max_clients"),
            ("user = \"\"", "server.user"),
            ("user = \"a:b\"", "server.user"),
        ] {
            let config = Config::parse(&format!("[server]\n{bad}")).unwrap();
            let err = config.server.validate().unwrap_err();
            assert!(err.to_string().contains(expected), "{bad}: {err:#}");
        }
        let off = Config::parse("[server.rate_limit]\nqueries_per_second = 0").unwrap();
        assert!(off.server.validate().is_ok());
        let server = off.server.to_server_config();
        assert_eq!(server.rate_limit.queries_per_second, 0);
        assert!(server.rate_limit.exempt_loopback);
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
