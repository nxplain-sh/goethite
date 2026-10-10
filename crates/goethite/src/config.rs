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
use goethite_api::TokenHash;
use goethite_cluster::vrrp::VrrpConfig;
use goethite_cluster::vrrp::packet::MAX_INTERVAL;
use goethite_cluster::{NodeId, Role};
use goethite_filter::{LineKind, parse_line};
use goethite_proto::Name;
use goethite_resolver::{
    CacheConfig, Cidr, DEFAULT_PRIVATE_DOMAINS, MAX_ENTRIES, MAX_UPSTREAMS, RebindingProtection,
    RecursorConfig, Transport, UpstreamConfig,
};
use goethite_server::{
    MAX_LISTEN_ADDRESSES, MAX_RATE_LIMIT_EXEMPTIONS, MAX_RATE_LIMITED_CLIENTS, MAX_UDP_SOCKETS,
    RateLimitConfig, ServerConfig,
};
use goethite_store::{
    AccessSpec, BlockResponseKind, Import, ListSpec, ManagedBy, QueryLogConfig, RuleSpec,
    SettingsSpec, model::MAX_NAME_LEN,
};
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

/// Config files larger than this many bytes are rejected.
const MAX_CONFIG_LEN: usize = 1024 * 1024;

/// The whole configuration file.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    /// The `[server]` table.
    #[serde(default)]
    pub server: ServerSection,
    /// The `[[upstream]]` tables, in order of preference.
    #[serde(default)]
    pub upstream: Vec<UpstreamSection>,
    /// The `[recursion]` table: resolving from the root servers down
    /// instead of forwarding.
    #[serde(default)]
    pub recursion: RecursionSection,
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
    /// The `[api]` table.
    #[serde(default)]
    pub api: ApiSection,
    /// The `[telemetry]` table: sending telemetry to an OpenTelemetry
    /// collector.
    #[serde(default)]
    pub telemetry: TelemetrySection,
    /// The `[cluster]` table; absent for a node on its own.
    #[serde(default)]
    pub cluster: Option<ClusterSection>,
    /// The `[vrrp]` table: the floating IP, held by `goethite vrrp`.
    #[serde(default)]
    pub vrrp: Option<VrrpSection>,
    /// The absolute directory of the config file, which relative paths are
    /// relative to. Set by [`Config::load`].
    #[serde(skip)]
    pub dir: PathBuf,
}

/// The `[cluster]` table: this node's place in a cluster.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClusterSection {
    /// This node's name, as in its certificate.
    pub node: NodeId,
    /// Whether to start a new cluster on this node, with its configuration,
    /// while it is in none. On one node only.
    #[serde(default)]
    pub bootstrap: bool,
    /// goethite 0.4's role: `primary` starts the cluster, as `bootstrap`
    /// does; `replica` waits to be added to it.
    #[serde(default)]
    pub role: Option<Role>,
    /// Where it listens for the other members; also the address it gives
    /// them when it starts a cluster.
    #[serde(default = "default_cluster_listen")]
    pub listen: SocketAddr,
    /// The cluster's CA certificate (PEM), from `goethite cluster init`.
    pub ca: PathBuf,
    /// This node's certificate (PEM), from `goethite cluster cert`.
    pub cert: PathBuf,
    /// This node's private key (PEM).
    pub key: PathBuf,
    /// The other members: `[[cluster.member]]` tables.
    #[serde(default, rename = "member")]
    pub members: Vec<MemberSection>,
    /// goethite 0.4's one other member, as `[[cluster.member]]`.
    #[serde(default)]
    pub peer: Option<MemberSection>,
}

/// A `[[cluster.member]]` table, or goethite 0.4's `[cluster.peer]`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct MemberSection {
    /// Its name, as in its certificate.
    pub node: NodeId,
    /// Its cluster listener.
    pub address: SocketAddr,
}

/// The most other members a cluster may list.
const MAX_MEMBERS: usize = 15;

fn default_cluster_listen() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8054))
}

impl ClusterSection {
    fn validate(&self) -> Result<()> {
        if self.bootstrap && self.role == Some(Role::Replica) {
            bail!("cluster.bootstrap and role = \"replica\" contradict each other: drop role");
        }
        let members: Vec<&MemberSection> = self.members().collect();
        if members.len() > MAX_MEMBERS {
            bail!("a cluster may list at most {MAX_MEMBERS} other members");
        }
        let mut ids = std::collections::HashMap::new();
        ids.insert(goethite_cluster::raft::raft_id(&self.node), &self.node);
        for member in members {
            if member.node == self.node {
                bail!(
                    "cluster.member lists this node, {}: list only the other members",
                    self.node
                );
            }
            if let Some(other) =
                ids.insert(goethite_cluster::raft::raft_id(&member.node), &member.node)
            {
                if *other == member.node {
                    bail!("cluster.member lists {} twice", member.node);
                }
                bail!(
                    "the node names {other} and {} cannot be told apart in the cluster: rename one",
                    member.node
                );
            }
        }
        Ok(())
    }

    /// The other members: `[[cluster.member]]` and `[cluster.peer]`.
    pub(crate) fn members(&self) -> impl Iterator<Item = &MemberSection> {
        self.members.iter().chain(&self.peer)
    }

    /// Whether this node starts the cluster, given the role goethite 0.4
    /// kept in the store after promote or demote (`stored`, and the config
    /// file's role then, `stored_base`): that one wins until the config
    /// file's role changes.
    pub(crate) fn bootstraps(&self, stored: Option<Role>, stored_base: Option<Role>) -> bool {
        let role = match (stored, stored_base, self.role) {
            (Some(stored), Some(base), Some(configured)) if base == configured => Some(stored),
            _ => self.role,
        };
        self.bootstrap || role == Some(Role::Primary)
    }

    fn resolve_paths(&mut self, base: &Path) {
        for path in [&mut self.ca, &mut self.cert, &mut self.key] {
            if path.is_relative() {
                *path = base.join(&*path);
            }
        }
    }
}

/// The `[vrrp]` table: a floating IP that whichever node is healthy holds,
/// moved between the nodes with VRRP by `goethite vrrp`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct VrrpSection {
    /// The network interface the address lives on.
    pub interface: String,
    /// The floating IP.
    pub address: Ipv4Addr,
    /// The other node's address on the interface.
    pub peer: Ipv4Addr,
    /// The virtual router's ID, 1 to 255: the same on both nodes, and
    /// unique on the network.
    pub router_id: u8,
    /// This node's priority, 1 to 254: of two healthy nodes, the higher
    /// holds the address.
    pub priority: u8,
    /// How often the node holding the address announces itself.
    #[serde(default = "default_vrrp_interval_ms")]
    pub interval_ms: u32,
    /// Whether to take the address back from a peer of lower priority.
    #[serde(default = "enabled")]
    pub preempt: bool,
    /// Advertise to the peer directly instead of by multicast.
    #[serde(default)]
    pub unicast: bool,
    /// Where to check that goethite answers; a `[server] listen` address
    /// other than the floating IP if unset.
    #[serde(default)]
    pub check: Option<SocketAddr>,
}

fn default_vrrp_interval_ms() -> u32 {
    1000
}

/// The longest name Linux gives an interface (`IFNAMSIZ` - 1).
const MAX_INTERFACE_NAME_LEN: usize = 15;

impl VrrpSection {
    fn validate(&self, server: &ServerSection) -> Result<()> {
        let name = &self.interface;
        if name.is_empty()
            || name.len() > MAX_INTERFACE_NAME_LEN
            || name == "."
            || name == ".."
            || name.contains(['/', ':', '\0'])
            || name.contains(char::is_whitespace)
        {
            bail!("vrrp.interface {name:?} is not an interface name");
        }
        for (key, address) in [("address", self.address), ("peer", self.peer)] {
            if address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || address.is_broadcast()
            {
                bail!("vrrp.{key} {address} is not a unicast address");
            }
        }
        if self.peer == self.address {
            bail!("vrrp.peer must be the other node's own address, not the floating IP");
        }
        if self.router_id == 0 {
            bail!("vrrp.router_id must be between 1 and 255");
        }
        if !(1..=254).contains(&self.priority) {
            bail!(
                "vrrp.priority is {}; it must be between 1 and 254",
                self.priority
            );
        }
        if !(100..=40_950).contains(&self.interval_ms) || !self.interval_ms.is_multiple_of(10) {
            bail!(
                "vrrp.interval_ms is {}; it must be a multiple of 10 between 100 and 40950",
                self.interval_ms
            );
        }
        let covered = server.listen.iter().any(|listen| {
            listen.ip() == IpAddr::V4(self.address)
                || listen.ip() == IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        });
        if !covered {
            bail!(
                "server.listen does not include the floating IP: add \"{}:53\" (or listen on \
                 0.0.0.0) so goethite answers on it",
                self.address
            );
        }
        if self.check_address(server).is_none() {
            bail!(
                "nothing to check goethite on: add an address other than the floating IP to \
                 server.listen, such as \"127.0.0.1:53\", or set vrrp.check"
            );
        }
        Ok(())
    }

    /// Where `goethite vrrp` checks that goethite answers: `check`, or the
    /// first listen address that is always there (not the floating IP),
    /// with loopback for an unspecified one.
    pub(crate) fn check_address(&self, server: &ServerSection) -> Option<SocketAddr> {
        if self.check.is_some() {
            return self.check;
        }
        server
            .listen
            .iter()
            .find(|listen| listen.ip() != IpAddr::V4(self.address))
            .map(|&listen| match listen.ip() {
                IpAddr::V4(ip) if ip.is_unspecified() => {
                    SocketAddr::from((Ipv4Addr::LOCALHOST, listen.port()))
                }
                IpAddr::V6(ip) if ip.is_unspecified() => {
                    SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, listen.port()))
                }
                _ => listen,
            })
    }

    /// The settings `goethite vrrp` runs with.
    pub(crate) fn to_vrrp_config(&self) -> VrrpConfig {
        VrrpConfig {
            interface: self.interface.clone(),
            address: self.address,
            router_id: self.router_id,
            priority: self.priority,
            interval: u16::try_from(self.interval_ms / 10).unwrap_or(MAX_INTERVAL),
            preempt: self.preempt,
            peer: self.peer,
            unicast: self.unicast,
        }
    }
}

/// The `[api]` table.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct ApiSection {
    /// Whether the API (and the web UI) is served.
    pub enabled: bool,
    /// Addresses for the API: one, or a list.
    #[serde(deserialize_with = "listen_addresses")]
    pub listen: Vec<SocketAddr>,
    /// The SHA-256 hash of the admin token, from `goethite token`.
    pub token_sha256: Option<String>,
    /// The TLS certificate chain (PEM), to serve HTTPS.
    pub tls_cert: Option<PathBuf>,
    /// The TLS private key (PEM).
    pub tls_key: Option<PathBuf>,
    /// Whether the web UI is served next to the API.
    pub web_ui: bool,
    /// Whether the API reference is served at `/api/docs`, to loopback
    /// clients only.
    pub docs: bool,
}

impl Default for ApiSection {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 8053))],
            token_sha256: None,
            tls_cert: None,
            tls_key: None,
            web_ui: true,
            docs: false,
        }
    }
}

impl ApiSection {
    /// The token hash, if one is configured.
    pub(crate) fn token(&self) -> Result<Option<TokenHash>> {
        self.token_sha256
            .as_deref()
            .map(|hash| hash.parse().context("api.token_sha256"))
            .transpose()
    }

    fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.listen.is_empty() {
            bail!("api.listen is empty; give at least one address or set api.enabled = false");
        }
        let token = self.token()?;
        if token.is_none()
            && let Some(open) = self.listen.iter().find(|addr| !addr.ip().is_loopback())
        {
            bail!(
                "the API would listen on {open} without an admin token; run `goethite token` \
                 and set api.token_sha256, or listen on loopback only"
            );
        }
        if self.tls_cert.is_some() != self.tls_key.is_some() {
            bail!("api.tls_cert and api.tls_key go together");
        }
        Ok(())
    }

    fn resolve_paths(&mut self, base: &Path) {
        for path in [&mut self.tls_cert, &mut self.tls_key]
            .into_iter()
            .flatten()
        {
            if path.is_relative() {
                *path = base.join(&*path);
            }
        }
    }
}

/// Seconds between metric exports: at least and at most.
const TELEMETRY_INTERVAL: (u64, u64) = (10, 3600);

/// The `[telemetry]` table: sending telemetry to an OpenTelemetry collector
/// over OTLP/HTTP (ADR 0034). Nothing is sent without an endpoint.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct TelemetrySection {
    /// The collector's OTLP/HTTP base URL, such as
    /// `https://collector.example:4318`.
    pub endpoint: Option<String>,
    /// A file of `Name: value` lines, sent as headers with every export:
    /// an API key, for example.
    pub headers_file: Option<PathBuf>,
    /// CA certificates (PEM) to verify the collector with, instead of the
    /// public roots.
    pub ca_file: Option<PathBuf>,
    /// Whether metrics are sent.
    pub metrics: bool,
    /// Seconds between metric exports.
    pub interval: u64,
}

impl Default for TelemetrySection {
    fn default() -> Self {
        Self {
            endpoint: None,
            headers_file: None,
            ca_file: None,
            metrics: true,
            interval: 60,
        }
    }
}

impl TelemetrySection {
    /// The endpoint, if one is configured.
    ///
    /// # Errors
    ///
    /// If it is not an `http://` or `https://` URL with a host and without
    /// a query.
    pub(crate) fn endpoint(&self) -> Result<Option<hyper::Uri>> {
        let Some(endpoint) = &self.endpoint else {
            return Ok(None);
        };
        let uri: hyper::Uri = endpoint
            .parse()
            .with_context(|| format!("telemetry.endpoint {endpoint:?} is not a URL"))?;
        if !matches!(uri.scheme_str(), Some("http" | "https")) {
            bail!("telemetry.endpoint {endpoint:?} is not an http:// or https:// URL");
        }
        if uri.host().is_none_or(str::is_empty) {
            bail!("telemetry.endpoint {endpoint:?} has no host");
        }
        if uri.query().is_some() {
            bail!("telemetry.endpoint {endpoint:?} has a query; give the base URL");
        }
        Ok(Some(uri))
    }

    /// Where `signal` (`metrics`, `logs` or `traces`) is sent: the
    /// endpoint with `/v1/<signal>` appended, as OTLP/HTTP defines.
    pub(crate) fn signal_url(&self, signal: &str) -> Option<String> {
        let endpoint = self.endpoint.as_deref()?;
        Some(format!("{}/v1/{signal}", endpoint.trim_end_matches('/')))
    }

    fn validate(&self) -> Result<()> {
        let endpoint = self.endpoint()?;
        if endpoint.is_none() && (self.headers_file.is_some() || self.ca_file.is_some()) {
            bail!("telemetry.headers_file and telemetry.ca_file need telemetry.endpoint");
        }
        let (min, max) = TELEMETRY_INTERVAL;
        if !(min..=max).contains(&self.interval) {
            bail!("telemetry.interval must be between {min} and {max} seconds");
        }
        Ok(())
    }

    fn resolve_paths(&mut self, base: &Path) {
        for path in [&mut self.headers_file, &mut self.ca_file]
            .into_iter()
            .flatten()
        {
            if path.is_relative() {
                *path = base.join(&*path);
            }
        }
    }
}

/// The `[querylog]` table.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct QueryLogSection {
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
    pub(crate) fn to_config(&self) -> QueryLogConfig {
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
pub(crate) struct StoreSection {
    /// The database file. Defaults to `goethite.redb` in the state
    /// directory.
    pub path: Option<PathBuf>,
}

impl Config {
    /// Where goethite keeps its state: systemd's `STATE_DIRECTORY` (the
    /// unit's `StateDirectory=`) if set, otherwise the config file's
    /// directory.
    pub(crate) fn state_dir(&self) -> PathBuf {
        std::env::var_os("STATE_DIRECTORY")
            .and_then(|dirs| {
                std::env::split_paths(&dirs)
                    .next()
                    .filter(|dir| dir.is_absolute())
            })
            .unwrap_or_else(|| self.dir.clone())
    }

    /// The store's database file.
    pub(crate) fn store_path(&self) -> PathBuf {
        self.store
            .path
            .clone()
            .unwrap_or_else(|| self.state_dir().join("goethite.redb"))
    }

    /// Where downloaded lists are kept.
    pub(crate) fn lists_dir(&self) -> PathBuf {
        self.filter
            .cache_dir
            .clone()
            .unwrap_or_else(|| self.state_dir().join("lists"))
    }

    /// The only directory lists given by a path are read from.
    pub(crate) fn local_lists_dir(&self) -> PathBuf {
        self.filter
            .local_lists_dir
            .clone()
            .unwrap_or_else(|| self.dir.join("lists"))
    }
}

/// The `[security]` table.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct SecuritySection {
    /// Remove private addresses from answers for public names.
    pub rebinding_protection: bool,
    /// Names below these may resolve to private addresses.
    pub private_domains: Vec<String>,
    /// Confine the process once it runs (Linux): Landlock for files,
    /// seccomp for system calls.
    pub sandbox: bool,
}

impl Default for SecuritySection {
    fn default() -> Self {
        Self {
            rebinding_protection: true,
            sandbox: true,
            private_domains: DEFAULT_PRIVATE_DOMAINS
                .iter()
                .map(|&domain| domain.to_owned())
                .collect(),
        }
    }
}

impl SecuritySection {
    /// The resolver's rebinding protection, if it is on.
    pub(crate) fn rebinding_protection(&self) -> Result<Option<RebindingProtection>> {
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
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent on/off switches in the config file"
)]
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct FilterSection {
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
    /// The only directory lists given by a path are read from. Defaults to
    /// `lists` beside the config file.
    pub local_lists_dir: Option<PathBuf>,
    /// How often downloaded lists are refreshed, in hours.
    pub update_hours: u32,
    /// What to do when filtering fails. A node setting: it is not
    /// copied into the store.
    pub on_failure: OnFailure,
    /// Whether a new node starts with goethite's default list (HaGeZi
    /// Multi Normal) when this table names no lists. Only the first start
    /// of a new store looks at it.
    pub default_lists: bool,
    /// Whether the node looks lists up for the web UI when someone browses
    /// them: the FilterLists directory (filterlists.com), and the sizes the
    /// recommended lists state.
    pub directory: bool,
    /// Whether groups can block services (TikTok, YouTube…): the node
    /// downloads AdGuard's services catalog with the lists.
    pub services: bool,
    /// Reads the services catalog from this file instead of downloading
    /// it, for nodes that cannot reach the internet.
    pub services_file: Option<PathBuf>,
}

/// What to do when filtering fails: the store cannot be opened, the filter
/// cannot be built, or checking a name fails.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OnFailure {
    /// Keep resolving, unfiltered if need be, and say so loudly.
    #[default]
    Open,
    /// Refuse to start, or answer SERVFAIL: never resolve unfiltered.
    Closed,
}

impl OnFailure {
    /// The resolver's mode.
    pub(crate) fn mode(self) -> goethite_resolver::FailMode {
        match self {
            Self::Open => goethite_resolver::FailMode::Open,
            Self::Closed => goethite_resolver::FailMode::Closed,
        }
    }
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
            local_lists_dir: None,
            update_hours: 24,
            on_failure: OnFailure::Open,
            default_lists: true,
            directory: true,
            services: true,
            services_file: None,
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

    /// Where the services catalog comes from, unless blocked services are
    /// turned off.
    pub(crate) fn services_from(&self) -> Option<crate::services::ServicesFrom> {
        use crate::services::ServicesFrom;
        self.services.then(|| match &self.services_file {
            Some(path) => ServicesFrom::File(path.clone()),
            None => ServicesFrom::Url(goethite_api::services::SOURCE.to_owned()),
        })
    }

    /// The table as resources to import into the store: config rules and
    /// lists become resources managed by the config file.
    pub(crate) fn to_import(&self) -> Import {
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
                // Not in the config file: an import keeps the store's.
                access: AccessSpec::default(),
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
        if let Some(dir) = &mut self.local_lists_dir {
            resolve(dir);
        }
        if let Some(file) = &mut self.services_file {
            resolve(file);
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
pub(crate) struct ListSection {
    /// A local list file (hosts, domains or AdGuard syntax, mixed freely).
    pub path: Option<PathBuf>,
    /// An `https://` URL to download the list from, every `update_hours`.
    pub url: Option<String>,
}

/// `filter.block_response`.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BlockResponseSetting {
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

/// The `[recursion]` table.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct RecursionSection {
    /// Resolve from the root servers down instead of asking `[[upstream]]`
    /// resolvers.
    pub enabled: bool,
    /// QNAME minimisation (RFC 9156): show each server only as much of a
    /// name as it needs to see.
    pub qname_minimisation: bool,
    /// Ask servers over IPv6 too. Unset: if this host has an IPv6 route.
    pub ipv6: Option<bool>,
    /// DNSSEC validation: AD for answers proved authentic, SERVFAIL for
    /// bogus ones.
    pub dnssec: bool,
}

impl Default for RecursionSection {
    fn default() -> Self {
        Self {
            enabled: false,
            qname_minimisation: true,
            ipv6: None,
            dnssec: true,
        }
    }
}

impl RecursionSection {
    /// The resolver's view of this table; `has_ipv6` decides when `ipv6` is
    /// unset.
    pub(crate) fn to_recursor_config(&self, has_ipv6: impl FnOnce() -> bool) -> RecursorConfig {
        RecursorConfig {
            qname_minimisation: self.qname_minimisation,
            ipv6: self.ipv6.unwrap_or_else(has_ipv6),
            dnssec: self.dnssec,
            ..RecursorConfig::default()
        }
    }
}

/// The `[cache]` table.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct CacheSection {
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
    pub(crate) fn to_cache_config(&self) -> CacheConfig {
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
pub(crate) struct UpstreamSection {
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
pub(crate) struct Address {
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
pub(crate) enum Protocol {
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
    pub(crate) fn to_upstream(&self) -> UpstreamConfig {
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
pub(crate) struct ServerSection {
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
    /// The `[server.tls]` table: DNS over TLS and HTTPS.
    pub tls: Option<TlsSection>,
}

/// The `[server.tls]` table: DNS over TLS, HTTPS and QUIC for clients.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct TlsSection {
    /// The certificate chain (PEM).
    pub cert: PathBuf,
    /// Its private key (PEM).
    pub key: PathBuf,
    /// The name clients reach goethite by, such as `dns.example`: a server
    /// name one label below it (`anna-phone.dns.example`) carries a client
    /// ID. The certificate should cover `*.<server_name>` too.
    #[serde(default)]
    pub server_name: Option<String>,
    /// Addresses for DNS over TLS, usually port 853: one, or a list.
    #[serde(default, deserialize_with = "listen_addresses")]
    pub dot: Vec<SocketAddr>,
    /// Addresses for DNS over HTTPS, usually port 443: one, or a list.
    #[serde(default, deserialize_with = "listen_addresses")]
    pub doh: Vec<SocketAddr>,
    /// Addresses for DNS over QUIC, usually UDP port 853: one, or a list.
    #[serde(default, deserialize_with = "listen_addresses")]
    pub doq: Vec<SocketAddr>,
    /// Whether DNS over TLS, HTTPS and QUIC answer only queries with a
    /// known client ID, as when they are reachable from the internet.
    #[serde(default)]
    pub require_client_id: bool,
    /// Whether the DNS over HTTPS addresses are also an Oblivious DoH
    /// target (RFC 9230), for clients that ask through a proxy.
    #[serde(default)]
    pub odoh: bool,
}

impl TlsSection {
    fn validate(&self) -> Result<()> {
        if self.dot.is_empty() && self.doh.is_empty() && self.doq.is_empty() {
            bail!(
                "server.tls has no dot, doh or doq addresses: give at least one, or remove the table"
            );
        }
        for (name, list) in [("dot", &self.dot), ("doh", &self.doh), ("doq", &self.doq)] {
            if list.len() > MAX_LISTEN_ADDRESSES {
                bail!("server.tls.{name} has more than {MAX_LISTEN_ADDRESSES} addresses");
            }
        }
        if let Some(name) = &self.server_name
            && !is_host_name(name)
        {
            bail!(
                "server.tls.server_name {name:?} is not a host name such as \"dns.example\" \
                 (letters, digits and hyphens in dot-separated labels)"
            );
        }
        if self.odoh && self.doh.is_empty() {
            bail!("server.tls.odoh needs doh addresses: Oblivious DoH is served on them");
        }
        Ok(())
    }

    fn resolve_paths(&mut self, base: &Path) {
        for path in [&mut self.cert, &mut self.key] {
            if path.is_relative() {
                *path = base.join(&*path);
            }
        }
    }
}

/// Whether `name` is a host name: dot-separated labels of 1 to 63 letters,
/// digits and hyphens, not starting or ending with a hyphen, 253 characters
/// at most, with an optional final dot.
fn is_host_name(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
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
            tls: None,
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
        if let Some(tls) = &self.tls {
            tls.validate()?;
        }
        self.rate_limit.validate()
    }

    /// The listener settings.
    pub(crate) fn to_server_config(&self) -> ServerConfig {
        let mut config = ServerConfig::new(self.listen.clone());
        if let Some(sockets) = self.udp_sockets {
            config.udp_sockets = sockets;
        }
        config.max_tcp_connections = self.max_tcp_connections;
        config.max_tcp_connections_per_client = self.max_tcp_connections_per_client;
        config.rate_limit = self.rate_limit.to_rate_limit_config();
        if let Some(tls) = &self.tls {
            config.dot.clone_from(&tls.dot);
            config.doh.clone_from(&tls.doh);
            config.doq.clone_from(&tls.doq);
            config.require_client_id = tls.require_client_id;
            config.odoh = tls.odoh;
            config.server_name = tls
                .server_name
                .as_ref()
                .map(|name| name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase());
        }
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
pub(crate) struct RateLimitSection {
    /// Average queries per second per client network, over every transport
    /// but Oblivious DoH; 0 turns it off.
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
    /// Networks never limited: addresses or CIDR networks.
    pub exempt: Vec<String>,
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
            exempt: Vec::new(),
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
        if self.exempt.len() > MAX_RATE_LIMIT_EXEMPTIONS {
            bail!("server.rate_limit.exempt lists more than {MAX_RATE_LIMIT_EXEMPTIONS} networks");
        }
        for network in &self.exempt {
            network
                .parse::<Cidr>()
                .with_context(|| format!("server.rate_limit.exempt: {network:?}"))?;
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
            exempt: self
                .exempt
                .iter()
                .filter_map(|network| network.parse().ok())
                .collect(),
            ..RateLimitConfig::default()
        }
    }
}

impl Config {
    /// Reads and parses the configuration file at `path`.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        Self::load_for(path, true)
    }

    /// Loads the config file of a witness (`goethite witness`), which
    /// resolves nothing and so needs no upstreams.
    ///
    /// # Errors
    ///
    /// As [`Config::load`].
    pub(crate) fn load_witness(path: &Path) -> Result<Self> {
        Self::load_for(path, false)
    }

    fn load_for(path: &Path, resolves: bool) -> Result<Self> {
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
        match (config.upstream.is_empty(), config.recursion.enabled) {
            (true, false) if resolves => bail!(
                "no upstream resolvers configured in {}: add at least one [[upstream]] table, \
                 for example\n\n[[upstream]]\naddress = \"9.9.9.9\"\n\nor resolve from the \
                 root servers yourself:\n\n[recursion]\nenabled = true",
                path.display()
            ),
            (false, true) => bail!(
                "{} has [[upstream]] resolvers and [recursion] enabled: choose one",
                path.display()
            ),
            _ => {}
        }
        config
            .server
            .validate()
            .and_then(|()| config.cache.validate())
            .and_then(|()| config.querylog.validate())
            .and_then(|()| config.api.validate())
            .and_then(|()| config.telemetry.validate())
            .and_then(|()| config.filter.validate())
            .and_then(|()| {
                config
                    .cluster
                    .as_ref()
                    .map_or(Ok(()), ClusterSection::validate)
            })
            .and_then(|()| {
                config
                    .vrrp
                    .as_ref()
                    .map_or(Ok(()), |vrrp| vrrp.validate(&config.server))
            })
            .and_then(|()| config.security.rebinding_protection().map(drop))
            .and_then(|()| config.check_tcp_addresses())
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
        config.api.resolve_paths(&dir);
        config.telemetry.resolve_paths(&dir);
        if let Some(tls) = &mut config.server.tls {
            tls.resolve_paths(&dir);
        }
        if let Some(cluster) = &mut config.cluster {
            cluster.resolve_paths(&dir);
        }
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

    /// Every TCP address must be listened on once: DNS over TCP, TLS and
    /// HTTPS, the API and the cluster; and every UDP address: DNS over UDP
    /// and QUIC.
    fn check_tcp_addresses(&self) -> Result<()> {
        let mut seen = HashSet::new();
        let tls = self.server.tls.as_ref();
        let api = if self.api.enabled {
            self.api.listen.as_slice()
        } else {
            &[]
        };
        let all = [
            ("server.listen", self.server.listen.as_slice()),
            ("server.tls.dot", tls.map_or(&[][..], |tls| &tls.dot)),
            ("server.tls.doh", tls.map_or(&[][..], |tls| &tls.doh)),
            ("api.listen", api),
            (
                "cluster.listen",
                self.cluster
                    .as_ref()
                    .map_or(&[][..], |cluster| std::slice::from_ref(&cluster.listen)),
            ),
        ];
        for (name, addresses) in all {
            for addr in addresses {
                if addr.port() != 0 && !seen.insert(*addr) {
                    bail!("{name} uses the TCP address {addr}, which is listened on already");
                }
            }
        }
        let mut udp = HashSet::new();
        let doq = tls.map_or(&[][..], |tls| &tls.doq);
        for (name, addresses) in [
            ("server.listen", self.server.listen.as_slice()),
            ("server.tls.doq", doq),
        ] {
            for addr in addresses {
                if addr.port() != 0 && !udp.insert(*addr) {
                    bail!("{name} uses the UDP address {addr}, which is listened on already");
                }
            }
        }
        Ok(())
    }

    /// The DNS listener settings, with the floating IP (if any) bound
    /// before this node holds it.
    pub(crate) fn server_config(&self) -> ServerConfig {
        let mut server = self.server.to_server_config();
        if let Some(vrrp) = &self.vrrp {
            server.freebind = vec![IpAddr::V4(vrrp.address)];
        }
        server
    }

    /// Parses configuration from TOML text.
    pub(crate) fn parse(text: &str) -> Result<Self, toml::de::Error> {
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
    fn cluster_members() {
        let cluster = |text: &str| {
            let config = Config::parse(&format!(
                "[cluster]\nnode = \"dns1\"\nca = \"ca.crt\"\ncert = \"dns1.crt\"\nkey = \"dns1.key\"\n{text}"
            ))
            .unwrap();
            config.cluster.unwrap()
        };
        let three = cluster(
            "bootstrap = true\n[[cluster.member]]\nnode = \"dns2\"\naddress = \"192.0.2.12:8054\"\n\
             [[cluster.member]]\nnode = \"witness\"\naddress = \"192.0.2.13:8054\"\n",
        );
        three.validate().unwrap();
        assert_eq!(three.members().count(), 2);
        assert!(three.bootstraps(None, None));

        // goethite 0.4's tables still work: the primary starts the cluster.
        let legacy = cluster(
            "role = \"primary\"\n[cluster.peer]\nnode = \"dns2\"\naddress = \"192.0.2.12:8054\"\n",
        );
        legacy.validate().unwrap();
        assert_eq!(legacy.members().next().unwrap().node.as_str(), "dns2");
        assert!(legacy.bootstraps(None, None));
        // Unless promote and demote changed the role since.
        assert!(!legacy.bootstraps(Some(Role::Replica), Some(Role::Primary)));
        let replica = cluster("role = \"replica\"\n");
        assert!(!replica.bootstraps(None, None));
        assert!(replica.bootstraps(Some(Role::Primary), Some(Role::Replica)));
        // ...until the config file's role changes.
        assert!(!replica.bootstraps(Some(Role::Primary), Some(Role::Primary)));

        for (text, problem) in [
            (
                "[[cluster.member]]\nnode = \"dns1\"\naddress = \"192.0.2.11:8054\"\n",
                "lists this node",
            ),
            (
                "[[cluster.member]]\nnode = \"dns2\"\naddress = \"192.0.2.12:8054\"\n\
                 [cluster.peer]\nnode = \"dns2\"\naddress = \"192.0.2.12:8054\"\n",
                "twice",
            ),
            ("bootstrap = true\nrole = \"replica\"\n", "contradict"),
        ] {
            let err = cluster(text).validate().unwrap_err().to_string();
            assert!(err.contains(problem), "{text}: {err}");
        }
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
    fn api_settings() {
        let default = Config::parse("").unwrap().api;
        assert!(default.enabled);
        assert_eq!(default.listen, ["127.0.0.1:8053".parse().unwrap()]);
        assert!(default.validate().is_ok());
        assert_eq!(default.token().unwrap(), None);

        let open = Config::parse("[api]\nlisten = \"0.0.0.0:8053\"")
            .unwrap()
            .api;
        let err = open.validate().unwrap_err().to_string();
        assert!(err.contains("without an admin token"), "{err}");

        let hash = goethite_api::hash_token("gth_test").to_string();
        let tokened = Config::parse(&format!(
            "[api]\nlisten = [\"0.0.0.0:8053\", \"[::]:8053\"]\ntoken_sha256 = \"{hash}\""
        ))
        .unwrap()
        .api;
        assert!(tokened.validate().is_ok());
        assert!(tokened.token().unwrap().unwrap().matches("gth_test"));

        for bad in [
            "token_sha256 = \"short\"",
            "tls_cert = \"cert.pem\"",
            "listen = []",
        ] {
            let config = Config::parse(&format!("[api]\n{bad}")).unwrap();
            assert!(config.api.validate().is_err(), "{bad}");
        }
        let off = Config::parse("[api]\nenabled = false\nlisten = \"0.0.0.0:1\"").unwrap();
        assert!(off.api.validate().is_ok());
    }

    #[test]
    fn telemetry_settings() {
        let default = Config::parse("").unwrap().telemetry;
        assert_eq!(default.endpoint().unwrap(), None);
        assert_eq!(default.signal_url("metrics"), None);
        assert!(default.validate().is_ok());

        let set = Config::parse(
            "[telemetry]\nendpoint = \"https://collector.example:4318/\"\ninterval = 10",
        )
        .unwrap()
        .telemetry;
        assert!(set.validate().is_ok());
        assert_eq!(
            set.signal_url("metrics").as_deref(),
            Some("https://collector.example:4318/v1/metrics")
        );
        let prefixed = Config::parse("[telemetry]\nendpoint = \"http://127.0.0.1:4318/otlp\"")
            .unwrap()
            .telemetry;
        assert_eq!(
            prefixed.signal_url("metrics").as_deref(),
            Some("http://127.0.0.1:4318/otlp/v1/metrics")
        );

        for (bad, expected) in [
            (
                "endpoint = \"collector:4318\"",
                "not an http:// or https:// URL",
            ),
            (
                "endpoint = \"ftp://collector\"",
                "not an http:// or https:// URL",
            ),
            ("endpoint = \"https://c.example/?a=b\"", "has a query"),
            ("headers_file = \"otlp-headers\"", "need telemetry.endpoint"),
            (
                "endpoint = \"https://c.example\"\ninterval = 5",
                "between 10 and 3600",
            ),
        ] {
            let config = Config::parse(&format!("[telemetry]\n{bad}")).unwrap();
            let err = config.telemetry.validate().unwrap_err().to_string();
            assert!(err.contains(expected), "{bad}: {err}");
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
            ("rate_limit.exempt = [\"192.168.1.5/24\"]", "exempt"),
            ("rate_limit.exempt = [\"lan\"]", "exempt"),
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

        let exempt =
            Config::parse("[server.rate_limit]\nexempt = [\"192.168.0.0/16\", \"2001:db8::1\"]")
                .unwrap();
        assert!(exempt.server.validate().is_ok());
        assert_eq!(
            exempt.server.to_server_config().rate_limit.exempt,
            vec![
                "192.168.0.0/16".parse().unwrap(),
                "2001:db8::1".parse().unwrap()
            ]
        );
    }

    #[test]
    fn tls_settings() {
        let config = Config::parse(
            r#"
            [server.tls]
            cert = "dns.crt"
            key = "dns.key"
            server_name = "DNS.example."
            dot = "0.0.0.0:853"
            doh = ["0.0.0.0:443", "[::]:443"]
            doq = "0.0.0.0:853"
            require_client_id = true
            odoh = true
            "#,
        )
        .unwrap();
        assert!(config.server.validate().is_ok());
        assert!(config.check_tcp_addresses().is_ok());
        let server = config.server.to_server_config();
        assert_eq!(server.dot, ["0.0.0.0:853".parse().unwrap()]);
        assert_eq!(server.doh.len(), 2);
        assert_eq!(server.doq, ["0.0.0.0:853".parse().unwrap()]);
        assert_eq!(server.server_name.as_deref(), Some("dns.example"));
        assert!(server.require_client_id);
        assert!(server.odoh);
        let plain = Config::parse("").unwrap().server.to_server_config();
        assert_eq!((plain.dot.len(), plain.doh.len()), (0, 0));
        assert!(!plain.odoh);

        for (bad, expected) in [
            ("", "no dot, doh or doq"),
            ("dot = \"0.0.0.0:853\"\nodoh = true", "odoh needs doh"),
            (
                "dot = \"0.0.0.0:853\"\nserver_name = \"dns example\"",
                "server_name",
            ),
            (
                "dot = \"0.0.0.0:853\"\nserver_name = \"-x.example\"",
                "server_name",
            ),
        ] {
            let config =
                Config::parse(&format!("[server.tls]\ncert = \"c\"\nkey = \"k\"\n{bad}")).unwrap();
            let err = config.server.validate().unwrap_err();
            assert!(err.to_string().contains(expected), "{bad}: {err:#}");
        }
        assert!(Config::parse("[server.tls]\ncert = \"c\"\ndot = \"0.0.0.0:853\"").is_err());

        let clash = Config::parse(
            "[server]\nlisten = \"127.0.0.1:8053\"\n\
             [server.tls]\ncert = \"c\"\nkey = \"k\"\ndot = \"127.0.0.1:853\"",
        )
        .unwrap();
        let err = clash.check_tcp_addresses().unwrap_err().to_string();
        assert!(
            err.contains("api.listen") && err.contains("127.0.0.1:8053"),
            "{err}"
        );
    }

    #[test]
    fn host_names() {
        for good in ["dns.example", "dns.example.", "a", "x-1.b2.example"] {
            assert!(is_host_name(good), "{good}");
        }
        let long = format!("{}.example", "a".repeat(64));
        for bad in [
            "",
            ".",
            "a..b",
            "-a.example",
            "a-.example",
            "a_b.example",
            &long,
        ] {
            assert!(!is_host_name(bad), "{bad}");
        }
    }

    /// A config file with these listen addresses and a valid `[vrrp]`
    /// table, with `changes` (`key = value` lines) applied, if it is valid.
    fn with_vrrp(listen: &str, changes: &str) -> Result<Config> {
        let mut lines: Vec<String> = [
            r#"interface = "eth0""#,
            r#"address = "192.0.2.53""#,
            r#"peer = "192.0.2.12""#,
            "router_id = 53",
            "priority = 150",
        ]
        .map(String::from)
        .to_vec();
        for change in changes.lines() {
            let key = format!("{} ", change.split(" = ").next().unwrap());
            lines.retain(|line| !line.starts_with(&key));
            lines.push(change.to_owned());
        }
        let config = Config::parse(&format!(
            "[server]\nlisten = {listen}\n[vrrp]\n{}\n",
            lines.join("\n")
        ))?;
        if let Some(section) = &config.vrrp {
            section.validate(&config.server)?;
        }
        Ok(config)
    }

    #[test]
    fn vrrp_settings() {
        let config = with_vrrp(r#"["192.0.2.53:53", "127.0.0.1:53"]"#, "").unwrap();
        let section = config.vrrp.as_ref().unwrap();
        assert_eq!(
            section.to_vrrp_config(),
            VrrpConfig {
                interface: "eth0".into(),
                address: Ipv4Addr::new(192, 0, 2, 53),
                router_id: 53,
                priority: 150,
                interval: 100,
                preempt: true,
                peer: Ipv4Addr::new(192, 0, 2, 12),
                unicast: false,
            }
        );
        assert_eq!(
            section.check_address(&config.server),
            Some("127.0.0.1:53".parse().unwrap())
        );
        // The floating IP is bound before the node holds it.
        assert_eq!(
            config.server_config().freebind,
            [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))]
        );

        // Listening everywhere covers the floating IP, and is checked on
        // loopback.
        let config = with_vrrp(r#""0.0.0.0:53""#, "interval_ms = 250\npreempt = false").unwrap();
        let section = config.vrrp.as_ref().unwrap();
        assert_eq!(section.to_vrrp_config().interval, 25);
        assert!(!section.preempt);
        assert_eq!(
            section.check_address(&config.server),
            Some("127.0.0.1:53".parse().unwrap())
        );
        let config = with_vrrp(r#""192.0.2.53:53""#, r#"check = "[::1]:53""#).unwrap();
        assert_eq!(
            config.vrrp.unwrap().check_address(&config.server),
            Some("[::1]:53".parse().unwrap())
        );
        // No [vrrp]: nothing bound early.
        assert_eq!(
            Config::default().server_config().freebind,
            Vec::<IpAddr>::new()
        );
    }

    #[test]
    fn vrrp_settings_are_checked() {
        let listen = r#"["192.0.2.53:53", "127.0.0.1:53"]"#;
        for (change, expected) in [
            ("router_id = 0", "router_id"),
            ("priority = 0", "priority"),
            ("priority = 255", "priority"),
            ("interval_ms = 50", "interval_ms"),
            ("interval_ms = 1005", "interval_ms"),
            ("interval_ms = 41000", "interval_ms"),
            (r#"interface = """#, "interface"),
            (r#"interface = "eth0:1""#, "interface"),
            (r#"interface = "a-very-long-name0""#, "interface"),
            (r#"address = "127.0.0.1""#, "vrrp.address"),
            (r#"address = "224.0.0.18""#, "vrrp.address"),
            (r#"peer = "0.0.0.0""#, "vrrp.peer"),
            (r#"peer = "192.0.2.53""#, "vrrp.peer"),
        ] {
            let err = with_vrrp(listen, change)
                .err()
                .unwrap_or_else(|| panic!("{change} was accepted"));
            assert!(format!("{err:#}").contains(expected), "{change}: {err:#}");
        }
        let err = with_vrrp(r#""127.0.0.1:53""#, "").unwrap_err();
        assert!(format!("{err:#}").contains("does not include the floating IP"));
        let err = with_vrrp(r#""192.0.2.53:53""#, "").unwrap_err();
        assert!(format!("{err:#}").contains("nothing to check"));
        assert!(with_vrrp(listen, "router_id = 256").is_err(), "not a byte");
        assert!(with_vrrp(listen, "unknown = 1").is_err());
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
