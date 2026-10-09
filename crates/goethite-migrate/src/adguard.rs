//! AdGuard Home: what its API (`/control`) returns, and the plan it makes.
//!
//! - Filter subscriptions become filter lists, all in goethite's default
//!   group, as AdGuard Home applies them to everyone; allowlist
//!   subscriptions do not come over. Custom filtering rules become rules.
//! - Persistent clients known by address, network or client ID come over.
//!   One with settings of its own gets a group of its own, with its
//!   filtering, safe search and blocked services.
//! - DNS rewrites become local records.
//! - Global safe search and blocked services go to the default group; the
//!   blocking mode, the blocked answers' TTL, the list update interval and
//!   the allowed and disallowed clients become settings.
//!
//! Most of AdGuard Home's arrays are `null` when empty, so every one is an
//! `Option`.

use std::net::IpAddr;

use goethite_store::{BlockResponseKind, RecordKind};
use serde::Deserialize;

use crate::plan::{Plan, PlannedClient, PlannedGroup};

/// Everything read from one AdGuard Home.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct Export {
    /// `GET /control/filtering/status`.
    #[serde(default)]
    pub filtering: Filtering,
    /// `GET /control/clients`.
    #[serde(default)]
    pub clients: Clients,
    /// `GET /control/rewrite/list`.
    #[serde(default)]
    pub rewrites: Vec<Rewrite>,
    /// `GET /control/rewrite/settings`; servers before v0.107.68 have none.
    #[serde(default)]
    pub rewrite_settings: Option<RewriteSettings>,
    /// `GET /control/blocked_services/get`.
    #[serde(default)]
    pub blocked_services: BlockedServices,
    /// `GET /control/safesearch/status`.
    #[serde(default)]
    pub safe_search: SafeSearch,
    /// `GET /control/dns_info`.
    #[serde(default)]
    pub dns: DnsInfo,
    /// `GET /control/access/list`.
    #[serde(default)]
    pub access: Access,
}

/// `GET /control/filtering/status`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct Filtering {
    /// Block-list subscriptions.
    #[serde(default)]
    pub filters: Option<Vec<Filter>>,
    /// Allowlist subscriptions.
    #[serde(default)]
    pub whitelist_filters: Option<Vec<Filter>>,
    /// Custom rules, one line each.
    #[serde(default)]
    pub user_rules: Option<Vec<String>>,
    /// How often lists are updated, in hours; 0 for never.
    #[serde(default)]
    pub interval: Option<u32>,
    /// Whether filtering is on.
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// One subscription.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct Filter {
    /// Its URL, or a local file path.
    #[serde(default)]
    pub url: String,
    /// Its name.
    #[serde(default)]
    pub name: String,
    /// Whether it is used.
    #[serde(default)]
    pub enabled: bool,
}

/// `GET /control/clients`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct Clients {
    /// The persistent clients.
    #[serde(default)]
    pub clients: Option<Vec<Client>>,
}

/// One persistent client.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the switches AdGuard Home's JSON has, field for field"
)]
pub struct Client {
    /// Its name.
    #[serde(default)]
    pub name: String,
    /// IPs, then networks, then MAC addresses, then client IDs.
    #[serde(default)]
    pub ids: Option<Vec<String>>,
    /// Whether it follows the global filtering and safe search settings.
    #[serde(default = "yes")]
    pub use_global_settings: bool,
    /// Its own filtering switch.
    #[serde(default = "yes")]
    pub filtering_enabled: bool,
    /// Its own safe search settings.
    #[serde(default)]
    pub safe_search: Option<SafeSearch>,
    /// Whether it follows the global blocked services.
    #[serde(default = "yes")]
    pub use_global_blocked_services: bool,
    /// Its own blocked services.
    #[serde(default)]
    pub blocked_services: Option<Vec<String>>,
    /// Its own upstreams.
    #[serde(default)]
    pub upstreams: Option<Vec<String>>,
    /// Parental control (AdGuard's own service).
    #[serde(default)]
    pub parental_enabled: bool,
    /// Safe browsing (AdGuard's own service).
    #[serde(default)]
    pub safebrowsing_enabled: bool,
}

/// One DNS rewrite.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct Rewrite {
    /// The name, or `*.name` for the names below it.
    #[serde(default)]
    pub domain: String,
    /// An IPv4 or IPv6 address, a name (a CNAME), or `A` or `AAAA`: resolve
    /// that type upstream.
    #[serde(default)]
    pub answer: String,
    /// Whether it applies; servers before v0.107.68 leave it out.
    #[serde(default = "yes")]
    pub enabled: bool,
}

/// `GET /control/rewrite/settings`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct RewriteSettings {
    /// Whether rewrites apply at all.
    #[serde(default = "yes")]
    pub enabled: bool,
}

/// `GET /control/blocked_services/get`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct BlockedServices {
    /// The services blocked for everyone.
    #[serde(default)]
    pub ids: Option<Vec<String>>,
    /// When blocking is paused: a time zone and day ranges.
    #[serde(default)]
    pub schedule: Option<serde_json::Map<String, serde_json::Value>>,
}

/// Safe search, globally or for one client.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct SafeSearch {
    /// The master switch.
    #[serde(default)]
    pub enabled: bool,
}

/// `GET /control/dns_info`, as far as the migration reads it.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct DnsInfo {
    /// `default`, `refused`, `nxdomain`, `null_ip` or `custom_ip`.
    #[serde(default)]
    pub blocking_mode: Option<String>,
    /// TTL of blocked answers, in seconds.
    #[serde(default)]
    pub blocked_response_ttl: Option<u32>,
    /// Upstreams, dnsproxy syntax, comments included.
    #[serde(default)]
    pub upstream_dns: Option<Vec<String>>,
}

/// `GET /control/access/list`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct Access {
    /// When not empty, only these clients are answered.
    #[serde(default)]
    pub allowed_clients: Option<Vec<String>>,
    /// Never answered.
    #[serde(default)]
    pub disallowed_clients: Option<Vec<String>>,
    /// Names never answered.
    #[serde(default)]
    pub blocked_hosts: Option<Vec<String>>,
}

fn yes() -> bool {
    true
}

impl Export {
    /// What goethite would get.
    pub fn plan(&self) -> Plan {
        let mut plan = Plan::new("AdGuard Home");
        plan_filtering(&mut plan, &self.filtering);
        self.plan_global(&mut plan);
        self.plan_clients(&mut plan);
        let rewrites_on = self
            .rewrite_settings
            .as_ref()
            .is_none_or(|settings| settings.enabled);
        plan_rewrites(&mut plan, &self.rewrites, rewrites_on);
        plan_dns(&mut plan, &self.dns);
        plan_access(&mut plan, &self.access);
        plan
    }

    /// Safe search and blocked services for everyone, in the default group.
    fn plan_global(&self, plan: &mut Plan) {
        if self.safe_search.enabled {
            plan.default_safe_search = Some(true);
            plan.note(
                "Safe search covers Google, YouTube, Bing and DuckDuckGo in goethite, not each engine separately",
            );
        }
        plan.default_blocked_services = self.blocked_services.ids.clone().unwrap_or_default();
        if !plan.default_blocked_services.is_empty()
            && has_ranges(self.blocked_services.schedule.as_ref())
        {
            plan.note(
                "Blocked services are blocked at all times: AdGuard Home's pauses in their schedule do not come over",
            );
        }
    }

    /// Persistent clients; those with settings of their own get a group.
    fn plan_clients(&self, plan: &mut Plan) {
        let lists = plan.default_lists.clone();
        let global_services = plan.default_blocked_services.clone();
        for client in self.clients.clients.iter().flatten() {
            let mut planned = PlannedClient {
                name: client.name.clone(),
                ..PlannedClient::default()
            };
            for id in client.ids.iter().flatten() {
                if !Plan::add_client_id(&mut planned, id) {
                    plan.skip(
                        format!("client {} id {id}", client.name),
                        "a MAC address, which goethite does not see",
                    );
                }
            }
            if !client.use_global_settings || !client.use_global_blocked_services {
                let services = if client.use_global_blocked_services {
                    global_services.clone()
                } else {
                    client.blocked_services.clone().unwrap_or_default()
                };
                let (filtering, safe_search) = if client.use_global_settings {
                    (true, self.safe_search.enabled)
                } else {
                    (
                        client.filtering_enabled,
                        client.safe_search.as_ref().is_some_and(|s| s.enabled),
                    )
                };
                planned.group = plan.add_group(PlannedGroup {
                    name: client.name.clone(),
                    filtering,
                    safe_search,
                    lists: lists.clone(),
                    blocked_services: services,
                    comment: format!("The settings of {} in AdGuard Home", client.name),
                });
            }
            if client.parental_enabled || client.safebrowsing_enabled {
                plan.note(
                    "AdGuard's parental control and safe browsing services have no counterpart in goethite",
                );
            }
            if client
                .upstreams
                .iter()
                .flatten()
                .any(|line| !line.trim().is_empty())
            {
                plan.skip(
                    format!("upstreams of client {}", client.name),
                    "goethite uses the same upstreams for every client",
                );
            }
            plan.add_client(planned);
        }
    }
}

/// Lists in the default group, and custom rules.
fn plan_filtering(plan: &mut Plan, filtering: &Filtering) {
    for filter in filtering.filters.iter().flatten() {
        if let Some(url) = plan.add_list(&filter.url, Some(&filter.name), filter.enabled, None)
            && !plan.default_lists.contains(&url)
        {
            plan.default_lists.push(url);
        }
    }
    for filter in filtering.whitelist_filters.iter().flatten() {
        plan.skip(
            format!("allowlist {}", filter.url),
            "goethite has no allowlist subscriptions; add the domains it allows as @@ rules",
        );
    }
    for rule in filtering.user_rules.iter().flatten() {
        plan.add_rule(rule, true, None);
    }
    match filtering.interval {
        Some(0) => plan.note("Lists were never updated in AdGuard Home; goethite updates them"),
        Some(hours) => plan.list_update_hours = Some(hours.clamp(1, 168)),
        None => {}
    }
    if filtering.enabled == Some(false) {
        plan.note(
            "Filtering was off in AdGuard Home; goethite filters once migrated (turn it off in Settings)",
        );
    }
}

/// Rewrites as local records.
fn plan_rewrites(plan: &mut Plan, rewrites: &[Rewrite], on: bool) {
    for rewrite in rewrites {
        let answer = rewrite.answer.trim();
        if answer.eq_ignore_ascii_case("A") || answer.eq_ignore_ascii_case("AAAA") {
            plan.skip(
                format!("rewrite {} {answer}", rewrite.domain),
                "resolves that type upstream; goethite answers a name with records only from them",
            );
            continue;
        }
        let kind = match answer.parse::<IpAddr>() {
            Ok(IpAddr::V4(_)) => RecordKind::A,
            Ok(IpAddr::V6(_)) => RecordKind::Aaaa,
            Err(_) => RecordKind::Cname,
        };
        plan.add_record(&rewrite.domain, kind, answer, None, on && rewrite.enabled);
    }
    if !on && !rewrites.is_empty() {
        plan.note("Rewrites were switched off in AdGuard Home; their records come over disabled");
    }
}

/// The blocking mode and TTL; upstreams stay behind.
fn plan_dns(plan: &mut Plan, dns: &DnsInfo) {
    match dns.blocking_mode.as_deref() {
        Some("default" | "null_ip") => plan.block_response = Some(BlockResponseKind::NullIp),
        Some("nxdomain") => plan.block_response = Some(BlockResponseKind::Nxdomain),
        Some("refused") => plan.block_response = Some(BlockResponseKind::Refused),
        Some(other) => plan.skip(
            format!("blocking mode {other}"),
            "goethite answers blocked names with 0.0.0.0, NXDOMAIN or REFUSED",
        ),
        None => {}
    }
    if let Some(ttl) = dns.blocked_response_ttl {
        plan.blocked_ttl = Some(ttl.min(86_400));
    }
    let upstreams: Vec<&str> = dns
        .upstream_dns
        .iter()
        .flatten()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    if !upstreams.is_empty() {
        plan.note(format!(
            "Upstream servers are set in goethite's config file ([[upstream]]); AdGuard Home used {}",
            upstreams.join(", ")
        ));
    }
}

/// Allowed and disallowed clients.
fn plan_access(plan: &mut Plan, access: &Access) {
    plan.add_access(access.allowed_clients.as_deref().unwrap_or_default(), true);
    plan.add_access(
        access.disallowed_clients.as_deref().unwrap_or_default(),
        false,
    );
    for host in access.blocked_hosts.iter().flatten() {
        plan.skip(
            format!("disallowed domain {host}"),
            "goethite has no such list; block the name with a custom rule instead",
        );
    }
}

/// Whether a schedule has any day range: AdGuard Home leaves days out
/// rather than sending empty ones.
fn has_ranges(schedule: Option<&serde_json::Map<String, serde_json::Value>>) -> bool {
    schedule.is_some_and(|days| days.keys().any(|key| key != "time_zone"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn export() -> Export {
        serde_json::from_str(
            r##"{
              "filtering": {
                "filters": [
                  {"url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", "name": "AdGuard DNS filter", "id": 1, "rules_count": 5912, "enabled": true},
                  {"url": "/opt/adguardhome/lists/local.txt", "name": "Local", "id": 2, "enabled": true}
                ],
                "whitelist_filters": null,
                "user_rules": ["||ads.example.org^", "@@||good.example.org^", "! comment", "/regex/"],
                "interval": 12,
                "enabled": true
              },
              "clients": {"clients": [
                {"name": "kids-tablet", "ids": ["192.168.1.40", "192.168.50.0/24", "aa:bb:cc:dd:ee:ff", "tablet1"],
                 "use_global_settings": false, "filtering_enabled": true, "safe_search": {"enabled": true},
                 "use_global_blocked_services": false, "blocked_services": ["tiktok"], "upstreams": null,
                 "parental_enabled": true, "safebrowsing_enabled": false, "tags": null},
                {"name": "laptop", "ids": ["192.168.1.41"], "use_global_settings": true,
                 "use_global_blocked_services": true, "blocked_services": null}
              ], "auto_clients": null, "supported_tags": []},
              "rewrites": [
                {"domain": "nas.lan", "answer": "192.168.1.10", "enabled": true},
                {"domain": "nas.lan", "answer": "AAAA", "enabled": true},
                {"domain": "*.home.example", "answer": "nas.lan"},
                {"domain": "old.lan", "answer": "10.0.0.9", "enabled": false}
              ],
              "blocked_services": {"ids": ["youtube"], "schedule": {"time_zone": "Local", "sat": {"start": 0, "end": 86400000}}},
              "safe_search": {"enabled": true, "bing": true, "google": true, "youtube": false},
              "dns": {"blocking_mode": "nxdomain", "blocked_response_ttl": 10,
                      "upstream_dns": ["https://dns10.quad9.net/dns-query", "# comment", "[/lan/]192.168.1.1"]},
              "access": {"allowed_clients": null, "disallowed_clients": ["192.168.1.66", "guest", "aa:bb:cc:dd:ee:ff"], "blocked_hosts": ["version.bind"]}
            }"##,
        )
        .unwrap()
    }

    #[test]
    fn an_adguard_home_becomes_a_plan() {
        let plan = export().plan();
        assert_eq!(plan.lists.len(), 1);
        assert_eq!(plan.lists[0].name, "AdGuard DNS filter");
        assert_eq!(plan.default_lists.len(), 1);
        let rules: Vec<_> = plan.rules.iter().map(|r| r.rule.as_str()).collect();
        assert_eq!(rules, ["||ads.example.org^", "@@||good.example.org^"]);
        assert_eq!(plan.list_update_hours, Some(12));

        assert_eq!(plan.groups.len(), 1);
        let kids = &plan.groups[0];
        assert_eq!(kids.name, "kids-tablet");
        assert!(kids.safe_search);
        assert_eq!(kids.blocked_services, ["tiktok"]);
        assert_eq!(kids.lists, plan.default_lists);
        assert_eq!(plan.clients.len(), 2);
        assert_eq!(
            plan.clients[0].addresses,
            ["192.168.1.40", "192.168.50.0/24"]
        );
        assert_eq!(plan.clients[0].ids, ["tablet1"]);
        assert_eq!(plan.clients[0].group.as_deref(), Some("kids-tablet"));
        assert_eq!(plan.clients[1].group, None);

        assert_eq!(plan.default_safe_search, Some(true));
        assert_eq!(plan.default_blocked_services, ["youtube"]);
        let records: Vec<_> = plan
            .records
            .iter()
            .map(|r| (r.name.as_str(), r.value.as_str(), r.enabled))
            .collect();
        assert_eq!(
            records,
            [
                ("nas.lan", "192.168.1.10", true),
                ("*.home.example", "nas.lan", true),
                ("old.lan", "10.0.0.9", false),
            ]
        );
        assert_eq!(plan.block_response, Some(BlockResponseKind::Nxdomain));
        assert_eq!(plan.blocked_ttl, Some(10));
        assert_eq!(plan.access.blocked, ["192.168.1.66", "guest"]);
        let skipped: Vec<_> = plan.skipped.iter().map(|s| s.what.as_str()).collect();
        assert_eq!(
            skipped,
            [
                "list /opt/adguardhome/lists/local.txt",
                "rule /regex/",
                "client kids-tablet id aa:bb:cc:dd:ee:ff",
                "rewrite nas.lan AAAA",
                "access entry aa:bb:cc:dd:ee:ff",
                "disallowed domain version.bind",
            ]
        );
        assert!(plan.notes.iter().any(|note| note.contains("pauses")));
        assert!(plan.notes.iter().any(|note| note.contains("parental")));
        assert!(plan.notes.iter().any(|note| note.contains("quad9")));
    }

    #[test]
    fn nulls_everywhere_plan_nothing() {
        let export: Export = serde_json::from_str(
            r#"{"filtering": {"filters": null, "whitelist_filters": null, "user_rules": null},
                "clients": {"clients": null}, "rewrites": [], "blocked_services": {"ids": null},
                "access": {"allowed_clients": null, "disallowed_clients": null, "blocked_hosts": null}}"#,
        )
        .unwrap();
        assert_eq!(export.plan(), Plan::new("AdGuard Home"));
    }
}
