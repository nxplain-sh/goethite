//! Pi-hole v6: what its API (`/api`) returns, and the plan it makes.
//!
//! - Adlists become filter lists, in goethite's default group if Pi-hole's
//!   Default group (0) uses them, and in the groups made from Pi-hole's
//!   other groups. Allowlist subscriptions do not come over.
//! - Exact allowed and denied domains become rules (`@@|name^`, `|name^`).
//!   goethite's rules apply to every group. Regular expressions do not come
//!   over.
//! - Clients known by address or network come over, in one group each;
//!   clients known by MAC address, host name or interface do not.
//! - Local DNS records (`dns.hosts`) and CNAME records (`dns.cnameRecords`)
//!   become local records.
//! - The blocking mode and the blocked answers' TTL become settings.

use std::collections::HashMap;
use std::net::IpAddr;

use goethite_store::{BlockResponseKind, RecordKind};
use serde::Deserialize;

use crate::plan::{Plan, PlannedClient, PlannedGroup, comment_text};

/// The ID of Pi-hole's Default group.
const DEFAULT_GROUP: u32 = 0;

/// Everything read from one Pi-hole.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct Export {
    /// `GET /api/lists`.
    #[serde(default)]
    pub lists: Lists,
    /// `GET /api/domains`.
    #[serde(default)]
    pub domains: Domains,
    /// `GET /api/groups`.
    #[serde(default)]
    pub groups: Groups,
    /// `GET /api/clients`.
    #[serde(default)]
    pub clients: Clients,
    /// `GET /api/config/dns`.
    #[serde(default)]
    pub config: Config,
}

/// `GET /api/lists`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct Lists {
    /// The lists.
    #[serde(default)]
    pub lists: Vec<List>,
}

/// One subscribed list.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct List {
    /// Its URL, or a `file://` path.
    #[serde(default)]
    pub address: String,
    /// `block` or `allow`.
    #[serde(default, rename = "type")]
    pub kind: String,
    /// Whether it is used.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Free text.
    #[serde(default)]
    pub comment: Option<String>,
    /// The groups that use it, by ID.
    #[serde(default)]
    pub groups: Vec<u32>,
}

/// `GET /api/domains`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct Domains {
    /// The domains.
    #[serde(default)]
    pub domains: Vec<Domain>,
}

/// One allowed or denied domain.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct Domain {
    /// The domain (punycode) or the regular expression.
    #[serde(default)]
    pub domain: String,
    /// `allow` or `deny`.
    #[serde(default, rename = "type")]
    pub kind: String,
    /// `exact` or `regex`, as Pi-hole names it.
    #[serde(default, rename = "kind")]
    pub matching: String,
    /// Whether it is used.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Free text.
    #[serde(default)]
    pub comment: Option<String>,
    /// The groups it applies to, by ID.
    #[serde(default)]
    pub groups: Vec<u32>,
}

/// `GET /api/groups`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct Groups {
    /// The groups, Default (0) included.
    #[serde(default)]
    pub groups: Vec<Group>,
}

/// One group.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct Group {
    /// Its ID; 0 is Default.
    #[serde(default)]
    pub id: u32,
    /// Its name.
    #[serde(default)]
    pub name: String,
    /// Whether its lists and domains apply.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Free text.
    #[serde(default)]
    pub comment: Option<String>,
}

/// `GET /api/clients`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct Clients {
    /// The clients.
    #[serde(default)]
    pub clients: Vec<Client>,
}

/// One client.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct Client {
    /// An address, a network, a MAC address, a host name or `:interface`.
    #[serde(default)]
    pub client: String,
    /// The host name Pi-hole found for it, or empty.
    #[serde(default)]
    pub name: String,
    /// Free text.
    #[serde(default)]
    pub comment: Option<String>,
    /// Its groups, by ID.
    #[serde(default)]
    pub groups: Vec<u32>,
}

/// `GET /api/config/dns`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct Config {
    /// The configuration tree.
    #[serde(default)]
    pub config: ConfigTree,
}

/// The configuration tree, as far as the migration reads it.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct ConfigTree {
    /// The `dns` section.
    #[serde(default)]
    pub dns: Dns,
}

/// The `dns` section.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Dns {
    /// The upstream servers, dnsmasq `server=` syntax.
    #[serde(default)]
    pub upstreams: Vec<String>,
    /// Local DNS records: `IP host [host…] [# comment]`.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Local CNAME records: `alias[,alias…],target[,ttl]`.
    #[serde(default)]
    pub cname_records: Vec<String>,
    /// TTL of answers Pi-hole blocks itself, in seconds.
    #[serde(default, rename = "blockTTL")]
    pub block_ttl: Option<u32>,
    /// How blocked names are answered.
    #[serde(default)]
    pub blocking: Blocking,
    /// Conditional forwarding: `true|false,cidr,server[,domain]`.
    #[serde(default)]
    pub rev_servers: Vec<String>,
}

/// `dns.blocking`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct Blocking {
    /// `NULL`, `IP_NODATA_AAAA`, `IP`, `NX` or `NODATA`.
    #[serde(default)]
    pub mode: Option<String>,
}

fn yes() -> bool {
    true
}

impl Export {
    /// What goethite would get.
    pub fn plan(&self) -> Plan {
        let mut plan = Plan::new("Pi-hole");
        let groups: HashMap<u32, &Group> = self
            .groups
            .groups
            .iter()
            .map(|group| (group.id, group))
            .collect();
        let lists = plan_lists(&mut plan, &self.lists.lists);
        let names = plan_groups(&mut plan, &self.groups.groups, &lists);
        plan_domains(&mut plan, &self.domains.domains);
        plan_clients(&mut plan, &self.clients.clients, &names, &groups);
        plan_records(&mut plan, &self.config.config.dns);
        plan_settings(&mut plan, &self.config.config.dns);
        plan
    }
}

/// The block lists, and which group uses which (by Pi-hole group ID).
fn plan_lists(plan: &mut Plan, lists: &[List]) -> Vec<(String, Vec<u32>)> {
    let mut planned = Vec::new();
    for list in lists {
        if !list.kind.eq_ignore_ascii_case("block") {
            plan.skip(
                format!("allowlist {}", list.address),
                "goethite has no allowlist subscriptions; add the domains it allows as @@ rules",
            );
            continue;
        }
        if let Some(url) = plan.add_list(&list.address, None, list.enabled, list.comment.as_deref())
        {
            if list.groups.contains(&DEFAULT_GROUP) && !plan.default_lists.contains(&url) {
                plan.default_lists.push(url.clone());
            }
            planned.push((url, list.groups.clone()));
        }
    }
    planned
}

/// Groups other than Default, with their lists; returns goethite's name for
/// each Pi-hole group ID.
fn plan_groups(
    plan: &mut Plan,
    groups: &[Group],
    lists: &[(String, Vec<u32>)],
) -> HashMap<u32, String> {
    let mut names = HashMap::new();
    for group in groups.iter().filter(|group| group.id != DEFAULT_GROUP) {
        let urls = lists
            .iter()
            .filter(|(_, ids)| ids.contains(&group.id))
            .map(|(url, _)| url.clone())
            .collect();
        if !group.enabled {
            plan.note(
                "A disabled Pi-hole group becomes a goethite group with filtering off: its clients are answered unfiltered",
            );
        }
        if let Some(name) = plan.add_group(PlannedGroup {
            name: group.name.clone(),
            filtering: group.enabled,
            safe_search: false,
            lists: urls,
            blocked_services: Vec::new(),
            comment: group.comment.clone().unwrap_or_default(),
        }) {
            names.insert(group.id, name);
        }
    }
    names
}

/// Exact domains as rules; regular expressions are left out.
fn plan_domains(plan: &mut Plan, domains: &[Domain]) {
    for domain in domains {
        let name = domain.domain.trim();
        if domain.matching.eq_ignore_ascii_case("regex") {
            plan.skip(
                format!("regex {name}"),
                "goethite does not support regular expressions yet",
            );
            continue;
        }
        let rule = if domain.kind.eq_ignore_ascii_case("allow") {
            format!("@@|{name}^")
        } else {
            format!("|{name}^")
        };
        if !domain.groups.is_empty() && !domain.groups.contains(&DEFAULT_GROUP) {
            plan.note(
                "Pi-hole's domains for some groups only become rules for every group: goethite's custom rules apply to all clients",
            );
        }
        plan.add_rule(&rule, domain.enabled, domain.comment.as_deref());
    }
}

/// Clients by address or network, each in its first group other than
/// Default.
fn plan_clients(
    plan: &mut Plan,
    clients: &[Client],
    names: &HashMap<u32, String>,
    groups: &HashMap<u32, &Group>,
) {
    for client in clients {
        let label = client.client.trim();
        let mut planned = PlannedClient {
            name: [
                client.name.as_str(),
                client.comment.as_deref().unwrap_or_default(),
                label,
            ]
            .into_iter()
            .map(str::trim)
            .find(|name| !name.is_empty())
            .unwrap_or("Client")
            .to_owned(),
            comment: client
                .comment
                .as_deref()
                .map(comment_text)
                .unwrap_or_default(),
            ..PlannedClient::default()
        };
        let Some(network) = crate::plan::network(label) else {
            let why = if label.starts_with(':') {
                "known by its network interface, which goethite does not match by"
            } else if label.matches(':').count() == 5 && label.len() == 17 {
                "known by its MAC address, which goethite does not see"
            } else {
                "known by its host name, which goethite does not match by"
            };
            plan.skip(format!("client {label}"), why);
            continue;
        };
        planned.addresses.push(network);
        let mut own = client
            .groups
            .iter()
            .filter(|id| **id != DEFAULT_GROUP)
            .filter_map(|id| names.get(id));
        planned.group = own.next().cloned();
        if own.next().is_some() {
            plan.note(
                "A Pi-hole client in several groups goes into the first of them: a goethite client is in one group",
            );
        }
        if planned.group.is_none() && !client.groups.contains(&DEFAULT_GROUP) {
            let unknown = client.groups.iter().any(|id| !groups.contains_key(id));
            if !client.groups.is_empty() && !unknown {
                plan.note(
                    "A Pi-hole client in no group with lists goes into goethite's default group",
                );
            }
        }
        plan.add_client(planned);
    }
}

/// Local DNS and CNAME records.
fn plan_records(plan: &mut Plan, dns: &Dns) {
    for line in &dns.hosts {
        let line = line
            .split_once('#')
            .map_or(line.as_str(), |(record, _)| record);
        let mut fields = line.split_whitespace();
        let (Some(address), hosts) = (fields.next(), fields) else {
            continue;
        };
        let Ok(ip) = address.parse::<IpAddr>() else {
            plan.skip(
                format!("local record {line}"),
                "does not start with an address",
            );
            continue;
        };
        let kind = if ip.is_ipv4() {
            RecordKind::A
        } else {
            RecordKind::Aaaa
        };
        for host in hosts {
            plan.add_record(host, kind, address, None, true);
        }
    }
    for line in &dns.cname_records {
        let Some((aliases, target, ttl)) = cname_record(line) else {
            plan.skip(format!("CNAME record {line}"), "not alias,target[,ttl]");
            continue;
        };
        for alias in aliases {
            if alias.starts_with('*') {
                plan.skip(
                    format!("CNAME record {alias}"),
                    "Pi-hole does not treat it as a wildcard; add *. records in goethite if you want one",
                );
                continue;
            }
            plan.add_record(alias, RecordKind::Cname, target, ttl, true);
        }
    }
}

/// `alias[,alias…],target[,ttl]` as dnsmasq reads it: the last field is a
/// TTL only when there are at least three fields and it is a number.
pub fn cname_record(line: &str) -> Option<(Vec<&str>, &str, Option<u32>)> {
    let fields: Vec<&str> = line.split(',').map(str::trim).collect();
    if fields.len() < 2 || fields.iter().any(|field| field.is_empty()) {
        return None;
    }
    let (rest, ttl) = match fields.split_last() {
        Some((last, rest)) if fields.len() >= 3 && last.bytes().all(|b| b.is_ascii_digit()) => {
            (rest, last.parse().ok())
        }
        _ => (fields.as_slice(), None),
    };
    let (target, aliases) = rest.split_last()?;
    (!aliases.is_empty()).then(|| (aliases.to_vec(), *target, ttl))
}

/// The blocking mode, the blocked answers' TTL, and what stays behind.
fn plan_settings(plan: &mut Plan, dns: &Dns) {
    match dns
        .blocking
        .mode
        .as_deref()
        .map(str::to_ascii_uppercase)
        .as_deref()
    {
        Some("NULL") => plan.block_response = Some(BlockResponseKind::NullIp),
        Some("NX") => plan.block_response = Some(BlockResponseKind::Nxdomain),
        Some(other @ ("IP" | "IP_NODATA_AAAA" | "NODATA")) => plan.skip(
            format!("blocking mode {other}"),
            "goethite answers blocked names with 0.0.0.0, NXDOMAIN or REFUSED",
        ),
        Some(other) => plan.skip(
            format!("blocking mode {other}"),
            "not a mode goethite knows",
        ),
        None => {}
    }
    if let Some(ttl) = dns.block_ttl {
        plan.blocked_ttl = Some(ttl.min(86_400));
    }
    if !dns.upstreams.is_empty() {
        plan.note(format!(
            "Upstream servers are set in goethite's config file ([[upstream]]); Pi-hole used {}",
            dns.upstreams.join(", ")
        ));
    }
    for server in &dns.rev_servers {
        plan.skip(
            format!("conditional forwarding {server}"),
            "goethite does not forward chosen domains elsewhere yet",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn export() -> Export {
        serde_json::from_str(
            r#"{
              "lists": {"lists": [
                {"address": "https://example.com/ads.txt", "type": "block", "enabled": true, "comment": null, "groups": [0, 5], "id": 1},
                {"address": "http://example.com/plain.txt", "type": "block", "enabled": true, "groups": [0], "id": 2},
                {"address": "https://example.com/social.txt", "type": "block", "enabled": false, "comment": "kids", "groups": [5], "id": 3},
                {"address": "https://example.com/allow.txt", "type": "allow", "enabled": true, "groups": [0], "id": 4}
              ]},
              "domains": {"domains": [
                {"domain": "tracker.example", "unicode": "tracker.example", "type": "deny", "kind": "exact", "comment": null, "groups": [0], "enabled": true, "id": 1},
                {"domain": "good.example", "type": "allow", "kind": "exact", "groups": [0], "enabled": true, "id": 2},
                {"domain": "^ad[0-9]+\\.", "type": "deny", "kind": "regex", "groups": [0], "enabled": true, "id": 3}
              ]},
              "groups": {"groups": [
                {"name": "Default", "comment": "The default group", "enabled": true, "id": 0},
                {"name": "kids", "comment": null, "enabled": true, "id": 5}
              ]},
              "clients": {"clients": [
                {"client": "192.168.1.23", "name": "tablet.lan", "comment": null, "groups": [0, 5], "id": 1},
                {"client": "192.168.10.0/24", "name": "", "comment": "IoT", "groups": [0], "id": 2},
                {"client": "12:34:56:78:9A:BC", "name": "", "comment": null, "groups": [0], "id": 3},
                {"client": ":eth1", "name": "", "comment": null, "groups": [5], "id": 4}
              ]},
              "config": {"config": {"dns": {
                "upstreams": ["9.9.9.9"],
                "blockTTL": 2,
                "hosts": ["192.168.1.10 nas nas.lan # the NAS", "fd00::10 nas.lan"],
                "cnameRecords": ["www.lan,nas.lan", "a.lan,b.lan,nas.lan,3600", "*.lan,nas.lan"],
                "blocking": {"active": true, "mode": "NX", "edns": "TEXT"},
                "domain": {"name": "lan", "local": true}
              }}}
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn a_pi_hole_becomes_a_plan() {
        let plan = export().plan();
        let urls: Vec<_> = plan.lists.iter().filter_map(|l| l.url.as_deref()).collect();
        assert_eq!(
            urls,
            [
                "https://example.com/ads.txt",
                "https://example.com/social.txt"
            ]
        );
        assert!(!plan.lists[1].enabled);
        assert_eq!(plan.default_lists, ["https://example.com/ads.txt"]);
        assert_eq!(plan.groups.len(), 1);
        assert_eq!(plan.groups[0].name, "kids");
        assert_eq!(
            plan.groups[0].lists,
            [
                "https://example.com/ads.txt",
                "https://example.com/social.txt"
            ]
        );
        let rules: Vec<_> = plan.rules.iter().map(|r| r.rule.as_str()).collect();
        assert_eq!(rules, ["|tracker.example^", "@@|good.example^"]);
        assert_eq!(plan.clients.len(), 2);
        assert_eq!(plan.clients[0].name, "tablet.lan");
        assert_eq!(plan.clients[0].group.as_deref(), Some("kids"));
        assert_eq!(plan.clients[1].name, "IoT");
        assert_eq!(plan.clients[1].addresses, ["192.168.10.0/24"]);
        let records: Vec<_> = plan
            .records
            .iter()
            .map(|r| (r.name.as_str(), r.value.as_str(), r.ttl))
            .collect();
        assert_eq!(
            records,
            [
                ("nas", "192.168.1.10", 300),
                ("nas.lan", "192.168.1.10", 300),
                ("nas.lan", "fd00::10", 300),
                ("www.lan", "nas.lan", 300),
                ("a.lan", "nas.lan", 3600),
                ("b.lan", "nas.lan", 3600),
            ]
        );
        assert_eq!(plan.block_response, Some(BlockResponseKind::Nxdomain));
        assert_eq!(plan.blocked_ttl, Some(2));
        let skipped: Vec<_> = plan.skipped.iter().map(|s| s.what.as_str()).collect();
        assert_eq!(
            skipped,
            [
                "list http://example.com/plain.txt",
                "allowlist https://example.com/allow.txt",
                "regex ^ad[0-9]+\\.",
                "client 12:34:56:78:9A:BC",
                "client :eth1",
                "CNAME record *.lan",
            ]
        );
        assert!(plan.notes.iter().any(|note| note.contains("9.9.9.9")));
    }

    #[test]
    fn cname_records_follow_dnsmasq() {
        assert_eq!(cname_record("a,b"), Some((vec!["a"], "b", None)));
        assert_eq!(
            cname_record("a,123"),
            Some((vec!["a"], "123", None)),
            "two fields: no TTL"
        );
        assert_eq!(
            cname_record("a, b , c ,60"),
            Some((vec!["a", "b"], "c", Some(60)))
        );
        assert_eq!(cname_record("a,b,c"), Some((vec!["a", "b"], "c", None)));
        assert_eq!(cname_record("a"), None);
        assert_eq!(cname_record("a,,b"), None);
    }

    #[test]
    fn an_empty_pi_hole_plans_nothing() {
        let plan = Export::default().plan();
        assert_eq!(plan, Plan::new("Pi-hole"));
    }
}
