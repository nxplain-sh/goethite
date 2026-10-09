//! What a migration would do, and the checks every planned resource passes.

use std::collections::HashSet;
use std::fmt::Write as _;

use goethite_filter::{LineKind, parse_line};
use goethite_resolver::{Cidr, CidrError, is_client_id};
use goethite_store::model::{
    MAX_CLIENT_ADDRESSES, MAX_CLIENT_IDS, MAX_CLIENTS, MAX_COMMENT_LEN, MAX_GROUPS, MAX_LISTS,
    MAX_NAME_LEN, MAX_RECORD_TTL, MAX_RECORDS, MAX_RULES, MAX_SOURCE_LEN,
};
use goethite_store::{
    AccessSpec, BlockResponseKind, ListSpec, ManagedBy, RecordKind, RecordSpec, RuleSpec,
};

/// Everything a migration would create or change in goethite, and what it
/// leaves out.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// Where the configuration comes from, such as `Pi-hole`.
    pub source: String,
    /// Filter lists to add, unless goethite has one with the same URL.
    pub lists: Vec<ListSpec>,
    /// The URLs of the lists goethite's default group uses.
    pub default_lists: Vec<String>,
    /// Safe search for the default group, if the source sets it.
    pub default_safe_search: Option<bool>,
    /// Blocked services (AdGuard's catalog IDs) for the default group.
    pub default_blocked_services: Vec<String>,
    /// Groups to add, unless goethite has one with the same name.
    pub groups: Vec<PlannedGroup>,
    /// Clients to add, unless goethite has one with the same name.
    pub clients: Vec<PlannedClient>,
    /// Custom rules to add, unless goethite has the same rule.
    pub rules: Vec<RuleSpec>,
    /// Local DNS records to add, unless goethite has the same record.
    pub records: Vec<RecordSpec>,
    /// How blocked names are answered, if the source says.
    pub block_response: Option<BlockResponseKind>,
    /// Time to live of blocked answers, if the source says.
    pub blocked_ttl: Option<u32>,
    /// How often lists are downloaded, in hours, if the source says.
    pub list_update_hours: Option<u32>,
    /// Allowed and blocked clients to add to goethite's.
    pub access: AccessSpec,
    /// Things that come over, but behave differently in goethite.
    pub notes: Vec<String>,
    /// Things that do not come over, and why.
    pub skipped: Vec<Skipped>,
}

/// A group to add, with its lists by URL.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlannedGroup {
    /// Its name.
    pub name: String,
    /// Whether its clients are filtered.
    pub filtering: bool,
    /// Safe search for its clients.
    pub safe_search: bool,
    /// The URLs of the lists it uses.
    pub lists: Vec<String>,
    /// Blocked services (catalog IDs).
    pub blocked_services: Vec<String>,
    /// Free text.
    pub comment: String,
}

/// A client to add, with its group by name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlannedClient {
    /// Its name.
    pub name: String,
    /// Addresses and networks.
    pub addresses: Vec<String>,
    /// Client IDs.
    pub ids: Vec<String>,
    /// The group, by name; `None` for the default group.
    pub group: Option<String>,
    /// Free text.
    pub comment: String,
}

/// Something the migration leaves out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped {
    /// What it is, such as `list http://example.com/hosts`.
    pub what: String,
    /// Why it does not come over.
    pub why: String,
}

impl Plan {
    /// An empty plan for `source`.
    pub fn new(source: &str) -> Self {
        Self {
            source: source.to_owned(),
            ..Self::default()
        }
    }

    /// Leaves `what` out, because `why`.
    pub(crate) fn skip(&mut self, what: impl Into<String>, why: impl Into<String>) {
        self.skipped.push(Skipped {
            what: what.into(),
            why: why.into(),
        });
    }

    /// Notes something that behaves differently in goethite, once.
    pub(crate) fn note(&mut self, note: impl Into<String>) {
        let note = note.into();
        if !self.notes.contains(&note) {
            self.notes.push(note);
        }
    }

    /// Adds a list, if goethite can download it and does not have it yet.
    /// Returns its URL, for the groups that use it.
    pub(crate) fn add_list(
        &mut self,
        url: &str,
        name: Option<&str>,
        enabled: bool,
        comment: Option<&str>,
    ) -> Option<String> {
        let what = format!("list {url}");
        if self
            .lists
            .iter()
            .any(|list| list.url.as_deref() == Some(url))
        {
            return Some(url.to_owned());
        }
        if !url.starts_with("https://") || url.len() > MAX_SOURCE_LEN {
            let why = if url.starts_with("http://") {
                "goethite downloads lists over HTTPS only; add it with https:// if its host offers that"
            } else if url.contains("://") {
                "goethite downloads lists over HTTPS only"
            } else {
                "a file on the old server; copy it over and add it as a local list"
            };
            self.skip(what, why);
            return None;
        }
        if self.lists.len() >= MAX_LISTS {
            self.skip(what, format!("goethite holds at most {MAX_LISTS} lists"));
            return None;
        }
        let name = name
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map_or_else(|| list_name(url), text_name);
        self.lists.push(ListSpec {
            name,
            url: Some(url.to_owned()),
            path: None,
            enabled,
            comment: comment.map(comment_text).unwrap_or_default(),
            managed_by: ManagedBy::Api,
        });
        Some(url.to_owned())
    }

    /// Adds a custom rule, if goethite supports its syntax.
    pub(crate) fn add_rule(&mut self, rule: &str, enabled: bool, comment: Option<&str>) {
        let rule = rule.trim();
        match parse_line(rule, |_| {}) {
            LineKind::Rules(_) => {}
            LineKind::Ignored => return,
            LineKind::Unsupported(reason) => {
                self.skip(
                    format!("rule {rule}"),
                    format!("not supported by goethite yet ({reason})"),
                );
                return;
            }
            LineKind::Invalid(reason) => {
                self.skip(
                    format!("rule {rule}"),
                    format!("not a valid rule ({reason})"),
                );
                return;
            }
        }
        if self.rules.iter().any(|existing| existing.rule == rule) {
            return;
        }
        if self.rules.len() >= MAX_RULES {
            self.skip(
                format!("rule {rule}"),
                format!("goethite holds at most {MAX_RULES} rules"),
            );
            return;
        }
        self.rules.push(RuleSpec {
            rule: rule.to_owned(),
            enabled,
            comment: comment.map(comment_text).unwrap_or_default(),
            managed_by: ManagedBy::Api,
        });
    }

    /// Adds a local record, if it is valid and does not clash with another:
    /// a name with an enabled CNAME has no other enabled record.
    pub(crate) fn add_record(
        &mut self,
        name: &str,
        kind: RecordKind,
        value: &str,
        ttl: Option<u32>,
        enabled: bool,
    ) {
        let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
        let value = value.trim().trim_end_matches('.');
        let value = if kind == RecordKind::Cname {
            value.to_ascii_lowercase()
        } else {
            value.to_owned()
        };
        let kind_name = match kind {
            RecordKind::A => "A",
            RecordKind::Aaaa => "AAAA",
            RecordKind::Cname => "CNAME",
        };
        let what = format!("record {name} {kind_name} {value}");
        let spec = RecordSpec {
            name,
            kind,
            value,
            ttl: ttl.unwrap_or(300).min(MAX_RECORD_TTL),
            enabled,
            comment: String::new(),
            managed_by: ManagedBy::Api,
        };
        if spec.local().is_none() {
            self.skip(what, "not a name and value goethite can answer");
            return;
        }
        let same_name = |other: &RecordSpec| other.name == spec.name;
        if self
            .records
            .iter()
            .any(|other| same_name(other) && other.kind == spec.kind && other.value == spec.value)
        {
            return;
        }
        let clash = spec.enabled
            && self.records.iter().any(|other| {
                other.enabled
                    && same_name(other)
                    && (other.kind == RecordKind::Cname || spec.kind == RecordKind::Cname)
            });
        if clash {
            self.skip(
                what,
                "the name has a CNAME and other records; goethite answers a CNAME alone",
            );
            return;
        }
        if self.records.len() >= MAX_RECORDS {
            self.skip(
                what,
                format!("goethite holds at most {MAX_RECORDS} records"),
            );
            return;
        }
        self.records.push(spec);
    }

    /// Adds a group under a name no other planned group has.
    pub(crate) fn add_group(&mut self, mut group: PlannedGroup) -> Option<String> {
        if self.groups.len() >= MAX_GROUPS.saturating_sub(1) {
            self.skip(
                format!("group {}", group.name),
                format!("goethite holds at most {MAX_GROUPS} groups"),
            );
            return None;
        }
        group.name = self.unique_name(&group.name, |plan, name| {
            plan.groups.iter().any(|other| other.name == name)
        });
        group.comment = comment_text(&group.comment);
        let name = group.name.clone();
        self.groups.push(group);
        Some(name)
    }

    /// Adds a client, if it has an address or a client ID left.
    pub(crate) fn add_client(&mut self, mut client: PlannedClient) {
        if client.addresses.is_empty() && client.ids.is_empty() {
            self.skip(
                format!("client {}", client.name),
                "no address, network or client ID goethite can match it by",
            );
            return;
        }
        if self.clients.len() >= MAX_CLIENTS {
            self.skip(
                format!("client {}", client.name),
                format!("goethite holds at most {MAX_CLIENTS} clients"),
            );
            return;
        }
        client.addresses.truncate(MAX_CLIENT_ADDRESSES);
        client.ids.truncate(MAX_CLIENT_IDS);
        client.name = self.unique_name(&client.name, |plan, name| {
            plan.clients.iter().any(|other| other.name == name)
        });
        client.comment = comment_text(&client.comment);
        self.clients.push(client);
    }

    /// Takes an addresses, network or client ID for a client: `true` if it
    /// went into `client`.
    pub(crate) fn add_client_id(client: &mut PlannedClient, entry: &str) -> bool {
        let entry = entry.trim();
        if let Some(network) = network(entry) {
            if !client.addresses.contains(&network) {
                client.addresses.push(network);
            }
            return true;
        }
        let id = entry.to_ascii_lowercase();
        if is_client_id(&id) && !client.ids.contains(&id) {
            client.ids.push(id);
            return true;
        }
        false
    }

    /// `name`, or `name (2)`, `name (3)`… if `taken` says it is in use.
    fn unique_name(&self, name: &str, taken: impl Fn(&Self, &str) -> bool) -> String {
        let base = text_name(name);
        if !taken(self, &base) {
            return base;
        }
        for n in 2..1000_u32 {
            let suffix = format!(" ({n})");
            let stem: String = base
                .chars()
                .take(MAX_NAME_LEN.saturating_sub(suffix.len()))
                .collect();
            let candidate = format!("{stem}{suffix}");
            if !taken(self, &candidate) {
                return candidate;
            }
        }
        base
    }

    /// Adds `entries` (addresses, networks, client IDs) to the access list
    /// `allowed` or `blocked`, skipping what goethite cannot match.
    pub(crate) fn add_access(&mut self, entries: &[String], allowed: bool) {
        let mut seen = HashSet::new();
        for entry in entries {
            let entry = entry.trim();
            if entry.is_empty() || entry.starts_with('#') {
                continue;
            }
            let parsed = network(entry).or_else(|| {
                let id = entry.to_ascii_lowercase();
                is_client_id(&id).then_some(id)
            });
            let Some(parsed) = parsed else {
                self.skip(
                    format!("access entry {entry}"),
                    "not an address, a network or a client ID",
                );
                continue;
            };
            if !seen.insert(parsed.clone()) {
                continue;
            }
            let list = if allowed {
                &mut self.access.allowed
            } else {
                &mut self.access.blocked
            };
            if !list.contains(&parsed) {
                list.push(parsed);
            }
        }
    }

    /// A report for people: what comes over, what behaves differently and
    /// what is left out.
    pub fn report(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "From {}:", self.source);
        let line = |out: &mut String, count: usize, what: &str| {
            if count > 0 {
                let _ = writeln!(out, "  {count} {what}");
            }
        };
        line(&mut out, self.lists.len(), "filter lists");
        line(&mut out, self.groups.len(), "groups");
        line(&mut out, self.clients.len(), "clients");
        line(&mut out, self.rules.len(), "custom rules");
        line(&mut out, self.records.len(), "local records");
        let settings = [
            self.block_response.is_some(),
            self.blocked_ttl.is_some(),
            self.list_update_hours.is_some(),
            self.default_safe_search.is_some(),
            !self.default_blocked_services.is_empty(),
            !self.access.allowed.is_empty() || !self.access.blocked.is_empty(),
        ];
        if settings.contains(&true) {
            let _ = writeln!(out, "  settings for the default group and the node");
        }
        if !self.notes.is_empty() {
            let _ = writeln!(out, "\nDifferent in goethite:");
            for note in &self.notes {
                let _ = writeln!(out, "  - {note}");
            }
        }
        if !self.skipped.is_empty() {
            let _ = writeln!(out, "\nLeft out ({}):", self.skipped.len());
            for skipped in &self.skipped {
                let _ = writeln!(out, "  - {}: {}", skipped.what, skipped.why);
            }
        }
        out
    }
}

/// An address or network in goethite's form, if `text` is one. A network
/// with host bits set becomes the network it is in.
pub(crate) fn network(text: &str) -> Option<String> {
    match text.parse::<Cidr>() {
        Ok(network) | Err(CidrError::HostBits { network, .. }) => Some(cidr_text(network)),
        Err(CidrError::Address(_) | CidrError::Prefix(_)) => None,
    }
}

/// A network as goethite stores it: a bare address for a single host.
fn cidr_text(network: Cidr) -> String {
    let host = if network.addr().is_ipv4() { 32 } else { 128 };
    if network.prefix() == host {
        network.addr().to_string()
    } else {
        format!("{}/{}", network.addr(), network.prefix())
    }
}

/// A name for people: trimmed, at most goethite's longest.
pub(crate) fn text_name(text: &str) -> String {
    let name: String = text.trim().chars().take(MAX_NAME_LEN).collect();
    if name.trim().is_empty() {
        "Imported".to_owned()
    } else {
        name
    }
}

/// A comment: trimmed, at most goethite's longest.
pub(crate) fn comment_text(text: &str) -> String {
    text.trim().chars().take(MAX_COMMENT_LEN).collect()
}

/// A name for a list from its URL: the host and the file name.
fn list_name(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let host = rest.split('/').next().unwrap_or_default();
    let file = rest
        .rsplit('/')
        .find(|part| !part.is_empty() && *part != host)
        .unwrap_or_default();
    if file.is_empty() {
        text_name(host)
    } else {
        text_name(&format!("{host}: {file}"))
    }
}

/// Standard Base64 with padding (RFC 4648), for HTTP Basic credentials.
pub fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let symbol = |index: u32| {
        ALPHABET
            .get(usize::try_from(index & 63).unwrap_or_default())
            .map_or('=', |&byte| char::from(byte))
    };
    let mut out = String::with_capacity(input.len().div_ceil(3).saturating_mul(4));
    for chunk in input.chunks(3) {
        let byte = |index: usize| u32::from(chunk.get(index).copied().unwrap_or_default());
        let bits = (byte(0) << 16) | (byte(1) << 8) | byte(2);
        out.push(symbol(bits >> 18));
        out.push(symbol(bits >> 12));
        out.push(if chunk.len() > 1 {
            symbol(bits >> 6)
        } else {
            '='
        });
        out.push(if chunk.len() > 2 { symbol(bits) } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc_4648() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
            ("admin:pässword", "YWRtaW46cMOkc3N3b3Jk"),
        ] {
            assert_eq!(base64(input.as_bytes()), expected, "{input}");
        }
    }

    #[test]
    fn lists_must_be_https_and_get_names() {
        let mut plan = Plan::new("test");
        assert!(
            plan.add_list("https://example.com/lists/ads.txt", None, true, None)
                .is_some()
        );
        assert_eq!(plan.lists[0].name, "example.com: ads.txt");
        assert!(
            plan.add_list("http://example.com/hosts", None, true, None)
                .is_none()
        );
        assert!(
            plan.add_list("/etc/lists/local.txt", None, true, None)
                .is_none()
        );
        assert_eq!(plan.skipped.len(), 2);
        assert!(plan.skipped[0].why.contains("HTTPS"));
        assert!(
            plan.add_list("https://example.com/lists/ads.txt", None, true, None)
                .is_some(),
            "a list seen again is found, not added"
        );
        assert_eq!(plan.lists.len(), 1);
    }

    #[test]
    fn records_keep_a_cname_alone() {
        let mut plan = Plan::new("test");
        plan.add_record("NAS.lan.", RecordKind::A, "192.168.1.10", None, true);
        plan.add_record("nas.lan", RecordKind::A, "192.168.1.10", None, true);
        plan.add_record("nas.lan", RecordKind::Cname, "other.lan", None, true);
        plan.add_record("www.lan", RecordKind::Cname, "nas.lan", Some(60), true);
        plan.add_record("bad name.lan", RecordKind::A, "10.0.0.1", None, true);
        assert_eq!(plan.records.len(), 2);
        assert_eq!(plan.records[0].name, "nas.lan");
        assert_eq!(plan.records[1].ttl, 60);
        assert_eq!(plan.skipped.len(), 2);
    }

    #[test]
    fn networks_and_client_ids() {
        assert_eq!(network("192.168.1.5"), Some("192.168.1.5".into()));
        assert_eq!(network("192.168.1.5/24"), Some("192.168.1.0/24".into()));
        assert_eq!(network("fd00::/64"), Some("fd00::/64".into()));
        assert_eq!(network("aa:bb:cc:dd:ee:ff"), None);
        let mut client = PlannedClient::default();
        assert!(Plan::add_client_id(&mut client, "Tablet-1"));
        assert!(Plan::add_client_id(&mut client, "10.0.0.0/8"));
        assert!(!Plan::add_client_id(&mut client, "aa:bb:cc:dd:ee:ff"));
        assert_eq!(client.ids, vec!["tablet-1".to_owned()]);
        assert_eq!(client.addresses, vec!["10.0.0.0/8".to_owned()]);
    }

    #[test]
    fn rules_goethite_cannot_use_are_left_out() {
        let mut plan = Plan::new("test");
        plan.add_rule("||ads.example^", true, None);
        plan.add_rule("! a comment", true, None);
        plan.add_rule("/ads[0-9]+\\.example/", true, None);
        assert_eq!(plan.rules.len(), 1);
        assert_eq!(plan.skipped.len(), 1);
    }
}
