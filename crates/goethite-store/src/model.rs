//! The configuration resources the store holds, and their validation.
//!
//! Every resource has an ID, a revision that counts its updates, creation
//! and update times, and a *spec*: the part a client writes. Requests carry
//! only the spec; responses nest it under `spec`. Specs reject unknown
//! fields, so a typo is an error rather than a silently ignored setting.

use std::collections::HashSet;

use goethite_filter::{LineKind, parse_line};
use std::net::{Ipv4Addr, Ipv6Addr};

use goethite_proto::Name;
use goethite_resolver::{
    AccessList, Cidr, LocalData, LocalRecord, MAX_ACCESS_ENTRIES, MAX_LOCAL_RECORDS, MAX_SCHEDULES,
    MAX_SERVICES, TEST_NAME, is_client_id, is_service_id,
};
use jiff::Timestamp;
use jiff::tz::TimeZone;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The ID of the group that clients without a group of their own use.
pub const DEFAULT_GROUP: &str = "default";

/// The most filter lists: the filter tells 64 sources apart and the custom
/// rules take one.
pub const MAX_LISTS: usize = 63;
/// The most custom rules.
pub const MAX_RULES: usize = 50_000;
/// The most groups.
pub const MAX_GROUPS: usize = 256;
/// The most clients.
pub const MAX_CLIENTS: usize = 10_000;
/// The most addresses one client has.
pub const MAX_CLIENT_ADDRESSES: usize = 64;
/// The most client IDs one client has.
pub const MAX_CLIENT_IDS: usize = 16;
/// The most schedules.
pub const MAX_SCHEDULE_COUNT: usize = MAX_SCHEDULES;
/// The most local DNS records.
pub const MAX_RECORDS: usize = MAX_LOCAL_RECORDS;
/// The longest clients may cache a local record, in seconds: a day.
pub const MAX_RECORD_TTL: u32 = 86_400;
/// The most blocked services one group names, schedules included.
pub const MAX_BLOCKED_SERVICES: usize = MAX_SERVICES;
/// The most time windows in one schedule.
pub const MAX_WINDOWS: usize = 32;
/// The longest name, in characters.
pub const MAX_NAME_LEN: usize = 100;
/// The longest comment, in characters.
pub const MAX_COMMENT_LEN: usize = 1000;
/// The longest list URL or path, in bytes.
pub const MAX_SOURCE_LEN: usize = 2048;

/// Who manages a resource. Resources managed by Terraform are read-only in
/// the web UI and the TUI, so they do not drift from their definition.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ManagedBy {
    /// Created through the API, the web UI or the TUI.
    #[default]
    Api,
    /// Created by the Terraform provider.
    Terraform,
    /// Imported from the `[filter]` table of the config file.
    ConfigFile,
}

/// How blocked names are answered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BlockResponseKind {
    /// `0.0.0.0` for A, `::` for AAAA, an empty answer for other types.
    #[default]
    NullIp,
    /// NXDOMAIN: the name does not exist.
    Nxdomain,
    /// REFUSED.
    Refused,
}

/// Node-wide filtering settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SettingsSpec {
    /// The master switch: when off, nothing is filtered for anyone.
    #[serde(default = "yes")]
    pub protection: bool,
    /// How blocked names are answered.
    #[serde(default)]
    pub block_response: BlockResponseKind,
    /// Time to live of null-IP answers, in seconds, at most 86,400.
    #[serde(default = "default_blocked_ttl")]
    pub blocked_ttl: u32,
    /// How often downloaded lists are refreshed, in hours, 1 to 168.
    #[serde(default = "default_update_hours")]
    pub list_update_hours: u32,
    /// Which clients are answered at all; by default, everyone.
    #[serde(default)]
    pub access: AccessSpec,
}

impl Default for SettingsSpec {
    fn default() -> Self {
        Self {
            protection: true,
            block_response: BlockResponseKind::default(),
            blocked_ttl: default_blocked_ttl(),
            list_update_hours: default_update_hours(),
            access: AccessSpec::default(),
        }
    }
}

/// Which clients are answered, over every transport. An entry is an IP
/// address, a network in CIDR notation (`192.168.1.0/24`) or a client ID. A
/// query is answered when its client is on `allowed`, or `allowed` is
/// empty, and is not on `blocked`. Loopback addresses always pass, but a
/// blocked client ID is refused even there. Refused UDP queries get no
/// answer; refused connections are closed before their TLS handshake; a
/// client ID refused after it is known gets `REFUSED`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AccessSpec {
    /// When not empty, only these clients are answered. At most 10,000
    /// entries.
    #[serde(default)]
    pub allowed: Vec<String>,
    /// These clients are never answered. At most 10,000 entries.
    #[serde(default)]
    pub blocked: Vec<String>,
}

impl AccessSpec {
    /// The networks and client IDs in `entries`, which must be valid, as
    /// [`ConfigSnapshot::validate`] makes sure; anything else is skipped.
    pub fn list(entries: &[String]) -> AccessList {
        let mut list = AccessList::default();
        for entry in entries {
            match parse_access_entry(entry) {
                Some(AccessEntry::Network(network)) => list.networks.push(network),
                Some(AccessEntry::Id(id)) => list.ids.push(id.into()),
                None => {}
            }
        }
        list
    }

    fn validate(&self) -> Result<(), ValidationError> {
        for (name, entries) in [("allowed", &self.allowed), ("blocked", &self.blocked)] {
            let field = format!("settings.access.{name}");
            if entries.len() > MAX_ACCESS_ENTRIES {
                return Err(invalid(
                    field,
                    format!("has more than {MAX_ACCESS_ENTRIES} entries"),
                ));
            }
            let mut seen = HashSet::new();
            for (index, entry) in entries.iter().enumerate() {
                let at = format!("{field}[{index}]");
                let parsed = parse_access_entry(entry).ok_or_else(|| {
                    invalid(
                        &at,
                        "needs an IP address, a network such as 192.168.1.0/24, or a client ID",
                    )
                })?;
                if !seen.insert(parsed) {
                    return Err(invalid(at, format!("{entry} is listed twice")));
                }
            }
        }
        Ok(())
    }
}

/// One entry of an access list.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum AccessEntry<'a> {
    Network(Cidr),
    Id(&'a str),
}

/// An address or network, or else a client ID; `None` for anything else,
/// such as a network with host bits set.
fn parse_access_entry(entry: &str) -> Option<AccessEntry<'_>> {
    match entry.parse::<Cidr>() {
        Ok(network) => Some(AccessEntry::Network(network)),
        Err(_) => is_client_id(entry).then_some(AccessEntry::Id(entry)),
    }
}

/// The settings, with their revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Settings {
    /// Counts updates, starting at 1.
    pub revision: u64,
    /// When they last changed.
    pub updated_at: Timestamp,
    /// The settings.
    pub spec: SettingsSpec,
}

/// A filter list: a file on disk or an `https://` URL.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ListSpec {
    /// A name for people.
    pub name: String,
    /// Where to download the list from: an `https://` URL. Exactly one of
    /// `url` and `path` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// The list file: an absolute path on the node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Whether the list is used at all.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Free text.
    #[serde(default)]
    pub comment: String,
    /// Who manages the list.
    #[serde(default)]
    pub managed_by: ManagedBy,
}

/// A custom filtering rule, in any syntax the filter lists use.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    /// The rule, such as `||ads.example^` or `@@||good.example^`.
    pub rule: String,
    /// Whether the rule is used.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Free text.
    #[serde(default)]
    pub comment: String,
    /// Who manages the rule.
    #[serde(default)]
    pub managed_by: ManagedBy,
}

/// The type of a local DNS record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub enum RecordKind {
    /// An IPv4 address.
    #[serde(rename = "A")]
    A,
    /// An IPv6 address.
    #[serde(rename = "AAAA")]
    Aaaa,
    /// Another name, which answers for this one.
    #[serde(rename = "CNAME")]
    Cname,
}

/// A DNS record goethite answers itself, for every client and before the
/// filter: a device on the local network such as `nas.lan`, or every name
/// below one (`*.home.example`). A name with records answers only from
/// them; a CNAME's target is resolved like any other name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordSpec {
    /// The name, such as `nas.lan`, or `*.home.example` for every name below
    /// `home.example` (not that name itself).
    pub name: String,
    /// What the record holds.
    #[serde(rename = "type")]
    pub kind: RecordKind,
    /// An IPv4 address for `A`, an IPv6 address for `AAAA`, a name for
    /// `CNAME`.
    pub value: String,
    /// How long clients may cache it, in seconds, at most 86,400.
    #[serde(default = "default_record_ttl")]
    pub ttl: u32,
    /// Whether the record is answered.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Free text.
    #[serde(default)]
    pub comment: String,
    /// Who manages the record.
    #[serde(default)]
    pub managed_by: ManagedBy,
}

impl RecordSpec {
    /// The record as the resolver answers it, or `None` if it is not valid
    /// (which [`ConfigSnapshot::validate`] prevents).
    pub fn local(&self) -> Option<LocalRecord> {
        let (name, wildcard) = record_name(&self.name).ok()?;
        let data = record_data(self.kind, &self.value).ok()?;
        Some(LocalRecord {
            name,
            wildcard,
            data,
            ttl: self.ttl,
        })
    }

    fn validate(&self, field: &str) -> Result<(), ValidationError> {
        check_comment(&format!("{field}.comment"), &self.comment)?;
        record_name(&self.name).map_err(|message| invalid(format!("{field}.name"), message))?;
        record_data(self.kind, &self.value)
            .map_err(|message| invalid(format!("{field}.value"), message))?;
        if self.ttl > MAX_RECORD_TTL {
            return Err(invalid(
                format!("{field}.ttl"),
                format!("must be at most {MAX_RECORD_TTL}"),
            ));
        }
        Ok(())
    }

    /// What tells two records apart: the name, whether it is a wildcard,
    /// the type and the value, ignoring case.
    fn key(&self) -> (String, RecordKind, String) {
        (
            self.name.trim_end_matches('.').to_ascii_lowercase(),
            self.kind,
            self.value.trim_end_matches('.').to_ascii_lowercase(),
        )
    }
}

/// A record's name, and whether it is a wildcard (`*.` in front).
fn record_name(text: &str) -> Result<(Name, bool), String> {
    let (wildcard, rest) = match text.strip_prefix("*.") {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    if rest.contains('*') {
        return Err("may have a wildcard only as its first label, as in *.home.example".into());
    }
    let name: Name = rest.parse().map_err(|err| format!("{err}"))?;
    if name.is_root() {
        return Err("must not be the root".into());
    }
    let own: Name = TEST_NAME.parse().map_err(|err| format!("{err}"))?;
    if name.is_within(&own) {
        return Err(format!(
            "is under {TEST_NAME}, which goethite answers itself"
        ));
    }
    Ok((name, wildcard))
}

/// A record's value, for its type.
fn record_data(kind: RecordKind, value: &str) -> Result<LocalData, String> {
    match kind {
        RecordKind::A => value
            .parse::<Ipv4Addr>()
            .map(LocalData::A)
            .map_err(|_| "must be an IPv4 address".into()),
        RecordKind::Aaaa => value
            .parse::<Ipv6Addr>()
            .map(LocalData::Aaaa)
            .map_err(|_| "must be an IPv6 address".into()),
        RecordKind::Cname => {
            if value.contains('*') {
                return Err("must be a name, without wildcards".into());
            }
            let target: Name = value.parse().map_err(|err| format!("{err}"))?;
            if target.is_root() {
                return Err("must not be the root".into());
            }
            Ok(LocalData::Cname(target))
        }
    }
}

/// A list a group uses, always or while a schedule is active.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupList {
    /// The list's ID.
    pub list: String,
    /// The schedule's ID: the list applies only while the schedule is
    /// active. Without one it always applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
}

/// A service a group blocks, always or while a schedule is active.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BlockedService {
    /// The service's ID in the services catalog (`GET /api/v1/services`),
    /// such as `tiktok`. An ID the catalog does not have blocks nothing.
    pub service: String,
    /// The schedule's ID: the service is blocked only while the schedule is
    /// active. Without one it is always blocked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
}

/// A group of clients with the same filtering.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupSpec {
    /// A name for people.
    pub name: String,
    /// Whether the group's clients are filtered at all.
    #[serde(default = "yes")]
    pub filtering: bool,
    /// Whether search engines are sent to their safe endpoints.
    #[serde(default)]
    pub safe_search: bool,
    /// The lists the group uses. Custom rules always apply while filtering
    /// is on.
    #[serde(default)]
    pub lists: Vec<GroupList>,
    /// The services the group blocks, such as TikTok or YouTube: every name
    /// the service uses, whatever the lists say. They apply while filtering
    /// is on.
    #[serde(default)]
    pub blocked_services: Vec<BlockedService>,
    /// Free text.
    #[serde(default)]
    pub comment: String,
    /// Who manages the group.
    #[serde(default)]
    pub managed_by: ManagedBy,
}

/// A device or network, identified by its addresses or its client IDs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientSpec {
    /// A name for people.
    pub name: String,
    /// IP addresses or networks in CIDR notation, such as `192.168.1.23`
    /// or `192.168.1.0/24`. The longest network containing a query's source
    /// address decides which client asked. May be empty for a client known
    /// by its client IDs only.
    pub addresses: Vec<String>,
    /// Client IDs, such as `anna-phone`: over DNS over TLS, HTTPS or QUIC a
    /// device can name itself, in the server name (`anna-phone.dns.example`)
    /// or the DNS over HTTPS path (`/dns-query/anna-phone`), wherever it is.
    /// A known ID decides which client asked before the address does. 1 to
    /// 63 lowercase letters, digits and hyphens, not at either end.
    #[serde(default)]
    pub ids: Vec<String>,
    /// The group's ID.
    #[serde(default = "default_group")]
    pub group: String,
    /// Free text.
    #[serde(default)]
    pub comment: String,
    /// Who manages the client.
    #[serde(default)]
    pub managed_by: ManagedBy,
}

/// A day of the week.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
#[allow(missing_docs, reason = "the names say it")]
pub enum Weekday {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

impl Weekday {
    fn from_jiff(day: jiff::civil::Weekday) -> Self {
        match day {
            jiff::civil::Weekday::Monday => Self::Mon,
            jiff::civil::Weekday::Tuesday => Self::Tue,
            jiff::civil::Weekday::Wednesday => Self::Wed,
            jiff::civil::Weekday::Thursday => Self::Thu,
            jiff::civil::Weekday::Friday => Self::Fri,
            jiff::civil::Weekday::Saturday => Self::Sat,
            jiff::civil::Weekday::Sunday => Self::Sun,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::Mon => Self::Sun,
            Self::Tue => Self::Mon,
            Self::Wed => Self::Tue,
            Self::Thu => Self::Wed,
            Self::Fri => Self::Thu,
            Self::Sat => Self::Fri,
            Self::Sun => Self::Sat,
        }
    }
}

/// A weekly time window. `end` before `start` runs past midnight into the
/// next day.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Window {
    /// The days the window starts on.
    pub days: Vec<Weekday>,
    /// Local start time, `HH:MM`.
    pub start: String,
    /// Local end time, `HH:MM` (`24:00` for midnight).
    pub end: String,
}

/// When something applies: weekly time windows in a time zone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ScheduleSpec {
    /// A name for people.
    pub name: String,
    /// An IANA time zone such as `Europe/Berlin`, or `UTC`.
    #[serde(default = "utc")]
    pub time_zone: String,
    /// The windows.
    pub windows: Vec<Window>,
    /// Free text.
    #[serde(default)]
    pub comment: String,
    /// Who manages the schedule.
    #[serde(default)]
    pub managed_by: ManagedBy,
}

impl ScheduleSpec {
    /// Whether the schedule is active at `now`. False if its time zone or a
    /// window is invalid, which validation prevents.
    pub fn is_active(&self, now: Timestamp) -> bool {
        let Ok(tz) = TimeZone::get(&self.time_zone) else {
            return false;
        };
        let local = now.to_zoned(tz);
        let day = Weekday::from_jiff(local.weekday());
        let minute = i32::from(local.hour())
            .saturating_mul(60)
            .saturating_add(i32::from(local.minute()));
        self.windows.iter().any(|window| {
            let (Some(start), Some(end)) = (minutes(&window.start), minutes(&window.end)) else {
                return false;
            };
            let on = |day: Weekday| window.days.contains(&day);
            if start < end {
                on(day) && (start..end).contains(&minute)
            } else {
                (on(day) && minute >= start) || (on(day.previous()) && minute < end)
            }
        })
    }
}

/// Minutes since midnight for `HH:MM`, where `24:00` is 1440.
fn minutes(text: &str) -> Option<i32> {
    let (hours, mins) = text.split_once(':')?;
    if hours.len() != 2 || mins.len() != 2 {
        return None;
    }
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if !digits(hours) || !digits(mins) {
        return None;
    }
    let hours: i32 = hours.parse().ok()?;
    let mins: i32 = mins.parse().ok()?;
    match (hours, mins) {
        (0..=23, 0..=59) => Some(hours.saturating_mul(60).saturating_add(mins)),
        (24, 0) => Some(1440),
        _ => None,
    }
}

fn yes() -> bool {
    true
}

fn utc() -> String {
    "UTC".to_owned()
}

fn default_group() -> String {
    DEFAULT_GROUP.to_owned()
}

fn default_blocked_ttl() -> u32 {
    10
}

fn default_update_hours() -> u32 {
    24
}

fn default_record_ttl() -> u32 {
    300
}

macro_rules! resource {
    ($(#[$doc:meta])* $name:ident, $spec:ident, $kind:literal, $prefix:literal, $field:ident) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
        pub struct $name {
            /// The ID, chosen by goethite.
            pub id: String,
            /// Counts updates, starting at 1.
            pub revision: u64,
            /// When it was created.
            pub created_at: Timestamp,
            /// When it last changed.
            pub updated_at: Timestamp,
            /// What it is.
            pub spec: $spec,
        }

        impl crate::store::Kind for $name {
            type Spec = $spec;
            const NAME: &'static str = $kind;
            const PREFIX: &'static str = $prefix;
            const TABLE_NAME: &'static str = concat!($kind, "s");

            fn new(id: String, revision: u64, created_at: Timestamp, updated_at: Timestamp, spec: $spec) -> Self {
                Self { id, revision, created_at, updated_at, spec }
            }
            fn id(&self) -> &str {
                &self.id
            }
            fn revision(&self) -> u64 {
                self.revision
            }
            fn created_at(&self) -> Timestamp {
                self.created_at
            }
            fn spec(&self) -> &$spec {
                &self.spec
            }
            fn all(config: &ConfigSnapshot) -> &Vec<Self> {
                &config.$field
            }
            fn all_mut(config: &mut ConfigSnapshot) -> &mut Vec<Self> {
                &mut config.$field
            }
        }
    };
}

resource!(
    /// A stored filter list.
    List, ListSpec, "list", "li", lists
);
resource!(
    /// A stored custom rule.
    Rule, RuleSpec, "rule", "ru", rules
);
resource!(
    /// A stored group.
    Group, GroupSpec, "group", "gr", groups
);
resource!(
    /// A stored client.
    Client, ClientSpec, "client", "cl", clients
);
resource!(
    /// A stored local DNS record.
    Record, RecordSpec, "record", "rc", records
);
resource!(
    /// A stored schedule.
    Schedule, ScheduleSpec, "schedule", "sc", schedules
);

/// The whole configuration, as of one moment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ConfigSnapshot {
    /// The settings.
    pub settings: Settings,
    /// The filter lists, oldest first.
    pub lists: Vec<List>,
    /// The custom rules, oldest first.
    pub rules: Vec<Rule>,
    /// The groups, the default group first.
    pub groups: Vec<Group>,
    /// The clients, oldest first.
    pub clients: Vec<Client>,
    /// The schedules, oldest first.
    pub schedules: Vec<Schedule>,
    /// The local DNS records, oldest first.
    #[serde(default)]
    pub records: Vec<Record>,
}

/// A configuration that breaks a rule.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{field}: {message}")]
pub struct ValidationError {
    /// Which resource and field, such as `clients[cl_…].addresses[0]`.
    pub field: String,
    /// What is wrong.
    pub message: String,
    /// Whether it is a reference to something missing (or still in use),
    /// rather than a bad value.
    pub conflict: bool,
}

fn invalid(field: impl Into<String>, message: impl Into<String>) -> ValidationError {
    ValidationError {
        field: field.into(),
        message: message.into(),
        conflict: false,
    }
}

fn conflict(field: impl Into<String>, message: impl Into<String>) -> ValidationError {
    ValidationError {
        field: field.into(),
        message: message.into(),
        conflict: true,
    }
}

fn check_name(field: &str, name: &str) -> Result<(), ValidationError> {
    if name.trim().is_empty() {
        return Err(invalid(field, "must not be empty"));
    }
    if name.chars().count() > MAX_NAME_LEN {
        return Err(invalid(
            field,
            format!("is longer than {MAX_NAME_LEN} characters"),
        ));
    }
    if name.chars().any(char::is_control) {
        return Err(invalid(field, "must not contain control characters"));
    }
    Ok(())
}

fn check_comment(field: &str, comment: &str) -> Result<(), ValidationError> {
    if comment.chars().count() > MAX_COMMENT_LEN {
        return Err(invalid(
            field,
            format!("is longer than {MAX_COMMENT_LEN} characters"),
        ));
    }
    Ok(())
}

/// Checks a list's URL: `https://`, a host, printable ASCII, bounded.
fn check_url(field: &str, url: &str) -> Result<(), ValidationError> {
    if url.len() > MAX_SOURCE_LEN {
        return Err(invalid(
            field,
            format!("is longer than {MAX_SOURCE_LEN} bytes"),
        ));
    }
    if !url.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(invalid(field, "must be printable ASCII without spaces"));
    }
    let Some(rest) = url.strip_prefix("https://") else {
        return Err(invalid(field, "must be an https:// URL"));
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if host.is_empty() || host.contains('@') {
        return Err(invalid(field, "must name a host (without credentials)"));
    }
    Ok(())
}

impl ListSpec {
    fn validate(&self, field: &str) -> Result<(), ValidationError> {
        check_name(&format!("{field}.name"), &self.name)?;
        check_comment(&format!("{field}.comment"), &self.comment)?;
        match (&self.url, &self.path) {
            (Some(url), None) => check_url(&format!("{field}.url"), url),
            (None, Some(path)) => {
                if path.len() > MAX_SOURCE_LEN {
                    return Err(invalid(format!("{field}.path"), "is too long"));
                }
                if !path.starts_with('/') || path.chars().any(char::is_control) {
                    return Err(invalid(format!("{field}.path"), "must be an absolute path"));
                }
                Ok(())
            }
            _ => Err(invalid(field, "needs exactly one of url and path")),
        }
    }
}

impl RuleSpec {
    fn validate(&self, field: &str) -> Result<(), ValidationError> {
        check_comment(&format!("{field}.comment"), &self.comment)?;
        match parse_line(&self.rule, |_| {}) {
            LineKind::Rules(_) => Ok(()),
            LineKind::Ignored => Err(invalid(format!("{field}.rule"), "is a comment, not a rule")),
            LineKind::Unsupported(reason) => Err(invalid(
                format!("{field}.rule"),
                format!("is not supported yet ({reason})"),
            )),
            LineKind::Invalid(reason) => Err(invalid(
                format!("{field}.rule"),
                format!("is not a valid rule ({reason})"),
            )),
        }
    }
}

impl ScheduleSpec {
    fn validate(&self, field: &str) -> Result<(), ValidationError> {
        check_name(&format!("{field}.name"), &self.name)?;
        check_comment(&format!("{field}.comment"), &self.comment)?;
        if TimeZone::get(&self.time_zone).is_err() {
            return Err(invalid(
                format!("{field}.time_zone"),
                format!("{:?} is not a known time zone", self.time_zone),
            ));
        }
        if self.windows.is_empty() || self.windows.len() > MAX_WINDOWS {
            return Err(invalid(
                format!("{field}.windows"),
                format!("needs 1 to {MAX_WINDOWS} windows"),
            ));
        }
        for (index, window) in self.windows.iter().enumerate() {
            let at = format!("{field}.windows[{index}]");
            if window.days.is_empty() {
                return Err(invalid(format!("{at}.days"), "must name at least one day"));
            }
            let unique: HashSet<_> = window.days.iter().collect();
            if unique.len() != window.days.len() {
                return Err(invalid(format!("{at}.days"), "names a day twice"));
            }
            let start = minutes(&window.start).filter(|m| *m < 1440);
            let end = minutes(&window.end);
            match (start, end) {
                (None, _) => {
                    return Err(invalid(
                        format!("{at}.start"),
                        "must be HH:MM, 00:00 to 23:59",
                    ));
                }
                (_, None) => {
                    return Err(invalid(
                        format!("{at}.end"),
                        "must be HH:MM, 00:00 to 24:00",
                    ));
                }
                (Some(start), Some(end)) if start == end => {
                    return Err(invalid(&at, "start and end are the same"));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

impl SettingsSpec {
    fn validate(&self) -> Result<(), ValidationError> {
        self.access.validate()?;
        if self.blocked_ttl > 86_400 {
            return Err(invalid("settings.blocked_ttl", "must be at most 86400"));
        }
        if !(1..=168).contains(&self.list_update_hours) {
            return Err(invalid(
                "settings.list_update_hours",
                "must be between 1 and 168",
            ));
        }
        Ok(())
    }
}

impl ConfigSnapshot {
    /// An empty configuration: default settings and the default group.
    pub fn empty(now: Timestamp) -> Self {
        Self {
            settings: Settings {
                revision: 1,
                updated_at: now,
                spec: SettingsSpec::default(),
            },
            lists: Vec::new(),
            rules: Vec::new(),
            groups: vec![default_group_resource(now)],
            clients: Vec::new(),
            schedules: Vec::new(),
            records: Vec::new(),
        }
    }

    /// Checks every resource and every reference between them.
    ///
    /// # Errors
    ///
    /// The first problem found.
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.settings.spec.validate()?;
        self.validate_counts()?;
        let mut sources = HashSet::new();
        for list in &self.lists {
            let field = format!("lists[{}]", list.id);
            list.spec.validate(&field)?;
            let source = list.spec.url.as_ref().or(list.spec.path.as_ref());
            if !sources.insert(source) {
                return Err(invalid(field, "another list has the same url or path"));
            }
        }
        for rule in &self.rules {
            rule.spec.validate(&format!("rules[{}]", rule.id))?;
        }
        self.validate_records()?;
        for schedule in &self.schedules {
            schedule
                .spec
                .validate(&format!("schedules[{}]", schedule.id))?;
        }
        self.validate_groups()?;
        self.validate_clients()
    }

    fn validate_counts(&self) -> Result<(), ValidationError> {
        if self.lists.len() > MAX_LISTS {
            return Err(invalid(
                "lists",
                format!("at most {MAX_LISTS} lists are supported"),
            ));
        }
        if self.rules.len() > MAX_RULES {
            return Err(invalid(
                "rules",
                format!("at most {MAX_RULES} rules are supported"),
            ));
        }
        if self.groups.len() > MAX_GROUPS {
            return Err(invalid(
                "groups",
                format!("at most {MAX_GROUPS} groups are supported"),
            ));
        }
        if self.clients.len() > MAX_CLIENTS {
            return Err(invalid(
                "clients",
                format!("at most {MAX_CLIENTS} clients are supported"),
            ));
        }
        if self.schedules.len() > MAX_SCHEDULE_COUNT {
            return Err(invalid(
                "schedules",
                format!("at most {MAX_SCHEDULE_COUNT} schedules are supported"),
            ));
        }
        if self.records.len() > MAX_RECORDS {
            return Err(invalid(
                "records",
                format!("at most {MAX_RECORDS} records are supported"),
            ));
        }
        Ok(())
    }

    /// Each record on its own, then together: no record twice, and a name
    /// with an enabled CNAME has no other enabled record, as in DNS.
    fn validate_records(&self) -> Result<(), ValidationError> {
        let mut seen = HashSet::new();
        let mut names: std::collections::HashMap<String, (usize, bool)> =
            std::collections::HashMap::new();
        for record in &self.records {
            let field = format!("records[{}]", record.id);
            record.spec.validate(&field)?;
            let key = record.spec.key();
            if !seen.insert(key.clone()) {
                return Err(invalid(field, "another record is the same"));
            }
            if record.spec.enabled {
                let (count, cname) = names.entry(key.0).or_default();
                *count = count.saturating_add(1);
                *cname |= record.spec.kind == RecordKind::Cname;
                if *cname && *count > 1 {
                    return Err(conflict(
                        format!("{field}.name"),
                        format!(
                            "{} has a CNAME, so it can have no other record",
                            record.spec.name
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_groups(&self) -> Result<(), ValidationError> {
        let lists: HashSet<&str> = self.lists.iter().map(|l| l.id.as_str()).collect();
        let schedules: HashSet<&str> = self.schedules.iter().map(|s| s.id.as_str()).collect();
        if self.groups.first().map(|g| g.id.as_str()) != Some(DEFAULT_GROUP) {
            return Err(conflict(
                "groups",
                "the default group must exist and come first",
            ));
        }
        for group in &self.groups {
            let field = format!("groups[{}]", group.id);
            check_name(&format!("{field}.name"), &group.spec.name)?;
            check_comment(&format!("{field}.comment"), &group.spec.comment)?;
            let mut seen = HashSet::new();
            for (index, entry) in group.spec.lists.iter().enumerate() {
                let at = format!("{field}.lists[{index}]");
                if !lists.contains(entry.list.as_str()) {
                    return Err(conflict(at, format!("there is no list {:?}", entry.list)));
                }
                if let Some(schedule) = &entry.schedule
                    && !schedules.contains(schedule.as_str())
                {
                    return Err(conflict(at, format!("there is no schedule {schedule:?}")));
                }
                if !seen.insert(entry) {
                    return Err(invalid(at, "names the same list and schedule twice"));
                }
            }
            if group.spec.blocked_services.len() > MAX_BLOCKED_SERVICES {
                return Err(invalid(
                    format!("{field}.blocked_services"),
                    format!("has more than {MAX_BLOCKED_SERVICES} entries"),
                ));
            }
            let mut seen = HashSet::new();
            for (index, entry) in group.spec.blocked_services.iter().enumerate() {
                let at = format!("{field}.blocked_services[{index}]");
                if !is_service_id(&entry.service) {
                    return Err(invalid(
                        format!("{at}.service"),
                        "needs 1 to 64 lowercase letters, digits, underscores and hyphens",
                    ));
                }
                if let Some(schedule) = &entry.schedule
                    && !schedules.contains(schedule.as_str())
                {
                    return Err(conflict(at, format!("there is no schedule {schedule:?}")));
                }
                if !seen.insert(entry) {
                    return Err(invalid(at, "names the same service and schedule twice"));
                }
            }
        }
        Ok(())
    }

    fn validate_clients(&self) -> Result<(), ValidationError> {
        let groups: HashSet<&str> = self.groups.iter().map(|g| g.id.as_str()).collect();
        let mut networks = HashSet::new();
        let mut ids = HashSet::new();
        for client in &self.clients {
            let field = format!("clients[{}]", client.id);
            check_name(&format!("{field}.name"), &client.spec.name)?;
            check_comment(&format!("{field}.comment"), &client.spec.comment)?;
            if !groups.contains(client.spec.group.as_str()) {
                return Err(conflict(
                    format!("{field}.group"),
                    format!("there is no group {:?}", client.spec.group),
                ));
            }
            if client.spec.addresses.len() > MAX_CLIENT_ADDRESSES {
                return Err(invalid(
                    format!("{field}.addresses"),
                    format!("has more than {MAX_CLIENT_ADDRESSES} addresses"),
                ));
            }
            if client.spec.ids.len() > MAX_CLIENT_IDS {
                return Err(invalid(
                    format!("{field}.ids"),
                    format!("has more than {MAX_CLIENT_IDS} client IDs"),
                ));
            }
            if client.spec.addresses.is_empty() && client.spec.ids.is_empty() {
                return Err(invalid(
                    format!("{field}.addresses"),
                    "needs an address or a client ID",
                ));
            }
            for (index, id) in client.spec.ids.iter().enumerate() {
                let at = format!("{field}.ids[{index}]");
                if !is_client_id(id) {
                    return Err(invalid(
                        at,
                        "needs 1 to 63 lowercase letters, digits and hyphens, not at either end",
                    ));
                }
                if !ids.insert(id.as_str()) {
                    return Err(invalid(at, format!("{id} is used by another client")));
                }
            }
            for (index, address) in client.spec.addresses.iter().enumerate() {
                let at = format!("{field}.addresses[{index}]");
                let network: Cidr = address
                    .parse()
                    .map_err(|err| invalid(&at, format!("{err}")))?;
                if !networks.insert(network) {
                    return Err(invalid(at, format!("{network} is used by another client")));
                }
            }
        }
        Ok(())
    }
}

/// The default group: filtering on, no lists.
pub(crate) fn default_group_resource(now: Timestamp) -> Group {
    Group {
        id: DEFAULT_GROUP.to_owned(),
        revision: 1,
        created_at: now,
        updated_at: now,
        spec: GroupSpec {
            name: "Default".to_owned(),
            filtering: true,
            safe_search: false,
            lists: Vec::new(),
            blocked_services: Vec::new(),
            comment: "Clients that are not in another group.".to_owned(),
            managed_by: ManagedBy::Api,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> Timestamp {
        text.parse().unwrap()
    }

    fn schedule(time_zone: &str, windows: &[(&[Weekday], &str, &str)]) -> ScheduleSpec {
        ScheduleSpec {
            name: "test".into(),
            time_zone: time_zone.into(),
            windows: windows
                .iter()
                .map(|(days, start, end)| Window {
                    days: days.to_vec(),
                    start: (*start).into(),
                    end: (*end).into(),
                })
                .collect(),
            comment: String::new(),
            managed_by: ManagedBy::Api,
        }
    }

    #[test]
    fn schedules_in_time_zones() {
        use Weekday::*;
        let school = schedule(
            "Europe/Berlin",
            &[(&[Mon, Tue, Wed, Thu, Fri], "08:00", "13:30")],
        );
        // 2026-10-07 is a Wednesday; Berlin is UTC+2 in October.
        assert!(school.is_active(at("2026-10-07T06:00:00Z")));
        assert!(school.is_active(at("2026-10-07T11:29:59Z")));
        assert!(!school.is_active(at("2026-10-07T11:30:00Z")));
        assert!(!school.is_active(at("2026-10-07T05:59:00Z")));
        assert!(!school.is_active(at("2026-10-10T08:00:00Z")), "Saturday");

        let night = schedule("UTC", &[(&[Fri], "22:00", "07:00")]);
        assert!(night.is_active(at("2026-10-09T23:00:00Z")), "Friday night");
        assert!(night.is_active(at("2026-10-10T06:59:00Z")), "into Saturday");
        assert!(!night.is_active(at("2026-10-10T07:00:00Z")));
        assert!(!night.is_active(at("2026-10-08T23:00:00Z")), "Thursday");

        let all_day = schedule("UTC", &[(&[Sun], "00:00", "24:00")]);
        assert!(all_day.is_active(at("2026-10-11T23:59:59Z")));
        assert!(!all_day.is_active(at("2026-10-12T00:00:00Z")));
    }

    #[test]
    fn times_are_strict() {
        for good in ["00:00", "23:59", "24:00", "09:05"] {
            assert!(minutes(good).is_some(), "{good}");
        }
        for bad in [
            "24:01", "9:05", "09:5", "25:00", "12:60", "+1:00", "", "1200", "12:00:00",
        ] {
            assert!(minutes(bad).is_none(), "{bad}");
        }
        let mut spec = schedule("Mars/Olympus", &[(&[Weekday::Mon], "08:00", "09:00")]);
        assert!(spec.validate("s").unwrap_err().field.ends_with("time_zone"));
        spec.time_zone = "UTC".into();
        assert!(spec.validate("s").is_ok());
        spec.windows[0].start = "24:00".into();
        assert!(spec.validate("s").unwrap_err().field.ends_with("start"));
        spec.windows[0].start = "09:00".into();
        assert!(spec.validate("s").unwrap_err().message.contains("same"));
        spec.windows[0].days = vec![Weekday::Mon, Weekday::Mon];
        spec.windows[0].start = "08:00".into();
        assert!(spec.validate("s").unwrap_err().field.ends_with("days"));
    }

    fn snapshot() -> ConfigSnapshot {
        let now = at("2026-10-07T00:00:00Z");
        let mut config = ConfigSnapshot::empty(now);
        config.lists.push(List {
            id: "li_1".into(),
            revision: 1,
            created_at: now,
            updated_at: now,
            spec: ListSpec {
                name: "Ads".into(),
                url: Some("https://lists.example/ads.txt".into()),
                path: None,
                enabled: true,
                comment: String::new(),
                managed_by: ManagedBy::Api,
            },
        });
        config.clients.push(Client {
            id: "cl_1".into(),
            revision: 1,
            created_at: now,
            updated_at: now,
            spec: ClientSpec {
                name: "Tablet".into(),
                addresses: vec!["192.168.1.23".into()],
                ids: vec!["tablet".into()],
                group: DEFAULT_GROUP.into(),
                comment: String::new(),
                managed_by: ManagedBy::Api,
            },
        });
        config.groups[0].spec.lists.push(GroupList {
            list: "li_1".into(),
            schedule: None,
        });
        config
    }

    #[test]
    fn validation() {
        let good = snapshot();
        assert_eq!(good.validate(), Ok(()));

        let mut bad = good.clone();
        bad.lists[0].spec.url = Some("http://lists.example/ads.txt".into());
        assert!(bad.validate().unwrap_err().field.ends_with("url"));

        let mut bad = good.clone();
        bad.lists[0].spec.path = Some("/etc/lists/ads.txt".into());
        assert!(bad.validate().unwrap_err().message.contains("exactly one"));

        let mut bad = good.clone();
        bad.clients[0].spec.addresses = vec!["192.168.1.5/24".into()];
        assert!(bad.validate().unwrap_err().message.contains("host bits"));

        let mut bad = good.clone();
        bad.clients[0].spec.group = "nope".into();
        assert!(bad.validate().unwrap_err().conflict);

        let mut bad = good.clone();
        bad.lists.clear();
        let err = bad.validate().unwrap_err();
        assert!(err.conflict, "a group still uses the list");

        let mut bad = good.clone();
        bad.groups.remove(0);
        assert!(bad.validate().unwrap_err().conflict);

        let mut bad = good.clone();
        let mut twin = bad.clients[0].clone();
        twin.id = "cl_2".into();
        bad.clients.push(twin);
        assert!(
            bad.validate()
                .unwrap_err()
                .message
                .contains("another client")
        );

        let mut bad = good.clone();
        let mut twin = bad.clients[0].clone();
        twin.id = "cl_2".into();
        twin.spec.addresses.clear();
        bad.clients.push(twin);
        let err = bad.validate().unwrap_err();
        assert_eq!(err.field, "clients[cl_2].ids[0]");
        assert!(err.message.contains("another client"));

        let mut bad = good.clone();
        bad.clients[0].spec.ids = vec!["Tablet".into()];
        assert!(bad.validate().unwrap_err().field.ends_with("ids[0]"));

        // An ID alone is enough; neither is not.
        let mut fine = good.clone();
        fine.clients[0].spec.addresses.clear();
        assert_eq!(fine.validate(), Ok(()));
        fine.clients[0].spec.ids.clear();
        assert!(fine.validate().unwrap_err().message.contains("client ID"));

        let mut bad = good;
        bad.settings.spec.list_update_hours = 0;
        assert!(bad.validate().is_err());
    }

    #[test]
    fn blocked_services() {
        let blocked = |service: &str, schedule: Option<&str>| BlockedService {
            service: service.into(),
            schedule: schedule.map(Into::into),
        };
        let mut good = snapshot();
        good.groups[0].spec.blocked_services = vec![
            blocked("tiktok", None),
            // Not in the catalog (yet): kept, and blocks nothing.
            blocked("tomorrows_app", None),
        ];
        assert_eq!(good.validate(), Ok(()));

        let mut bad = good.clone();
        bad.groups[0].spec.blocked_services[1].service = "Tik Tok".into();
        let err = bad.validate().unwrap_err();
        assert_eq!(err.field, "groups[default].blocked_services[1].service");

        let mut bad = good.clone();
        bad.groups[0]
            .spec
            .blocked_services
            .push(blocked("tiktok", None));
        assert!(bad.validate().unwrap_err().message.contains("twice"));

        let mut bad = good.clone();
        bad.groups[0].spec.blocked_services[0].schedule = Some("sc_nope".into());
        assert!(bad.validate().unwrap_err().conflict);

        let mut bad = good;
        bad.groups[0].spec.blocked_services = (0..=MAX_BLOCKED_SERVICES)
            .map(|i| blocked(&format!("s{i}"), None))
            .collect();
        assert!(
            bad.validate()
                .unwrap_err()
                .field
                .ends_with("blocked_services")
        );

        let json = r#"{"name": "Kids", "blocked_services": [{"service": "tiktok"}]}"#;
        let spec: GroupSpec = serde_json::from_str(json).unwrap();
        assert_eq!(spec.blocked_services, [blocked("tiktok", None)]);
        let spec: GroupSpec = serde_json::from_str(r#"{"name": "Old"}"#).unwrap();
        assert!(spec.blocked_services.is_empty(), "older groups have none");
    }

    #[test]
    fn rules_must_be_supported() {
        let rule = |text: &str| RuleSpec {
            rule: text.into(),
            enabled: true,
            comment: String::new(),
            managed_by: ManagedBy::Api,
        };
        assert!(rule("||ads.example^").validate("r").is_ok());
        assert!(rule("@@||good.example^").validate("r").is_ok());
        assert!(
            rule("! comment")
                .validate("r")
                .unwrap_err()
                .message
                .contains("comment")
        );
        assert!(
            rule("/regex/")
                .validate("r")
                .unwrap_err()
                .message
                .contains("supported")
        );
        assert!(rule("not a rule!").validate("r").is_err());
    }

    #[test]
    fn specs_reject_unknown_fields() {
        let err = serde_json::from_str::<ClientSpec>(
            r#"{"name": "x", "addresses": ["10.0.0.1"], "groop": "default"}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
        let defaults: GroupSpec = serde_json::from_str(r#"{"name": "Kids"}"#).unwrap();
        assert!(defaults.filtering);
        assert!(!defaults.safe_search);
    }
}
