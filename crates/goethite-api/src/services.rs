//! The services catalog: well-known services, such as TikTok or YouTube,
//! with the rules that block them, for groups' `blocked_services`.
//!
//! The catalog is AdGuard's [HostlistsRegistry] `services.json` (GPL-3.0),
//! which the node downloads like a filter list: it is not part of goethite.
//! It is third-party data, read here without trusting it: unknown fields
//! (such as the icons) are ignored, IDs must be service IDs, names are
//! stripped of control characters and cut to a bounded length, and the
//! number of services, the rules per service and each rule's length are
//! capped. The parser is fuzzed (`parse_services`).
//!
//! [HostlistsRegistry]: https://github.com/AdguardTeam/HostlistsRegistry

use std::collections::HashSet;

use goethite_resolver::{MAX_SERVICES, is_service_id};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Where the catalog comes from.
pub const SOURCE: &str = "https://adguardteam.github.io/HostlistsRegistry/assets/services.json";

/// The catalog's license.
pub const LICENSE: &str = "GPL-3.0";

/// The largest catalog read: AdGuard's is about 270 KiB, icons included.
pub const MAX_LEN: usize = 4 * 1024 * 1024;

/// The most rules kept for one service.
pub const MAX_RULES_PER_SERVICE: usize = 2_048;

/// The longest rule kept, in bytes.
pub const MAX_RULE_LEN: usize = 1_024;

/// The longest name kept, in characters.
const MAX_NAME: usize = 100;

/// The kind of service when the catalog names none, or an odd one.
const OTHER: &str = "other";

/// A service a group can block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Service {
    /// Its ID, such as `tiktok`: what groups' `blocked_services` name.
    pub id: String,
    /// Its name, such as `TikTok`.
    pub name: String,
    /// What kind of service it is, such as `social_network` or `gaming`.
    pub group: String,
    /// The rules that block it, in adblock-style syntax. Rules goethite
    /// cannot read are left out.
    pub rules: Vec<String>,
}

/// The services groups can block, and how the catalog is doing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Services {
    /// Where the catalog comes from.
    pub source: String,
    /// The catalog's license.
    pub license: String,
    /// When this node saved its copy; `None` until it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub downloaded_at: Option<Timestamp>,
    /// Why the last download or read failed, if it did; the last good copy
    /// stays in use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The services, by name.
    pub services: Vec<Service>,
}

/// What goes wrong reading the catalog.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ServicesError {
    /// It is not the JSON the catalog is.
    #[error("unexpected data in the services catalog: {0}")]
    Json(String),
    /// It holds no service goethite can use.
    #[error("the services catalog holds no services")]
    Empty,
}

impl From<serde_json::Error> for ServicesError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err.to_string())
    }
}

#[derive(Deserialize)]
struct RawCatalog {
    blocked_services: Vec<RawService>,
}

#[derive(Deserialize)]
struct RawService {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    rules: Vec<String>,
}

/// `text` without control characters, cut to `max` characters.
fn clean(text: &str, max: usize) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .take(max)
        .collect::<String>()
        .trim()
        .to_owned()
}

/// Reads the catalog: up to [`MAX_SERVICES`] services with valid, distinct
/// IDs and at least one rule, by name.
///
/// # Errors
///
/// If it is not a JSON object with a `blocked_services` array, or holds no
/// usable service.
pub fn parse_services(json: &[u8]) -> Result<Vec<Service>, ServicesError> {
    let catalog: RawCatalog = serde_json::from_slice(json)?;
    let mut ids = HashSet::new();
    let mut services = Vec::new();
    for raw in catalog.blocked_services {
        if services.len() >= MAX_SERVICES {
            break;
        }
        let Some(id) = raw.id.filter(|id| is_service_id(id)) else {
            continue;
        };
        let mut seen = HashSet::new();
        let rules: Vec<String> = raw
            .rules
            .iter()
            .map(|rule| rule.trim())
            .filter(|rule| {
                !rule.is_empty()
                    && rule.len() <= MAX_RULE_LEN
                    && !rule.chars().any(char::is_control)
            })
            .filter(|rule| seen.insert(*rule))
            .take(MAX_RULES_PER_SERVICE)
            .map(str::to_owned)
            .collect();
        if rules.is_empty() || !ids.insert(id.clone()) {
            continue;
        }
        let name = clean(raw.name.as_deref().unwrap_or_default(), MAX_NAME);
        services.push(Service {
            name: if name.is_empty() { id.clone() } else { name },
            group: raw
                .group
                .filter(|group| is_service_id(group))
                .unwrap_or_else(|| OTHER.to_owned()),
            id,
            rules,
        });
    }
    if services.is_empty() {
        return Err(ServicesError::Empty);
    }
    services.sort_by_cached_key(|service| service.name.to_lowercase());
    Ok(services)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_catalog_without_trusting_it() {
        let long = "x".repeat(MAX_RULE_LEN + 1);
        let json = format!(
            r#"{{
                "groups": [{{"id": "social_network"}}],
                "blocked_services": [
                    {{"id": "tiktok", "name": "TikTok", "group": "social_network",
                      "icon_svg": "<svg/>", "rules": ["||tiktok.com^", " ||tiktok.com^ ", "", "{long}"]}},
                    {{"id": "Bad ID", "name": "Bad", "rules": ["||bad.example^"]}},
                    {{"id": "tiktok", "name": "Again", "rules": ["||again.example^"]}},
                    {{"id": "empty", "name": "No rules", "rules": []}},
                    {{"id": "9gag", "name": "  9GAG\u0007 ", "group": "Not A Group", "rules": ["||9gag.com^"]}},
                    {{"id": "nameless", "rules": ["||nameless.example^"]}},
                    {{"name": "No ID", "rules": ["||noid.example^"]}}
                ]
            }}"#
        );
        let services = parse_services(json.as_bytes()).unwrap();
        let ids: Vec<&str> = services.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, ["9gag", "nameless", "tiktok"], "by name");
        assert_eq!(services[0].name, "9GAG");
        assert_eq!(services[0].group, "other");
        assert_eq!(services[1].name, "nameless");
        assert_eq!(services[2].rules, ["||tiktok.com^"]);
        assert_eq!(services[2].group, "social_network");
    }

    #[test]
    fn bounds_and_errors() {
        let many: Vec<String> = (0..=MAX_SERVICES)
            .map(|i| format!(r#"{{"id": "s{i}", "rules": ["||s{i}.example^"]}}"#))
            .collect();
        let json = format!(r#"{{"blocked_services": [{}]}}"#, many.join(","));
        assert_eq!(parse_services(json.as_bytes()).unwrap().len(), MAX_SERVICES);

        let rules: Vec<String> = (0..=MAX_RULES_PER_SERVICE)
            .map(|i| format!(r#""||r{i}.example^""#))
            .collect();
        let json = format!(
            r#"{{"blocked_services": [{{"id": "big", "rules": [{}]}}]}}"#,
            rules.join(",")
        );
        assert_eq!(
            parse_services(json.as_bytes()).unwrap()[0].rules.len(),
            MAX_RULES_PER_SERVICE
        );

        assert_eq!(
            parse_services(br#"{"blocked_services": []}"#),
            Err(ServicesError::Empty)
        );
        for junk in [
            &b"<html>"[..],
            b"[]",
            b"{}",
            br#"{"blocked_services": [{"rules": 1}]}"#,
        ] {
            assert!(matches!(parse_services(junk), Err(ServicesError::Json(_))));
        }
    }
}
