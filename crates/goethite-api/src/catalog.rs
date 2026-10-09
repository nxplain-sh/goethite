//! The [FilterLists](https://filterlists.com) directory, for finding filter
//! lists beyond the ones goethite recommends ([`crate::recommended`]).
//!
//! The directory is third-party data, fetched by the node when someone
//! browses it. Everything here reads it without trusting it: unknown fields
//! are ignored, missing ones get defaults, text is stripped of control
//! characters and cut to a bounded length, counts are capped, and only
//! `https://` addresses are kept, since goethite downloads nothing else.
//! Lists in syntaxes goethite cannot read, and allowlists (whose domains
//! goethite would block), are left out. The parsers are fuzzed
//! (`parse_filterlists`).

use std::collections::HashMap;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// FilterLists' syntaxes goethite reads: hosts files (localhost IPv4 and
/// IPv6, and `0`), plain domains, domains with wildcards, and adblock-style
/// domain rules.
pub const DNS_SYNTAXES: [u64; 8] = [1, 2, 16, 28, 36, 47, 48, 54];

/// FilterLists' tag for allowlists, and its syntax for allowlisted domains:
/// goethite would block their domains, so they are left out.
const ALLOWLIST_TAG: u64 = 10;
const ALLOWLIST_SYNTAX: u64 = 50;

/// The most lists read from the directory.
pub const MAX_LISTS: usize = 20_000;
/// The longest name kept, in characters.
const MAX_NAME: usize = 200;
/// The longest description kept, in characters.
const MAX_DESCRIPTION: usize = 1_000;
/// The most tags, syntaxes or addresses kept for one list.
const MAX_PER_LIST: usize = 32;
/// The most names read for syntaxes, tags or licenses.
const MAX_NAMES: usize = 4_096;
/// The longest address kept.
const MAX_URL: usize = 2_048;

/// A list in the FilterLists directory that goethite can use.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DirectoryEntry {
    /// Its FilterLists ID.
    pub id: u64,
    /// Its name.
    pub name: String,
    /// What it is for.
    pub description: String,
    /// Topics, such as `ads` or `malware`.
    pub tags: Vec<String>,
    /// Its formats, such as `Domains`.
    pub syntaxes: Vec<String>,
    /// Its license, as FilterLists records it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
}

/// The FilterLists directory, as far as goethite can use it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Directory {
    /// When this node fetched it.
    pub fetched_at: Timestamp,
    /// Lists in syntaxes goethite reads, allowlists left out, by name.
    pub lists: Vec<DirectoryEntry>,
}

/// One address of a list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DirectoryUrl {
    /// The address; always `https://`.
    pub url: String,
    /// Which part of the list it is, for lists in several parts (from 1).
    pub segment: u32,
    /// Whether it is a mirror of another address.
    pub mirror: bool,
}

/// A list's details from the directory, with its addresses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DirectoryList {
    /// The list.
    #[serde(flatten)]
    pub entry: DirectoryEntry,
    /// Its home page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    /// Its `https://` addresses: main ones first, mirrors after.
    pub urls: Vec<DirectoryUrl>,
    /// Whether goethite can use it: a readable syntax, not an allowlist.
    pub usable: bool,
}

/// What goes wrong reading the directory.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DirectoryError {
    /// It is not the JSON FilterLists sends.
    #[error("unexpected data from FilterLists: {0}")]
    Json(String),
}

impl From<serde_json::Error> for DirectoryError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err.to_string())
    }
}

/// The names behind FilterLists' IDs for syntaxes, tags and licenses.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Names {
    syntaxes: HashMap<u64, String>,
    tags: HashMap<u64, String>,
    licenses: HashMap<u64, String>,
}

#[derive(Deserialize)]
struct Named {
    id: u64,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawList {
    id: u64,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    license_id: Option<u64>,
    #[serde(default)]
    syntax_ids: Vec<u64>,
    #[serde(default)]
    tag_ids: Vec<u64>,
    #[serde(default)]
    home_url: Option<String>,
    #[serde(default)]
    view_urls: Vec<RawUrl>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawUrl {
    #[serde(default)]
    segment_number: Option<u32>,
    #[serde(default)]
    primariness: Option<u32>,
    #[serde(default)]
    url: Option<String>,
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

fn names(json: &[u8]) -> Result<HashMap<u64, String>, DirectoryError> {
    let named: Vec<Named> = serde_json::from_slice(json)?;
    Ok(named
        .into_iter()
        .take(MAX_NAMES)
        .filter_map(|named| Some((named.id, clean(&named.name?, MAX_NAME))))
        .collect())
}

/// Reads FilterLists' `/syntaxes`, `/tags` and `/licenses`.
///
/// # Errors
///
/// If one is not a JSON array of objects with numeric IDs.
pub fn parse_names(syntaxes: &[u8], tags: &[u8], licenses: &[u8]) -> Result<Names, DirectoryError> {
    Ok(Names {
        syntaxes: names(syntaxes)?,
        tags: names(tags)?,
        licenses: names(licenses)?,
    })
}

fn usable(list: &RawList) -> bool {
    list.syntax_ids.iter().any(|id| DNS_SYNTAXES.contains(id))
        && !list.syntax_ids.contains(&ALLOWLIST_SYNTAX)
        && !list.tag_ids.contains(&ALLOWLIST_TAG)
}

fn entry(list: &RawList, names: &Names) -> DirectoryEntry {
    let lookup = |ids: &[u64], map: &HashMap<u64, String>| -> Vec<String> {
        ids.iter()
            .filter_map(|id| map.get(id).cloned())
            .take(MAX_PER_LIST)
            .collect()
    };
    DirectoryEntry {
        id: list.id,
        name: clean(list.name.as_deref().unwrap_or_default(), MAX_NAME),
        description: clean(
            list.description.as_deref().unwrap_or_default(),
            MAX_DESCRIPTION,
        ),
        tags: lookup(&list.tag_ids, &names.tags),
        syntaxes: lookup(&list.syntax_ids, &names.syntaxes),
        license: list
            .license_id
            .and_then(|id| names.licenses.get(&id).cloned()),
    }
}

/// Reads FilterLists' `/lists`: the lists goethite can use, by name.
///
/// # Errors
///
/// If it is not a JSON array of lists with numeric IDs.
pub fn parse_lists(json: &[u8], names: &Names) -> Result<Vec<DirectoryEntry>, DirectoryError> {
    let lists: Vec<RawList> = serde_json::from_slice(json)?;
    let mut entries: Vec<DirectoryEntry> = lists
        .iter()
        .take(MAX_LISTS)
        .filter(|list| usable(list))
        .map(|list| entry(list, names))
        .filter(|entry| !entry.name.is_empty())
        .collect();
    entries.sort_by_cached_key(|entry| entry.name.to_lowercase());
    Ok(entries)
}

/// Reads FilterLists' `/lists/{id}`: a list's details and its `https://`
/// addresses, main ones first and in part order.
///
/// # Errors
///
/// If it is not a JSON list with a numeric ID.
pub fn parse_list(json: &[u8], names: &Names) -> Result<DirectoryList, DirectoryError> {
    let list: RawList = serde_json::from_slice(json)?;
    let mut urls: Vec<(u32, u32, String)> = list
        .view_urls
        .iter()
        .filter_map(|raw| {
            let url = raw.url.as_deref()?.trim();
            let https = url
                .get(..8)
                .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"));
            (https && url.len() <= MAX_URL && !url.chars().any(char::is_control)).then(|| {
                (
                    raw.primariness.unwrap_or(1),
                    raw.segment_number.unwrap_or(1).max(1),
                    url.to_owned(),
                )
            })
        })
        .collect();
    urls.sort();
    urls.dedup_by(|a, b| a.2 == b.2);
    Ok(DirectoryList {
        entry: entry(&list, names),
        homepage: list
            .home_url
            .as_deref()
            .map(str::trim)
            .filter(|url| {
                (url.starts_with("https://") || url.starts_with("http://"))
                    && url.len() <= MAX_URL
                    && !url.chars().any(char::is_control)
            })
            .map(str::to_owned),
        urls: urls
            .into_iter()
            .take(MAX_PER_LIST)
            .map(|(primariness, segment, url)| DirectoryUrl {
                url,
                segment,
                mirror: primariness > 1,
            })
            .collect(),
        usable: usable(&list),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names_fixture() -> Names {
        parse_names(
            br#"[{"id": 2, "name": "Domains"}, {"id": 1, "name": "Hosts (localhost IPv4)"},
                {"id": 4, "name": "uBlock Origin Static"}, {"id": 50, "name": "Domains for whitelisting"}]"#,
            br#"[{"id": 2, "name": "ads"}, {"id": 10, "name": "allowlist"}, {"id": 6, "name": "malware"}]"#,
            br#"[{"id": 11, "name": "GPL-3.0", "url": null}]"#,
        )
        .unwrap()
    }

    #[test]
    fn keeps_lists_goethite_can_use() {
        let names = names_fixture();
        let lists = parse_lists(
            br#"[
                {"id": 3, "name": "Zeta hosts", "syntaxIds": [1], "tagIds": [2, 6], "licenseId": 11},
                {"id": 4, "name": "Browser only", "syntaxIds": [4], "tagIds": [2]},
                {"id": 5, "name": "alpha domains", "syntaxIds": [2], "description": "Ads\u0007 here", "extra": true},
                {"id": 6, "name": "Allowed", "syntaxIds": [2], "tagIds": [10]},
                {"id": 7, "name": "Whitelist", "syntaxIds": [50, 2]},
                {"id": 8, "syntaxIds": [2]}
            ]"#,
            &names,
        )
        .unwrap();
        let ids: Vec<u64> = lists.iter().map(|list| list.id).collect();
        assert_eq!(ids, [5, 3], "readable, not allowlists, named, by name");
        assert_eq!(lists[0].description, "Ads here");
        assert_eq!(lists[1].tags, ["ads", "malware"]);
        assert_eq!(lists[1].syntaxes, ["Hosts (localhost IPv4)"]);
        assert_eq!(lists[1].license.as_deref(), Some("GPL-3.0"));
        assert!(parse_lists(b"{}", &names).is_err());
        assert!(parse_lists(br#"[{"id": "x"}]"#, &names).is_err());
    }

    #[test]
    fn keeps_https_addresses_main_ones_first() {
        let list = parse_list(
            br#"{"id": 9, "name": "Two parts", "syntaxIds": [2], "homeUrl": "https://example.org",
                "viewUrls": [
                    {"segmentNumber": 2, "primariness": 1, "url": "https://example.org/b.txt"},
                    {"segmentNumber": 1, "primariness": 2, "url": "https://mirror.example/a.txt"},
                    {"segmentNumber": 1, "primariness": 1, "url": "https://example.org/a.txt"},
                    {"segmentNumber": 1, "primariness": 3, "url": "http://example.org/a.txt"},
                    {"segmentNumber": 1, "primariness": 4, "url": "javascript:alert(1)"},
                    {"url": null}
                ]}"#,
            &names_fixture(),
        )
        .unwrap();
        let urls: Vec<(&str, u32, bool)> = list
            .urls
            .iter()
            .map(|url| (url.url.as_str(), url.segment, url.mirror))
            .collect();
        assert_eq!(
            urls,
            [
                ("https://example.org/a.txt", 1, false),
                ("https://example.org/b.txt", 2, false),
                ("https://mirror.example/a.txt", 1, true),
            ]
        );
        assert_eq!(list.homepage.as_deref(), Some("https://example.org"));
        assert!(list.usable);
        let allowlist = parse_list(
            br#"{"id": 1, "syntaxIds": [2], "tagIds": [10]}"#,
            &names_fixture(),
        )
        .unwrap();
        assert!(!allowlist.usable);
        let bad_home = parse_list(
            br#"{"id": 1, "homeUrl": "javascript:alert(1)"}"#,
            &names_fixture(),
        )
        .unwrap();
        assert_eq!(bad_home.homepage, None);
    }
}
