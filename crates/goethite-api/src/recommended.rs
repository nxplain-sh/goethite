//! The filter lists goethite recommends, and presets of them.
//!
//! Lists come in four categories: one **base** list against ads and
//! trackers (they overlap, so a second one adds little), **security** lists
//! that stack on it, **optional** lists by topic, and **legacy** lists that
//! the base lists already include. Lists that do the same job (TIF and TIF
//! Mini, Perflyst and HaGeZi's lists for the same TV vendors) say so in
//! `excludes`, so a UI can offer to switch instead of stacking them.
//!
//! Every list was downloaded and read by goethite on 8 October 2026; rule
//! counts are not kept here, since they change daily: lists say how big
//! they are, and goethite counts what it reads. A new node starts with the
//! default preset's lists.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// What a recommended list is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Ads and trackers: pick one, they overlap.
    Base,
    /// Malware, phishing and scams: stack on the base list.
    Security,
    /// By topic, off unless wanted.
    Optional,
    /// Already included in the base lists.
    Legacy,
}

/// A filter list goethite recommends.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct RecommendedList {
    /// A stable identifier, such as `hagezi-normal`.
    pub id: &'static str,
    /// Its name.
    pub name: &'static str,
    /// Who maintains it.
    pub maintainer: &'static str,
    /// What it blocks.
    pub description: &'static str,
    /// Where goethite downloads it.
    pub url: &'static str,
    /// Its home page.
    pub homepage: &'static str,
    /// Its license, as the project states it.
    pub license: &'static str,
    /// Its category.
    pub category: Category,
    /// For optional lists, their topic, such as `Family`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<&'static str>,
    /// One of the lists goethite recommends most in its category.
    pub recommended: bool,
    /// A short label, such as `Minimal` or `Compatibility`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub badge: Option<&'static str>,
    /// When to choose it, or what to know first.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'static str>,
    /// Whether a new node starts with it.
    pub default: bool,
    /// Lists not to use with it: one includes the other, or they do the
    /// same job. Switch instead of stacking.
    pub excludes: &'static [&'static str],
}

/// A set of recommended lists for a group, in one step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct Preset {
    /// A stable identifier, such as `balanced`.
    pub id: &'static str,
    /// Its name.
    pub name: &'static str,
    /// Who it is for.
    pub description: &'static str,
    /// Its lists, by ID.
    pub lists: &'static [&'static str],
    /// Whether a new node starts with it.
    pub default: bool,
}

/// The recommended lists and presets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct Recommended {
    /// The lists, by category.
    pub lists: &'static [RecommendedList],
    /// The presets.
    pub presets: &'static [Preset],
}

const HAGEZI: &str = "https://github.com/hagezi/dns-blocklists";

/// A HaGeZi list's address, from its file name.
macro_rules! hagezi {
    ($file:literal) => {
        concat!(
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/",
            $file
        )
    };
}

/// A list with the fields most share.
const fn list(
    id: &'static str,
    name: &'static str,
    category: Category,
    description: &'static str,
    url: &'static str,
) -> RecommendedList {
    RecommendedList {
        id,
        name,
        maintainer: "HaGeZi",
        description,
        url,
        homepage: HAGEZI,
        license: "GPL-3.0",
        category,
        topic: None,
        recommended: false,
        badge: None,
        note: None,
        default: false,
        excludes: &[],
    }
}

/// HaGeZi's lists for one vendor's built-in trackers.
const fn native(
    id: &'static str,
    name: &'static str,
    vendor: &'static str,
    url: &'static str,
) -> RecommendedList {
    RecommendedList {
        topic: Some("Device trackers"),
        recommended: true,
        note: Some(vendor),
        ..list(
            id,
            name,
            Category::Optional,
            "Trackers built into this vendor's devices, apps and operating systems. Best for \
             a group with those devices in it; an app may stop working.",
            url,
        )
    }
}

/// HaGeZi's vendor lists Perflyst's Smart-TV list does the same job as.
const TV_VENDORS: &[&str] = &[
    "hagezi-native-samsung",
    "hagezi-native-lgwebos",
    "hagezi-native-roku",
];

/// The recommended lists.
pub const LISTS: &[RecommendedList] = &[
    // Base: one of these.
    RecommendedList {
        recommended: true,
        default: true,
        ..list(
            "hagezi-normal",
            "HaGeZi Multi Normal",
            Category::Base,
            "All-round protection from ads, trackers, metrics, telemetry, phishing, malware and \
             scams, made for DNS blocking. Rarely breaks anything.",
            hagezi!("multi.txt"),
        )
    },
    RecommendedList {
        recommended: true,
        ..list(
            "hagezi-pro",
            "HaGeZi Multi Pro",
            Category::Base,
            "Extended protection: more trackers and junk than Normal. May now and then block \
             something you want.",
            hagezi!("pro.txt"),
        )
    },
    RecommendedList {
        maintainer: "Stephan van Ruth",
        homepage: "https://oisd.nl",
        recommended: true,
        ..list(
            "oisd-big",
            "OISD Big",
            Category::Base,
            "OISD's broad list: ads, trackers, malware and phishing, kept so that it does not \
             break things.",
            "https://big.oisd.nl/",
        )
    },
    RecommendedList {
        badge: Some("Minimal"),
        ..list(
            "hagezi-light",
            "HaGeZi Multi Light",
            Category::Base,
            "Basic protection from ads, trackers, metrics and the most common phishing and \
             malware, for devices where nothing may break.",
            hagezi!("light.txt"),
        )
    },
    RecommendedList {
        badge: Some("Aggressive"),
        ..list(
            "hagezi-pro-plus",
            "HaGeZi Multi Pro++",
            Category::Base,
            "Aggressive protection, for people who will allow what it breaks.",
            hagezi!("pro.plus.txt"),
        )
    },
    RecommendedList {
        badge: Some("Strict"),
        note: Some("Experts only: expect to allow sites yourself."),
        ..list(
            "hagezi-ultimate",
            "HaGeZi Multi Ultimate",
            Category::Base,
            "HaGeZi's strictest list: ads, trackers, metrics, telemetry, phishing, malware, \
             scams, fakes and other junk, swept hard.",
            hagezi!("ultimate.txt"),
        )
    },
    RecommendedList {
        maintainer: "Stephan van Ruth",
        homepage: "https://oisd.nl",
        badge: Some("Minimal"),
        ..list(
            "oisd-small",
            "OISD Small",
            Category::Base,
            "\"Block. Don't break.\" Ads, trackers and malware, with very few false positives.",
            "https://small.oisd.nl/",
        )
    },
    RecommendedList {
        maintainer: "AdGuard",
        homepage: "https://github.com/AdguardTeam/AdGuardSDNSFilter",
        badge: Some("Compatibility"),
        note: Some("For people coming from AdGuard Home: what it starts with."),
        ..list(
            "adguard-dns",
            "AdGuard DNS filter",
            Category::Base,
            "AdGuard's ad, tracker, social media and mobile ad filters, simplified for DNS \
             blocking. goethite skips the few hundred rules a DNS server cannot apply.",
            "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
        )
    },
    RecommendedList {
        maintainer: "Steven Black",
        homepage: "https://github.com/StevenBlack/hosts",
        license: "MIT",
        badge: Some("Compatibility"),
        note: Some("For people coming from Pi-hole: what it starts with."),
        ..list(
            "stevenblack",
            "Steven Black's Unified Hosts",
            Category::Base,
            "Adware and malware hosts from several sources, consolidated.",
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        )
    },
    // Security: on top of the base list.
    RecommendedList {
        recommended: true,
        default: true,
        excludes: &["hagezi-tif"],
        ..list(
            "hagezi-tif-mini",
            "HaGeZi Threat Intelligence Feeds Mini",
            Category::Security,
            "The most active malware, phishing, scam, spam and cryptojacking domains from \
             HaGeZi's threat intelligence feeds, kept small.",
            hagezi!("tif.mini.txt"),
        )
    },
    RecommendedList {
        badge: Some("Max security"),
        note: Some("Replaces TIF Mini. Very large: millions of rules."),
        excludes: &["hagezi-tif-mini"],
        ..list(
            "hagezi-tif",
            "HaGeZi Threat Intelligence Feeds",
            Category::Security,
            "All of HaGeZi's threat intelligence: domains spreading malware, running phishing, \
             scams, spam and cryptojacking, and command-and-control servers.",
            hagezi!("tif.txt"),
        )
    },
    RecommendedList {
        recommended: true,
        default: true,
        ..list(
            "hagezi-fake",
            "HaGeZi Fake",
            Category::Security,
            "Fake shops, fake streaming and download sites, rip-offs and subscription traps.",
            hagezi!("fake.txt"),
        )
    },
    RecommendedList {
        maintainer: "Dandelion Sprout",
        homepage: "https://github.com/DandelionSprout/adfilt",
        license: "Dandelicence",
        note: Some("Hand-curated, with few false positives."),
        ..list(
            "dandelion-antimalware",
            "Dandelion Sprout's Anti-Malware List",
            Category::Security,
            "Malware redirect chains, parked domains and scams, kept by hand. goethite skips \
             its IP address rules.",
            "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareDomains.txt",
        )
    },
    RecommendedList {
        maintainer: "abuse.ch",
        homepage: "https://urlhaus.abuse.ch",
        license: "abuse.ch fair use terms",
        note: Some("Updated every few minutes."),
        ..list(
            "urlhaus",
            "URLhaus",
            Category::Security,
            "Domains serving malware right now, from abuse.ch's URLhaus. Small.",
            "https://urlhaus.abuse.ch/downloads/hostfile/",
        )
    },
    RecommendedList {
        note: Some("For pop-ups that lead to scams and malware."),
        ..list(
            "hagezi-popupads",
            "HaGeZi Pop-Up Ads",
            Category::Security,
            "Pop-up, pop-under and redirect ad networks, from annoying to outright malicious.",
            hagezi!("popupads.txt"),
        )
    },
    // Optional, by topic.
    RecommendedList {
        topic: Some("Bypass prevention"),
        note: Some("Stops devices from going around goethite."),
        ..list(
            "hagezi-bypass",
            "HaGeZi DoH/VPN/Tor/Proxy Bypass",
            Category::Optional,
            "Encrypted DNS, VPN, Tor and proxy services a device could use to sidestep \
             goethite. Blocks those services themselves.",
            hagezi!("doh-vpn-proxy-bypass.txt"),
        )
    },
    native(
        "hagezi-native-amazon",
        "HaGeZi Native Trackers: Amazon",
        "Amazon: Echo, Fire TV, Kindle.",
        hagezi!("native.amazon.txt"),
    ),
    native(
        "hagezi-native-apple",
        "HaGeZi Native Trackers: Apple",
        "Apple devices.",
        hagezi!("native.apple.txt"),
    ),
    native(
        "hagezi-native-huawei",
        "HaGeZi Native Trackers: Huawei",
        "Huawei devices.",
        hagezi!("native.huawei.txt"),
    ),
    RecommendedList {
        excludes: &["perflyst-smarttv"],
        ..native(
            "hagezi-native-lgwebos",
            "HaGeZi Native Trackers: LG webOS",
            "LG TVs (webOS).",
            hagezi!("native.lgwebos.txt"),
        )
    },
    native(
        "hagezi-native-oppo-realme",
        "HaGeZi Native Trackers: OPPO and Realme",
        "OPPO and Realme phones.",
        hagezi!("native.oppo-realme.txt"),
    ),
    RecommendedList {
        excludes: &["perflyst-smarttv"],
        ..native(
            "hagezi-native-roku",
            "HaGeZi Native Trackers: Roku",
            "Roku players and TVs.",
            hagezi!("native.roku.txt"),
        )
    },
    RecommendedList {
        excludes: &["perflyst-smarttv"],
        ..native(
            "hagezi-native-samsung",
            "HaGeZi Native Trackers: Samsung",
            "Samsung phones and TVs.",
            hagezi!("native.samsung.txt"),
        )
    },
    native(
        "hagezi-native-tiktok",
        "HaGeZi Native Trackers: TikTok",
        "TikTok's tracking, not the app itself (block that as a service).",
        hagezi!("native.tiktok.txt"),
    ),
    native(
        "hagezi-native-vivo",
        "HaGeZi Native Trackers: vivo",
        "vivo phones.",
        hagezi!("native.vivo.txt"),
    ),
    native(
        "hagezi-native-winoffice",
        "HaGeZi Native Trackers: Windows and Office",
        "Windows and Microsoft Office.",
        hagezi!("native.winoffice.txt"),
    ),
    native(
        "hagezi-native-xiaomi",
        "HaGeZi Native Trackers: Xiaomi",
        "Xiaomi phones and devices.",
        hagezi!("native.xiaomi.txt"),
    ),
    RecommendedList {
        maintainer: "Perflyst",
        homepage: "https://github.com/Perflyst/PiHoleBlocklist",
        license: "MIT",
        topic: Some("Device trackers"),
        note: Some("Instead of HaGeZi's Samsung, LG and Roku lists. Last updated in 2023."),
        excludes: TV_VENDORS,
        ..list(
            "perflyst-smarttv",
            "Perflyst Smart-TV",
            Category::Optional,
            "Smart TVs phoning home and showing ads, across brands. A TV may miss updates or \
             an app may stop working.",
            "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt",
        )
    },
    RecommendedList {
        topic: Some("Family"),
        note: Some("Large."),
        ..list(
            "hagezi-gambling",
            "HaGeZi Gambling",
            Category::Optional,
            "Gambling sites.",
            hagezi!("gambling.txt"),
        )
    },
    RecommendedList {
        topic: Some("Family"),
        ..list(
            "hagezi-nsfw",
            "HaGeZi NSFW",
            Category::Optional,
            "Adult content.",
            hagezi!("nsfw.txt"),
        )
    },
    RecommendedList {
        topic: Some("Hardening"),
        ..list(
            "hagezi-dyndns",
            "HaGeZi Dynamic DNS",
            Category::Optional,
            "Dynamic DNS services, often abused for phishing. Blocks your own dynamic DNS name \
             too, if you have one.",
            hagezi!("dyndns.txt"),
        )
    },
    RecommendedList {
        topic: Some("Hardening"),
        ..list(
            "hagezi-hoster",
            "HaGeZi Badware Hoster",
            Category::Optional,
            "Hosting providers that keep hosting badware through what users upload.",
            hagezi!("hoster.txt"),
        )
    },
    RecommendedList {
        topic: Some("Hardening"),
        ..list(
            "hagezi-urlshortener",
            "HaGeZi URL Shorteners",
            Category::Optional,
            "Every known link shortener: shortened links stop working.",
            hagezi!("urlshortener.txt"),
        )
    },
    RecommendedList {
        topic: Some("Hardening"),
        ..list(
            "hagezi-spam-tlds",
            "HaGeZi Most Abused TLDs",
            Category::Optional,
            "Whole top-level domains, such as .zip, mostly used for spam and scams, and with \
             no exceptions needed.",
            hagezi!("spam-tlds-adblock.txt"),
        )
    },
    // Legacy: in the base lists already.
    RecommendedList {
        maintainer: "AdAway",
        homepage: "https://adaway.org",
        license: "CC-BY-3.0",
        note: Some("Already in HaGeZi and OISD."),
        ..list(
            "adaway",
            "AdAway",
            Category::Legacy,
            "Mobile ad servers, from the AdAway app for Android.",
            "https://adaway.org/hosts.txt",
        )
    },
    RecommendedList {
        maintainer: "Peter Lowe",
        homepage: "https://pgl.yoyo.org/adservers/",
        license: "McRae GPL",
        note: Some("Already in HaGeZi and OISD."),
        ..list(
            "peter-lowe",
            "Peter Lowe's Ad and tracking server list",
            Category::Legacy,
            "A long-running, hand-kept list of ad and tracking servers.",
            "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblock&showintro=0&mimetype=plaintext",
        )
    },
];

/// The presets.
pub const PRESETS: &[Preset] = &[
    Preset {
        id: "balanced",
        name: "Balanced",
        description: "Ads, trackers, malware, phishing and scams, without breaking things. \
                      What a new node starts with.",
        lists: &["hagezi-normal", "hagezi-tif-mini", "hagezi-fake"],
        default: true,
    },
    Preset {
        id: "strict",
        name: "Strict",
        description: "More blocked, and more to allow now and then. Devices cannot go around \
                      goethite.",
        lists: &[
            "hagezi-pro",
            "hagezi-tif",
            "hagezi-fake",
            "dandelion-antimalware",
            "hagezi-bypass",
        ],
        default: false,
    },
    Preset {
        id: "family",
        name: "Family",
        description: "For children: Balanced's protection, gambling and adult content blocked, \
                      and no way around goethite.",
        lists: &[
            "oisd-big",
            "hagezi-tif-mini",
            "hagezi-fake",
            "hagezi-gambling",
            "hagezi-nsfw",
            "hagezi-bypass",
        ],
        default: false,
    },
    Preset {
        id: "minimal",
        name: "Don't break anything",
        description: "The essentials, for devices where nothing may break.",
        lists: &["hagezi-light", "hagezi-tif-mini"],
        default: false,
    },
];

/// Everything recommended.
pub const RECOMMENDED: Recommended = Recommended {
    lists: LISTS,
    presets: PRESETS,
};

/// How big recommended lists say they are, from their headers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RecommendedSizes {
    /// When this node read them.
    pub fetched_at: Timestamp,
    /// The lists whose header states a size; others are left out.
    pub lists: Vec<StatedSize>,
}

/// How many entries a list says it has.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct StatedSize {
    /// The list's ID.
    pub id: String,
    /// The number its header gives.
    pub entries: u64,
}

/// How many bytes of a list are read for its header.
pub const HEADER_LEN: usize = 8 * 1024;

/// The keys lists give their size under, in comment lines: HaGeZi's,
/// Steven Black's and OISD's.
const SIZE_KEYS: [&str; 3] = [
    "number of entries:",
    "number of unique domains:",
    "entries:",
];

/// The most comment lines read, and digits taken.
const MAX_HEADER_LINES: usize = 200;
const MAX_DIGITS: usize = 12;

/// The number of entries the header at the start of a list states, if it
/// states one: the first comment line (`!` or `#`) with a known key and a
/// number, such as `! Number of entries: 158,505`.
pub fn stated_size(head: &[u8]) -> Option<u64> {
    let text = String::from_utf8_lossy(head.get(..HEADER_LEN).unwrap_or(head));
    text.lines().take(MAX_HEADER_LINES).find_map(|line| {
        let comment = line
            .trim()
            .strip_prefix('!')
            .or_else(|| line.trim().strip_prefix('#'))?
            .trim()
            .to_ascii_lowercase();
        let value = SIZE_KEYS
            .iter()
            .find_map(|key| comment.strip_prefix(key))?
            .trim();
        let digits: String = value
            .chars()
            .take_while(|c| c.is_ascii_digit() || matches!(c, ',' | '.' | '_' | ' '))
            .filter(char::is_ascii_digit)
            .collect();
        if digits.is_empty() || digits.len() > MAX_DIGITS {
            return None;
        }
        digits.parse().ok()
    })
}

/// The list with this ID.
pub fn list_by_id(id: &str) -> Option<&'static RecommendedList> {
    LISTS.iter().find(|list| list.id == id)
}

/// The lists a new node starts with: the default preset's.
pub fn default_lists() -> impl Iterator<Item = &'static RecommendedList> {
    PRESETS
        .iter()
        .filter(|preset| preset.default)
        .flat_map(|preset| preset.lists.iter())
        .filter_map(|id| list_by_id(id))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn the_catalog_holds_together() {
        let ids: HashSet<&str> = LISTS.iter().map(|list| list.id).collect();
        assert_eq!(ids.len(), LISTS.len(), "IDs are unique");
        let urls: HashSet<&str> = LISTS.iter().map(|list| list.url).collect();
        assert_eq!(urls.len(), LISTS.len(), "URLs are unique");
        for list in LISTS {
            assert!(list.url.starts_with("https://"), "{}", list.id);
            assert!(list.homepage.starts_with("https://"), "{}", list.id);
            assert_eq!(
                list.topic.is_some(),
                list.category == Category::Optional,
                "{}: optional lists, and only they, have a topic",
                list.id
            );
            assert!(!list.recommended || list.badge.is_none(), "{}", list.id);
            for other in list.excludes {
                let other = list_by_id(other).unwrap_or_else(|| panic!("{other} is not a list"));
                assert!(
                    other.excludes.contains(&list.id),
                    "{} and {} exclude each other",
                    list.id,
                    other.id
                );
            }
        }
    }

    #[test]
    fn sizes_come_from_headers() {
        let hagezi =
            b"[Adblock Plus]\n! Title: HaGeZi\n! Number of entries: 158505\n||a.example^\n";
        assert_eq!(stated_size(hagezi), Some(158_505));
        assert_eq!(
            stated_size(b"! Entries: 240068\n||a.example^\n"),
            Some(240_068)
        );
        let steven = b"# Title: StevenBlack/hosts\n# Number of unique domains: 72,525\n";
        assert_eq!(stated_size(steven), Some(72_525));
        for none in [
            &b"||a.example^\n"[..],
            b"# Entries: many\n",
            b"! Entries: 1234567890123456\n",
            b"Entries: 5\n",
            b"",
        ] {
            assert_eq!(stated_size(none), None, "{}", String::from_utf8_lossy(none));
        }
    }

    #[test]
    fn presets_are_sound() {
        assert_eq!(PRESETS.iter().filter(|preset| preset.default).count(), 1);
        for preset in PRESETS {
            let lists: Vec<&RecommendedList> = preset
                .lists
                .iter()
                .map(|id| list_by_id(id).unwrap_or_else(|| panic!("{id} in {}", preset.id)))
                .collect();
            let base = lists
                .iter()
                .filter(|list| list.category == Category::Base)
                .count();
            assert_eq!(base, 1, "{}: one base list", preset.id);
            for list in &lists {
                for excluded in list.excludes {
                    assert!(
                        !preset.lists.contains(excluded),
                        "{}: {} and {excluded}",
                        preset.id,
                        list.id
                    );
                }
            }
        }
        // New nodes start with the default preset, and the lists marked
        // default are exactly its lists.
        let defaults: Vec<&str> = default_lists().map(|list| list.id).collect();
        assert_eq!(
            defaults,
            ["hagezi-normal", "hagezi-tif-mini", "hagezi-fake"]
        );
        let marked: Vec<&str> = LISTS
            .iter()
            .filter(|list| list.default)
            .map(|list| list.id)
            .collect();
        assert_eq!(marked, defaults);
    }
}
