//! Safe search: sending search engines to their filtered endpoints.
//!
//! The search engines below offer a "safe" host name that always filters
//! explicit results. With safe search on, a query for one of their search
//! hosts is answered with a CNAME to that host, followed by the host's own
//! records, so the browser talks to the filtered service whatever its
//! settings say.

use std::sync::OnceLock;

use goethite_filter::{Action, Filter, FilterBuilder, Rule, Scope, Source, Sources, Verdict};
use goethite_proto::Name;

/// Google's search domains (`google.<tld>`), from
/// <https://www.google.com/supported_domains>.
const GOOGLE_TLDS: &[&str] = &[
    "com", "ad", "ae", "com.af", "com.ag", "al", "am", "co.ao", "com.ar", "as", "at", "com.au",
    "az", "ba", "com.bd", "be", "bf", "bg", "com.bh", "bi", "bj", "com.bn", "com.bo", "com.br",
    "bs", "bt", "co.bw", "by", "com.bz", "ca", "cd", "cf", "cg", "ch", "ci", "co.ck", "cl", "cm",
    "cn", "com.co", "co.cr", "com.cu", "cv", "com.cy", "cz", "de", "dj", "dk", "dm", "com.do",
    "dz", "com.ec", "ee", "com.eg", "es", "com.et", "fi", "com.fj", "fm", "fr", "ga", "ge", "gg",
    "com.gh", "com.gi", "gl", "gm", "gr", "com.gt", "gy", "com.hk", "hn", "hr", "ht", "hu",
    "co.id", "ie", "co.il", "im", "co.in", "iq", "is", "it", "je", "com.jm", "jo", "co.jp",
    "co.ke", "com.kh", "ki", "kg", "co.kr", "com.kw", "kz", "la", "com.lb", "li", "lk", "co.ls",
    "lt", "lu", "lv", "com.ly", "co.ma", "md", "me", "mg", "mk", "ml", "com.mm", "mn", "com.mt",
    "mu", "mv", "mw", "com.mx", "com.my", "co.mz", "com.na", "com.ng", "com.ni", "ne", "nl", "no",
    "com.np", "nr", "nu", "co.nz", "com.om", "com.pa", "com.pe", "com.pg", "com.ph", "com.pk",
    "pl", "pn", "com.pr", "ps", "pt", "com.py", "com.qa", "ro", "ru", "rw", "com.sa", "com.sb",
    "sc", "se", "com.sg", "sh", "si", "sk", "com.sl", "sn", "so", "sm", "sr", "st", "com.sv", "td",
    "tg", "co.th", "com.tj", "tl", "tm", "tn", "to", "com.tr", "tt", "com.tw", "co.tz", "com.ua",
    "co.ug", "co.uk", "com.uy", "co.uz", "com.vc", "co.ve", "co.vi", "com.vn", "vu", "ws", "rs",
    "co.za", "co.zm", "co.zw", "cat",
];

/// The engines: their safe host and the hosts that are sent there. Google's
/// search domains are added from [`GOOGLE_TLDS`] as engine 0.
const ENGINES: &[(&str, &[&str])] = &[
    ("forcesafesearch.google.com", &[]),
    (
        "restrict.youtube.com",
        &[
            "www.youtube.com",
            "m.youtube.com",
            "youtubei.googleapis.com",
            "youtube.googleapis.com",
            "www.youtube-nocookie.com",
        ],
    ),
    ("strict.bing.com", &["www.bing.com", "bing.com"]),
    (
        "safe.duckduckgo.com",
        &[
            "duckduckgo.com",
            "www.duckduckgo.com",
            "start.duckduckgo.com",
        ],
    ),
];

struct Table {
    hosts: Filter,
    targets: Vec<Name>,
}

fn table() -> Option<&'static Table> {
    static TABLE: OnceLock<Option<Table>> = OnceLock::new();
    TABLE.get_or_init(build).as_ref()
}

fn build() -> Option<Table> {
    let mut builder = FilterBuilder::new();
    let mut targets = Vec::new();
    let mut add = |source: Source, host: &str| {
        if let Ok(name) = host.parse::<Name>() {
            builder.add_rule(
                source,
                &Rule {
                    name,
                    scope: Scope::Exact,
                    action: Action::Block,
                },
            );
        }
    };
    for (index, (target, hosts)) in ENGINES.iter().enumerate() {
        let source = Source::new(index)?;
        targets.push(target.parse().ok()?);
        for host in *hosts {
            add(source, host);
        }
        if index == 0 {
            for tld in GOOGLE_TLDS {
                add(source, &format!("google.{tld}"));
                add(source, &format!("www.google.{tld}"));
            }
        }
    }
    Some(Table {
        hosts: builder.build().ok()?,
        targets,
    })
}

/// The safe host that `name` must be sent to, if it is a search host.
pub(crate) fn target(name: &Name) -> Option<&'static Name> {
    let table = table()?;
    match table.hosts.check(name, Sources::ALL) {
        Verdict::Blocked(found) => table.targets.get(found.source.index()),
        Verdict::Pass | Verdict::Allowed(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target_of(name: &str) -> Option<String> {
        target(&name.parse().unwrap()).map(ToString::to_string)
    }

    #[test]
    fn search_hosts_have_safe_targets() {
        for (host, safe) in [
            ("www.google.com", "forcesafesearch.google.com."),
            ("google.com", "forcesafesearch.google.com."),
            ("WWW.Google.Co.UK", "forcesafesearch.google.com."),
            ("www.google.com.au", "forcesafesearch.google.com."),
            ("www.youtube.com", "restrict.youtube.com."),
            ("youtubei.googleapis.com", "restrict.youtube.com."),
            ("www.bing.com", "strict.bing.com."),
            ("duckduckgo.com", "safe.duckduckgo.com."),
        ] {
            assert_eq!(target_of(host).as_deref(), Some(safe), "{host}");
        }
        assert!(GOOGLE_TLDS.len() > 150);
    }

    #[test]
    fn other_hosts_and_the_targets_themselves_are_left_alone() {
        for host in [
            "mail.google.com",
            "forcesafesearch.google.com",
            "restrict.youtube.com",
            "strict.bing.com",
            "safe.duckduckgo.com",
            "example.com",
            "google.example",
            "youtube.com",
        ] {
            assert_eq!(target_of(host), None, "{host}");
        }
    }
}
