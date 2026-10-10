//! Safe search: sending search engines to their filtered endpoints.
//!
//! The search engines below offer a "safe" host name that always filters
//! explicit results. With safe search on, a query for one of their search
//! hosts is answered with a CNAME to that host, followed by the host's own
//! records, so the browser talks to the filtered service whatever its
//! settings say. Yandex offers no such host: its safe endpoint is a fixed
//! address, answered directly.

use std::net::Ipv4Addr;
use std::sync::OnceLock;

use goethite_filter::{Action, Filter, FilterBuilder, Rule, Scope, Source, Sources, Verdict};
use goethite_proto::{Name, RecordType};

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

/// Yandex's search domains (`yandex.<tld>`), from AdGuard Home's safe search
/// rules; `ya.ru` and `yandex.рф` (`xn--d1acpjx3f.xn--p1ai`) are listed
/// beside them.
const YANDEX_TLDS: &[&str] = &[
    "az", "by", "co.il", "com.am", "com.ge", "com.ru", "com.tr", "com", "de", "ee", "eu", "fi",
    "fr", "kz", "lt", "lv", "md", "net", "org", "pl", "ru", "tj", "tm", "uz",
];

/// One engine: the safe target, the search hosts sent to it, and optionally
/// a family of `{name}.{tld}` hosts (with their `www.` forms) added from a
/// TLD list. A target that parses as an IPv4 address is answered directly.
struct Engine {
    target: &'static str,
    hosts: &'static [&'static str],
    family: Option<(&'static str, &'static [&'static str])>,
}

/// The engines, with Google's and Yandex's search domains added from their
/// TLD lists.
const ENGINES: &[Engine] = &[
    Engine {
        target: "forcesafesearch.google.com",
        hosts: &[],
        family: Some(("google", GOOGLE_TLDS)),
    },
    Engine {
        target: "restrict.youtube.com",
        hosts: &[
            "www.youtube.com",
            "m.youtube.com",
            "youtubei.googleapis.com",
            "youtube.googleapis.com",
            "www.youtube-nocookie.com",
        ],
        family: None,
    },
    Engine {
        target: "strict.bing.com",
        hosts: &["www.bing.com", "bing.com"],
        family: None,
    },
    Engine {
        target: "safe.duckduckgo.com",
        hosts: &[
            "duckduckgo.com",
            "www.duckduckgo.com",
            "start.duckduckgo.com",
        ],
        family: None,
    },
    Engine {
        target: "strict-safe-search.ecosia.org",
        hosts: &["www.ecosia.org"],
        family: None,
    },
    Engine {
        target: "safesearch.pixabay.com",
        hosts: &["pixabay.com"],
        family: None,
    },
    Engine {
        target: "213.180.193.56",
        hosts: &[
            "ya.ru",
            "www.ya.ru",
            "xn--d1acpjx3f.xn--p1ai",
            "www.xn--d1acpjx3f.xn--p1ai",
        ],
        family: Some(("yandex", YANDEX_TLDS)),
    },
];

/// Where a search host is sent: a name to resolve and CNAME to, or an
/// address to answer with.
pub(crate) enum Target {
    Name(Name),
    Address(Ipv4Addr),
}

impl Target {
    /// Whether the target answers a query of `qtype`. A pinned address is
    /// answered for its own record type only (Yandex's safe endpoint is
    /// A-only); a name answers any type through its records.
    pub(crate) fn covers(&self, qtype: RecordType) -> bool {
        match self {
            Self::Name(_) => true,
            Self::Address(_) => qtype == RecordType::A,
        }
    }
}

struct Table {
    hosts: Filter,
    targets: Vec<Target>,
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
    for (index, engine) in ENGINES.iter().enumerate() {
        let source = Source::new(index)?;
        targets.push(target_from(engine.target)?);
        for host in engine.hosts {
            add(source, host);
        }
        if let Some((family, tlds)) = engine.family {
            for tld in tlds {
                add(source, &format!("{family}.{tld}"));
                add(source, &format!("www.{family}.{tld}"));
            }
        }
    }
    Some(Table {
        hosts: builder.build().ok()?,
        targets,
    })
}

fn target_from(target: &str) -> Option<Target> {
    if let Ok(address) = target.parse::<Ipv4Addr>() {
        return Some(Target::Address(address));
    }
    target.parse::<Name>().ok().map(Target::Name)
}

/// The safe target `name` must be sent to, if it is a search host.
pub(crate) fn target(name: &Name) -> Option<&'static Target> {
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
        target(&name.parse().unwrap()).map(|target| match target {
            Target::Name(name) => name.to_string(),
            Target::Address(address) => address.to_string(),
        })
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
            ("www.ecosia.org", "strict-safe-search.ecosia.org."),
            ("pixabay.com", "safesearch.pixabay.com."),
            ("ya.ru", "213.180.193.56"),
            ("yandex.ru", "213.180.193.56"),
            ("www.yandex.com.tr", "213.180.193.56"),
            ("xn--d1acpjx3f.xn--p1ai", "213.180.193.56"),
            ("www.xn--d1acpjx3f.xn--p1ai", "213.180.193.56"),
        ] {
            assert_eq!(target_of(host).as_deref(), Some(safe), "{host}");
        }
        assert!(GOOGLE_TLDS.len() > 150);
        assert!(YANDEX_TLDS.len() > 20);
    }

    #[test]
    fn other_hosts_and_the_targets_themselves_are_left_alone() {
        for host in [
            "mail.google.com",
            "forcesafesearch.google.com",
            "restrict.youtube.com",
            "strict.bing.com",
            "safe.duckduckgo.com",
            "ecosia.org",
            "strict-safe-search.ecosia.org",
            "mail.pixabay.com",
            "safesearch.pixabay.com",
            "mail.yandex.ru",
            "example.com",
            "google.example",
            "youtube.com",
        ] {
            assert_eq!(target_of(host), None, "{host}");
        }
    }

    #[test]
    fn pinned_addresses_cover_a_queries_only() {
        let address = Target::Address(Ipv4Addr::new(213, 180, 193, 56));
        assert!(address.covers(RecordType::A));
        assert!(!address.covers(RecordType::AAAA));
        let name = Target::Name("safe.example.".parse().unwrap());
        assert!(name.covers(RecordType::A));
        assert!(name.covers(RecordType::AAAA));
    }
}
