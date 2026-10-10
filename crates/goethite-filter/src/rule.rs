//! Filter rules and their text formats.
//!
//! One parser reads hosts files, plain domain lists and the core of the
//! AdGuard/uBlock DNS filter syntax, deciding the format line by line, so
//! mixed lists work too. Anything goethite does not support is counted and
//! skipped, never guessed at:
//!
//! | Line                          | Meaning                                          |
//! | ----------------------------- | ------------------------------------------------ |
//! | `0.0.0.0 ads.example`         | block exactly `ads.example` (hosts format)       |
//! | `ads.example`                 | block exactly `ads.example` (domain list)        |
//! | `*.ads.example`               | block every name below `ads.example`, not itself |
//! | `\|\|ads.example^`              | block `ads.example` and every name below it      |
//! | `\|ads.example^`               | block exactly `ads.example`                      |
//! | `.ads.example^`               | block every name below `ads.example`, not itself |
//! | `://ads.example^`             | block exactly `ads.example` (URL-style anchor)   |
//! | `@@\|\|good.example^` (etc.)    | the same patterns as exceptions: never block     |
//! | `! comment`, `# comment`, `[Adblock Plus 2.0]`, blank | ignored               |
//!
//! Unsupported for now: cosmetic and HTML filtering rules (`example.com##...`,
//! `example.com$$...`), regular expressions (`/.../`), modifiers (`$...`),
//! patterns without a `||` or `|` anchor, wildcards inside names, and hosts
//! entries with a real address (those are rewrites, not blocks).

use std::net::IpAddr;

use goethite_proto::Name;

/// The longest line accepted; longer lines are invalid.
pub const MAX_LINE_LEN: usize = 4096;

/// Which names a rule matches, relative to its own name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scope {
    /// Only the name itself.
    Exact,
    /// The name and every name below it.
    Subtree,
    /// Every name below the name, but not the name itself.
    Subdomains,
}

/// What a matching rule does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// Block the name.
    Block,
    /// An exception: never block the name, whatever other rules say.
    Allow,
}

/// One parsed rule.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Rule {
    /// The rule's name.
    pub name: Name,
    /// Which names relative to `name` it matches.
    pub scope: Scope,
    /// What it does.
    pub action: Action,
}

impl Rule {
    /// Whether this rule matches `name`.
    pub fn matches(&self, name: &Name) -> bool {
        match self.scope {
            Scope::Exact => name == &self.name,
            Scope::Subtree => name.is_within(&self.name),
            Scope::Subdomains => name != &self.name && name.is_within(&self.name),
        }
    }
}

/// What a line turned out to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineKind {
    /// It held this many rules (more than one for hosts lines with aliases).
    Rules(usize),
    /// A comment, header or blank line.
    Ignored,
    /// Valid syntax that goethite does not support yet.
    Unsupported(&'static str),
    /// Not a valid rule.
    Invalid(&'static str),
}

/// Names that hosts files map to loopback for the system's own sake; they
/// are not blocks.
const HOSTS_SYSTEM_NAMES: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
    "0.0.0.0",
];

/// Cosmetic and HTML-filtering markers of the AdGuard/uBlock syntax, which
/// goethite does not support: reading `example.com##.banner` as a domain line
/// would block the site it only restyles.
const COSMETIC_MARKERS: &[&str] = &["##", "#@#", "#?#", "#$#", "#%#", "$$", "$@$"];

/// The cosmetic markers that carry no domain part and so start a line.
const LEADING_COSMETIC_MARKERS: &[&str] = &["##", "#@#", "#?#", "#$#", "#%#"];

fn is_cosmetic(line: &str) -> bool {
    COSMETIC_MARKERS.iter().any(|marker| line.contains(marker))
}

/// Strips a trailing `#` comment. A `#` starts a comment only at the start of
/// the line or after whitespace, so `example.com##.banner` is not cut short.
fn strip_comment(line: &str) -> &str {
    let mut after_space = true;
    for (index, ch) in line.char_indices() {
        if ch == '#' && after_space {
            return line.split_at(index).0.trim_end();
        }
        after_space = ch.is_whitespace();
    }
    line.trim_end()
}

/// Parses one line, passing each rule it holds to `add`.
pub fn parse_line(line: &str, mut add: impl FnMut(Rule)) -> LineKind {
    if line.len() > MAX_LINE_LEN {
        return LineKind::Invalid("line too long");
    }
    let line = line.trim();
    if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
        return LineKind::Ignored;
    }
    if line.starts_with('#') {
        // A global cosmetic rule; anything else starting with `#` is a
        // comment.
        return if LEADING_COSMETIC_MARKERS
            .iter()
            .any(|marker| line.starts_with(marker))
        {
            LineKind::Unsupported("cosmetic rule")
        } else {
            LineKind::Ignored
        };
    }
    // Strip the comment before `is_adblock`, so a hosts line that ends with
    // `# $ ...` is not taken for a modifier rule.
    let line = strip_comment(line);
    if line.is_empty() {
        return LineKind::Ignored;
    }
    if is_cosmetic(line) {
        return LineKind::Unsupported("cosmetic or HTML filtering rule");
    }
    if let Some(pattern) = line.strip_prefix("@@") {
        return parse_adblock(pattern, Action::Allow, &mut add);
    }
    if is_adblock(line) {
        return parse_adblock(line, Action::Block, &mut add);
    }
    let mut tokens = line.split_whitespace();
    let Some(first) = tokens.next() else {
        return LineKind::Ignored;
    };
    // Hosts files may give link-local addresses with a zone: `fe80::1%lo0`.
    let address = first.split_once('%').map_or(first, |(ip, _zone)| ip);
    if let Ok(ip) = address.parse::<IpAddr>() {
        return parse_hosts(ip, tokens, &mut add);
    }
    if tokens.next().is_some() {
        return LineKind::Invalid("more than one name on a line");
    }
    if let Some(rest) = first.strip_prefix('.')
        && !rest.is_empty()
        && !rest.starts_with('.')
    {
        return LineKind::Unsupported("leading dot without a closing ^");
    }
    match parse_pattern(first) {
        Ok((name, wildcard)) => {
            let scope = if wildcard {
                Scope::Subdomains
            } else {
                Scope::Exact
            };
            add(Rule {
                name,
                scope,
                action: Action::Block,
            });
            LineKind::Rules(1)
        }
        Err(kind) => kind,
    }
}

fn is_adblock(line: &str) -> bool {
    line.starts_with('|')
        || line.starts_with("://")
        || line.starts_with('/')
        || line.contains('^')
        || line.contains('$')
}

fn parse_adblock(pattern: &str, action: Action, add: &mut impl FnMut(Rule)) -> LineKind {
    if pattern.len() > 1 && pattern.starts_with('/') && pattern.ends_with('/') {
        return LineKind::Unsupported("regular expression");
    }
    if pattern.contains('$') {
        return LineKind::Unsupported("modifiers");
    }
    let (body, anchored_subtree) = if let Some(rest) = pattern.strip_prefix("||") {
        (rest, true)
    } else if let Some(rest) = pattern.strip_prefix('|') {
        (rest, false)
    } else if let Some(rest) = pattern.strip_prefix("://") {
        // URL-style: the hostname starts right after the scheme, so this
        // anchors like `|`.
        (rest, false)
    } else if pattern.starts_with("*.") {
        (pattern, false)
    } else if let Some(rest) = pattern.strip_prefix('.')
        && rest.ends_with('^')
    {
        // `.ads.example^`: a label boundary, then the name to the end, which
        // is every name below `ads.example`.
        return parse_adblock(&format!("*.{rest}"), action, add);
    } else {
        return LineKind::Unsupported("pattern without a || or | anchor");
    };
    // `^` ends the domain; a trailing `|` (end anchor) changes nothing here.
    let body = body.strip_suffix('|').unwrap_or(body);
    let body = body.strip_suffix('^').unwrap_or(body);
    if body.contains('^') || body.contains('|') {
        return LineKind::Unsupported("separator inside a pattern");
    }
    match parse_pattern(body) {
        Ok((name, wildcard)) => {
            let scope = match (wildcard, anchored_subtree) {
                (true, _) => Scope::Subdomains,
                (false, true) => Scope::Subtree,
                (false, false) => Scope::Exact,
            };
            add(Rule {
                name,
                scope,
                action,
            });
            LineKind::Rules(1)
        }
        Err(kind) => kind,
    }
}

fn parse_hosts<'a>(
    ip: IpAddr,
    names: impl Iterator<Item = &'a str>,
    add: &mut impl FnMut(Rule),
) -> LineKind {
    let mut names = names.peekable();
    if names.peek().is_none() {
        return LineKind::Unsupported("IP address rule");
    }
    let mut names = names
        .filter(|token| {
            !HOSTS_SYSTEM_NAMES
                .iter()
                .any(|system| system.eq_ignore_ascii_case(token))
        })
        .peekable();
    // Lines that only map system names (`255.255.255.255 broadcasthost`).
    if names.peek().is_none() {
        return LineKind::Ignored;
    }
    if !(ip.is_unspecified() || ip.is_loopback()) {
        return LineKind::Unsupported("hosts entry with a real address");
    }
    let mut count = 0_usize;
    let mut invalid = None;
    for token in names {
        match parse_pattern(token) {
            Ok((name, false)) => {
                add(Rule {
                    name,
                    scope: Scope::Exact,
                    action: Action::Block,
                });
                count = count.saturating_add(1);
            }
            Ok((_, true)) => invalid = Some("wildcard in a hosts file"),
            Err(LineKind::Invalid(reason)) => invalid = Some(reason),
            Err(_) => invalid = Some("invalid name"),
        }
    }
    match (count, invalid) {
        (0, Some(reason)) => LineKind::Invalid(reason),
        (0, None) => LineKind::Ignored,
        (count, _) => LineKind::Rules(count),
    }
}

/// Parses `name` or `*.name`; the flag says whether the `*.` was there.
fn parse_pattern(text: &str) -> Result<(Name, bool), LineKind> {
    let (text, wildcard) = match text.strip_prefix("*.") {
        Some(rest) => (rest, true),
        None => (text, false),
    };
    if text.contains('*') {
        return Err(LineKind::Unsupported("wildcard inside a name"));
    }
    if !text.is_ascii() {
        return Err(LineKind::Invalid("non-ASCII name"));
    }
    let text = text.strip_suffix('.').unwrap_or(text);
    if text.is_empty() {
        return Err(LineKind::Invalid("empty name"));
    }
    if text.parse::<IpAddr>().is_ok() {
        return Err(LineKind::Unsupported("IP address rule"));
    }
    let lower = text.to_ascii_lowercase();
    let name = lower
        .parse::<Name>()
        .map_err(|_| LineKind::Invalid("invalid name"))?;
    // `..` and the like reduce to the root, which no rule may name.
    if name.is_root() {
        return Err(LineKind::Invalid("empty name"));
    }
    Ok((name, wildcard))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(line: &str) -> (LineKind, Vec<Rule>) {
        let mut rules = Vec::new();
        let kind = parse_line(line, |rule| rules.push(rule));
        (kind, rules)
    }

    fn rule(name: &str, scope: Scope, action: Action) -> Rule {
        Rule {
            name: name.parse().unwrap(),
            scope,
            action,
        }
    }

    #[test]
    fn hosts_lines() {
        let (kind, rules) = parse("0.0.0.0 ads.example tracker.example # trailing comment");
        assert_eq!(kind, LineKind::Rules(2));
        assert_eq!(
            rules,
            vec![
                rule("ads.example", Scope::Exact, Action::Block),
                rule("tracker.example", Scope::Exact, Action::Block)
            ]
        );
        assert_eq!(
            parse("127.0.0.1\tADS.Example").1[0].name.to_string(),
            "ads.example."
        );
        assert_eq!(parse(":: ads.example").0, LineKind::Rules(1));
        assert_eq!(parse("127.0.0.1 localhost").0, LineKind::Ignored);
        assert_eq!(parse("::1 ip6-localhost ip6-loopback").0, LineKind::Ignored);
        assert_eq!(
            parse("192.168.1.5 printer.lan").0,
            LineKind::Unsupported("hosts entry with a real address")
        );
        assert!(matches!(
            parse("0.0.0.0 bad_label!.example").0,
            LineKind::Invalid(_)
        ));
    }

    #[test]
    fn real_world_hosts_and_adguard_lines() {
        // From StevenBlack's hosts file and the AdGuard DNS filter.
        for line in [
            "fe80::1%lo0 localhost",
            "255.255.255.255 broadcasthost",
            "ff00::0 ip6-localnet",
            "ff02::1 ip6-allnodes",
        ] {
            assert_eq!(parse(line).0, LineKind::Ignored, "{line:?}");
        }
        assert_eq!(
            parse(".bbelements.com^").1,
            vec![rule("bbelements.com", Scope::Subdomains, Action::Block)]
        );
        assert_eq!(
            parse("@@.good.example^").1,
            vec![rule("good.example", Scope::Subdomains, Action::Allow)]
        );
        assert_eq!(
            parse(".3.n.2.1.l50.js").0,
            LineKind::Unsupported("leading dot without a closing ^")
        );
        assert_eq!(
            parse("://jhf.example^").1,
            vec![rule("jhf.example", Scope::Exact, Action::Block)]
        );
        assert_eq!(
            parse("://*.cdn.example^").1,
            vec![rule("cdn.example", Scope::Subdomains, Action::Block)]
        );
        assert_eq!(
            parse("vkcdn.example^").0,
            LineKind::Unsupported("pattern without a || or | anchor")
        );
        assert_eq!(
            parse("||194.63.143.96^").0,
            LineKind::Unsupported("IP address rule")
        );
        assert_eq!(
            parse("||ads.livetv*.me^").0,
            LineKind::Unsupported("wildcard inside a name")
        );
    }

    #[test]
    fn domain_lines() {
        assert_eq!(
            parse("Ads.Example.").1,
            vec![rule("ads.example", Scope::Exact, Action::Block)]
        );
        assert_eq!(
            parse("*.ads.example").1,
            vec![rule("ads.example", Scope::Subdomains, Action::Block)]
        );
        assert_eq!(parse("ads.example # why").0, LineKind::Rules(1));
        assert!(matches!(parse("two names.example").0, LineKind::Invalid(_)));
        assert!(matches!(parse("bücher.example").0, LineKind::Invalid(_)));
        assert!(matches!(parse("ads*.example").0, LineKind::Unsupported(_)));
        assert!(matches!(parse("192.0.2.1").0, LineKind::Unsupported(_)));
    }

    #[test]
    fn adblock_lines() {
        assert_eq!(
            parse("||ads.example^").1,
            vec![rule("ads.example", Scope::Subtree, Action::Block)]
        );
        assert_eq!(
            parse("||ads.example").1,
            vec![rule("ads.example", Scope::Subtree, Action::Block)]
        );
        assert_eq!(
            parse("|ads.example^").1,
            vec![rule("ads.example", Scope::Exact, Action::Block)]
        );
        assert_eq!(
            parse("@@||good.example^").1,
            vec![rule("good.example", Scope::Subtree, Action::Allow)]
        );
        assert_eq!(
            parse("@@|good.example^|").1,
            vec![rule("good.example", Scope::Exact, Action::Allow)]
        );
        assert_eq!(
            parse("||*.ads.example^").1,
            vec![rule("ads.example", Scope::Subdomains, Action::Block)]
        );
    }

    #[test]
    fn unsupported_and_ignored_lines() {
        for (line, kind) in [
            ("", LineKind::Ignored),
            ("   ", LineKind::Ignored),
            ("! AdGuard comment", LineKind::Ignored),
            ("# hosts comment", LineKind::Ignored),
            ("[Adblock Plus 2.0]", LineKind::Ignored),
            (
                "/ads[0-9]+\\.example/",
                LineKind::Unsupported("regular expression"),
            ),
            (
                "||ads.example^$important",
                LineKind::Unsupported("modifiers"),
            ),
            (
                "ads.example^",
                LineKind::Unsupported("pattern without a || or | anchor"),
            ),
            (
                "||ads^example^",
                LineKind::Unsupported("separator inside a pattern"),
            ),
        ] {
            assert_eq!(parse(line).0, kind, "{line:?}");
        }
        assert!(matches!(
            parse(&"a".repeat(MAX_LINE_LEN + 1)).0,
            LineKind::Invalid(_)
        ));
        assert!(matches!(parse("||^").0, LineKind::Invalid(_)));
        // Found by fuzzing: `..` reduced to the root name.
        for root in [".", "..", "||.^", "@@||..^", "0.0.0.0 ..", "*.."] {
            assert!(matches!(parse(root).0, LineKind::Invalid(_)), "{root:?}");
        }
    }

    #[test]
    fn cosmetic_rules_are_not_domain_blocks() {
        for line in [
            "example.com##.banner",
            "example.com#@#.banner",
            "example.com#?#.banner:has(.ad)",
            "example.com#$#.banner { display: none }",
            "example.com#%#window.ads = 0",
            "example.com$$script[tag-content=\"ad\"]",
            "example.com$@$script[tag-content=\"ad\"]",
            "##.banner",
            "#@#.banner",
        ] {
            let (kind, rules) = parse(line);
            assert!(rules.is_empty(), "{line:?} parsed as {rules:?}");
            assert!(
                matches!(kind, LineKind::Unsupported(_)),
                "{line:?} -> {kind:?}"
            );
        }
    }

    #[test]
    fn hash_is_a_comment_only_after_whitespace() {
        let (kind, rules) = parse("0.0.0.0 ads.example # $ modifiers");
        assert_eq!(kind, LineKind::Rules(1));
        assert_eq!(
            rules,
            vec![rule("ads.example", Scope::Exact, Action::Block)]
        );
        assert!(matches!(
            parse("ads.example#comment").0,
            LineKind::Invalid(_)
        ));
    }

    #[test]
    fn matching_by_scope() {
        let name = |s: &str| s.parse::<Name>().unwrap();
        let exact = rule("ads.example", Scope::Exact, Action::Block);
        let subtree = rule("ads.example", Scope::Subtree, Action::Block);
        let below = rule("ads.example", Scope::Subdomains, Action::Block);
        for (query, e, t, b) in [
            ("ads.example", true, true, false),
            ("x.ads.example", false, true, true),
            ("example", false, false, false),
            ("badads.example", false, false, false),
        ] {
            assert_eq!(exact.matches(&name(query)), e, "exact {query}");
            assert_eq!(subtree.matches(&name(query)), t, "subtree {query}");
            assert_eq!(below.matches(&name(query)), b, "subdomains {query}");
        }
    }
}
