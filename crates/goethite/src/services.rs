//! Blocked services: the services catalog, read and compiled.
//!
//! The catalog is AdGuard's HostlistsRegistry `services.json` (GPL-3.0),
//! downloaded with the filter lists into the list cache, where it replaces
//! the last good copy only once it reads as a catalog, or a local file
//! (`[filter] services_file`). Only the rules goethite reads, and only
//! blocking ones, are kept: a service whose rules it cannot read at all is
//! left out.

use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use goethite_api::services::{self, MAX_LEN, Service};
use goethite_filter::{Action, LineKind, parse_line};
use goethite_resolver::{ServiceFilter, ServiceRules};
use jiff::Timestamp;

/// Where the catalog comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ServicesFrom {
    /// Downloaded from this URL with the lists.
    Url(String),
    /// Read from this file.
    File(PathBuf),
}

/// The catalog, compiled.
pub(crate) struct Catalog {
    /// Its rules, one source per service.
    pub filter: Arc<ServiceFilter>,
    /// Its services, with the rules goethite uses, for the API.
    pub services: Vec<Service>,
    /// When the file was saved.
    pub saved_at: Option<Timestamp>,
}

impl Catalog {
    /// No services.
    pub(crate) fn empty() -> Self {
        Self {
            filter: Arc::new(ServiceFilter::empty()),
            services: Vec::new(),
            saved_at: None,
        }
    }
}

/// What reading the catalog's file found.
pub(crate) enum Read {
    /// There is no such file yet.
    Missing,
    /// It is the copy already in use.
    Unchanged,
    /// A new copy, compiled.
    Changed(Catalog),
}

/// Reads and compiles the catalog in `path`, unless it was saved at `known`,
/// when the copy in use was.
///
/// # Errors
///
/// If the file cannot be read, is larger than [`MAX_LEN`] or is not a
/// catalog.
pub(crate) fn read(path: &Path, known: Option<Timestamp>) -> Result<Read> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Read::Missing),
        Err(err) => {
            return Err(err).with_context(|| format!("cannot open {}", path.display()));
        }
    };
    let saved_at = file
        .metadata()
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|modified| Timestamp::try_from(modified).ok());
    if saved_at.is_some() && saved_at == known {
        return Ok(Read::Unchanged);
    }
    let mut bytes = Vec::new();
    file.take(u64::try_from(MAX_LEN)?.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {}", path.display()))?;
    let mut catalog = compile(&bytes).with_context(|| format!("cannot use {}", path.display()))?;
    catalog.saved_at = saved_at;
    Ok(Read::Changed(catalog))
}

/// Checks a download before it replaces the last good copy: it must be a
/// catalog with services goethite can use. Returns how many.
///
/// # Errors
///
/// If it is not.
pub(crate) fn validate(bytes: &[u8]) -> Result<usize> {
    Ok(compile(bytes)?.services.len())
}

/// Parses and compiles a catalog, keeping the blocking rules goethite
/// reads.
fn compile(bytes: &[u8]) -> Result<Catalog> {
    if bytes.len() > MAX_LEN {
        bail!("it is larger than {MAX_LEN} bytes");
    }
    let mut services = services::parse_services(bytes)?;
    let mut compiled = Vec::with_capacity(services.len());
    services.retain_mut(|service| {
        let mut rules = Vec::new();
        service.rules.retain(|line| {
            let mut parsed = Vec::new();
            let kept = matches!(
                parse_line(line, |rule| parsed.push(rule)),
                LineKind::Rules(_)
            ) && parsed.iter().all(|rule| rule.action == Action::Block);
            if kept {
                rules.append(&mut parsed);
            }
            kept
        });
        if rules.is_empty() {
            return false;
        }
        compiled.push(ServiceRules {
            id: service.id.as_str().into(),
            rules,
        });
        true
    });
    if services.is_empty() {
        bail!("it holds no services goethite can use");
    }
    Ok(Catalog {
        filter: Arc::new(ServiceFilter::build(&compiled)?),
        services,
        saved_at: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A catalog in the format of AdGuard's.
    const FIXTURE: &str = r#"{
        "groups": [{"id": "social_network"}, {"id": "video"}],
        "blocked_services": [
            {"id": "tiktok", "name": "TikTok", "group": "social_network", "icon_svg": "<svg/>",
             "rules": ["||tiktok.com^", "||tiktokv.com^", "/tiktok[0-9]+\\.example/"]},
            {"id": "youtube", "name": "YouTube", "group": "video", "icon_svg": "<svg/>",
             "rules": ["||youtube.com^", "||youtu.be^"]},
            {"id": "unreadable", "name": "Unreadable", "group": "video",
             "rules": ["/only-a-regex/", "@@||an-exception.example^"]}
        ]
    }"#;

    #[test]
    fn keeps_the_rules_goethite_reads() {
        let catalog = compile(FIXTURE.as_bytes()).unwrap();
        let ids: Vec<&str> = catalog.services.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(
            ids,
            ["tiktok", "youtube"],
            "no service without readable rules"
        );
        assert_eq!(
            catalog.services[0].rules,
            ["||tiktok.com^", "||tiktokv.com^"]
        );
        let filter = &catalog.filter;
        assert_eq!(filter.len(), 2);
        let youtube = filter.index("youtube").unwrap();
        let mask = goethite_resolver::ServiceMask::NONE.with(youtube);
        let name = "music.youtube.com".parse().unwrap();
        assert_eq!(filter.check(&name, &mask).map(|(i, _)| i), Some(youtube));
        assert_eq!(validate(FIXTURE.as_bytes()).unwrap(), 2);
    }

    #[test]
    fn rejects_what_is_not_a_catalog() {
        for junk in [
            "<html>Not found</html>",
            r#"{"blocked_services": []}"#,
            r#"{"blocked_services": [{"id": "x", "rules": ["/regex/"]}]}"#,
        ] {
            assert!(validate(junk.as_bytes()).is_err(), "{junk}");
        }
        let mut big = FIXTURE.as_bytes().to_vec();
        big.resize(MAX_LEN + 1, b' ');
        assert!(validate(&big).is_err());
    }

    #[test]
    fn reads_files() {
        let dir = std::env::temp_dir().join(format!("goethite-services-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("services.json");
        assert!(matches!(read(&path, None).unwrap(), Read::Missing));
        std::fs::write(&path, FIXTURE).unwrap();
        let Read::Changed(catalog) = read(&path, None).unwrap() else {
            panic!("a new catalog");
        };
        assert_eq!(catalog.services.len(), 2);
        assert!(catalog.saved_at.is_some());
        assert!(matches!(
            read(&path, catalog.saved_at).unwrap(),
            Read::Unchanged
        ));
        std::fs::write(&path, "{").unwrap();
        assert!(read(&path, None).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
