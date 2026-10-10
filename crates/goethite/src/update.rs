//! Checking the project's releases for a newer goethite.
//!
//! The check runs when the API asks for one, never on its own: it asks
//! GitHub's release API through goethite's own upstreams (see
//! [`crate::download`]) and nothing is installed. Upgrading is the
//! operator's step ([ADR 0012](../../docs/adr/0012-zero-downtime-upgrades.md)).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use goethite_api::UpdateCheck;
use goethite_resolver::{Resolver, TlsRoots, tls_client_config};
use serde::Deserialize;
use tokio::time::timeout;

use crate::download::{Downloader, Fetched, Validators};

/// Where the newest release is listed.
const RELEASE: &str = "https://api.github.com/repos/nxplain-sh/goethite/releases/latest";

/// The largest answer read.
const MAX_RELEASE: usize = 256 * 1024;

/// How long a check may take.
const CHECK_TIMEOUT: Duration = Duration::from_secs(15);

/// The version this binary is.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The newest release, and how this build compares. Resolved through
/// `resolver`, over TLS with the bundled roots.
///
/// # Errors
///
/// If GitHub cannot be reached or does not answer with a release this
/// understands.
pub(crate) async fn check(resolver: &Arc<Resolver>) -> Result<UpdateCheck> {
    let tls = tls_client_config(&TlsRoots::Bundled, &[b"h2", b"http/1.1"])?;
    let downloader = Downloader::new(Arc::clone(resolver), tls, MAX_RELEASE);
    let fetched = timeout(
        CHECK_TIMEOUT,
        downloader.fetch(RELEASE, &Validators::default()),
    )
    .await
    .map_err(|_| anyhow!("timed out after {} s", CHECK_TIMEOUT.as_secs()))??;
    let Fetched::Body { bytes, .. } = fetched else {
        bail!("GitHub answered \"not modified\" to a plain request");
    };
    let release: Release =
        serde_json::from_slice(&bytes).context("the answer is not GitHub's release JSON")?;
    let latest = version_of(&release.tag_name)?;
    Ok(UpdateCheck {
        current: VERSION.to_owned(),
        newer: is_newer(&latest, VERSION)?,
        latest,
        url: release.html_url,
        published_at: release.published_at.and_then(|at| at.parse().ok()),
    })
}

/// A release as GitHub's API describes it, the fields used.
#[derive(Deserialize)]
struct Release {
    tag_name: String,
    html_url: String,
    published_at: Option<String>,
}

/// The version of a release tag: `v0.6.0` is `0.6.0`.
fn version_of(tag: &str) -> Result<String> {
    let version = tag.strip_prefix('v').unwrap_or(tag).to_owned();
    parse_version(&version)?;
    Ok(version)
}

/// Whether `latest` is a newer version than `current`.
fn is_newer(latest: &str, current: &str) -> Result<bool> {
    Ok(parse_version(latest)? > parse_version(current)?)
}

/// The `X.Y.Z` numbers of a version.
fn parse_version(version: &str) -> Result<(u64, u64, u64)> {
    let parts: Vec<&str> = version.split('.').collect();
    let [major, minor, patch] = parts.as_slice() else {
        bail!("{version:?} is not an X.Y.Z version");
    };
    let number = |part: &str| {
        part.parse::<u64>()
            .with_context(|| format!("{version:?} is not an X.Y.Z version"))
    };
    Ok((number(major)?, number(minor)?, number(patch)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_by_number() {
        assert!(is_newer("0.7.0", "0.6.0").unwrap());
        assert!(is_newer("0.6.1", "0.6.0").unwrap());
        assert!(is_newer("0.10.0", "0.9.9").unwrap());
        assert!(is_newer("1.0.0", "0.99.99").unwrap());
        assert!(!is_newer("0.6.0", "0.6.0").unwrap());
        assert!(!is_newer("0.5.9", "0.6.0").unwrap());
    }

    #[test]
    fn release_tags_lose_their_v() {
        assert_eq!(version_of("v0.6.0").unwrap(), "0.6.0");
        assert_eq!(version_of("0.6.0").unwrap(), "0.6.0");
        for bad in ["0.6", "0.6.0.1", "banana", "", "0.6.x", "v0.6.0-rc.1"] {
            assert!(version_of(bad).is_err(), "{bad}");
        }
    }
}
