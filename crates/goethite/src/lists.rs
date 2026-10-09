//! Keeping downloaded filter lists on disk and up to date.
//!
//! Each list URL gets a file in the cache directory, named after a hash of
//! the URL, plus a small `.meta` file with its `ETag` and `Last-Modified`.
//! A download replaces the file only after it passes validation, by writing
//! a temporary file and renaming it, so the last good copy survives failed,
//! truncated or hostile downloads, and restarts work offline.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use goethite_filter::{FilterBuilder, ListStats, Source};

use crate::download::Validators;

/// Where downloaded lists live.
#[derive(Clone, Debug)]
pub(crate) struct ListStore {
    dir: PathBuf,
}

impl ListStore {
    /// A store in `dir`, created when the first list is saved.
    pub(crate) fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// The file holding the last good copy of `url`.
    pub(crate) fn path_for(&self, url: &str) -> PathBuf {
        self.dir
            .join(format!("list-{:016x}.txt", fnv1a(url.as_bytes())))
    }

    fn meta_path_for(&self, url: &str) -> PathBuf {
        self.path_for(url).with_extension("meta")
    }

    /// The validators saved with the last good copy of `url`, if any.
    pub(crate) fn validators(&self, url: &str) -> Validators {
        let Ok(text) = fs::read_to_string(self.meta_path_for(url)) else {
            return Validators::default();
        };
        let mut validators = Validators::default();
        for line in text.lines() {
            if let Some(etag) = line.strip_prefix("etag ") {
                validators.etag = Some(etag.to_owned());
            } else if let Some(date) = line.strip_prefix("last-modified ") {
                validators.last_modified = Some(date.to_owned());
            }
        }
        validators
    }

    /// Replaces the copy of `url` atomically and records its validators.
    pub(crate) fn save(&self, url: &str, bytes: &[u8], validators: &Validators) -> Result<()> {
        fs::create_dir_all(&self.dir)
            .with_context(|| format!("cannot create {}", self.dir.display()))?;
        write_atomically(&self.path_for(url), bytes)?;
        let mut meta = String::new();
        if let Some(etag) = &validators.etag {
            meta.push_str("etag ");
            meta.push_str(etag);
            meta.push('\n');
        }
        if let Some(date) = &validators.last_modified {
            meta.push_str("last-modified ");
            meta.push_str(date);
            meta.push('\n');
        }
        write_atomically(&self.meta_path_for(url), meta.as_bytes())
    }
}

/// Writes `bytes` to a temporary file next to `path`, flushes it to disk and
/// renames it over `path`, so readers see the old or the new file, never a
/// partial one.
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    let result = (|| -> Result<()> {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.with_context(|| format!("cannot write {}", path.display()))
}

/// Checks that a download looks like a filter list before it replaces the
/// last good copy: it must hold rules, and more rules than junk. An error
/// page served with status 200, or a list changed into something else, fails.
pub(crate) fn validate(bytes: &[u8]) -> Result<ListStats> {
    let text = String::from_utf8_lossy(bytes);
    let Some(source) = Source::new(0) else {
        bail!("no filter source available");
    };
    let stats = FilterBuilder::new().add_list(source, &text);
    if stats.rules == 0 {
        bail!("it holds no rules");
    }
    let junk = stats.invalid.saturating_add(stats.unsupported);
    if junk > stats.rules {
        bail!(
            "it has more invalid or unsupported lines ({junk}) than rules ({}); probably not a filter list",
            stats.rules
        );
    }
    Ok(stats)
}

/// FNV-1a: a stable hash for file names, unlike the standard library's
/// randomly keyed one.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (ListStore, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "goethite-store-{}-{}",
            std::process::id(),
            fnv1a(format!("{:?}", std::thread::current().id()).as_bytes())
        ));
        (ListStore::new(dir.clone()), dir)
    }

    #[test]
    fn saves_atomically_with_validators() {
        let (store, dir) = store();
        let url = "https://lists.example/hosts";
        assert_eq!(store.validators(url), Validators::default());
        let validators = Validators {
            etag: Some("\"abc\"".into()),
            last_modified: Some("Wed, 07 Oct 2026 10:00:00 GMT".into()),
        };
        store
            .save(url, b"0.0.0.0 ads.example\n", &validators)
            .unwrap();
        assert_eq!(
            fs::read(store.path_for(url)).unwrap(),
            b"0.0.0.0 ads.example\n"
        );
        assert_eq!(store.validators(url), validators);
        store
            .save(url, b"0.0.0.0 other.example\n", &Validators::default())
            .unwrap();
        assert_eq!(store.validators(url), Validators::default());
        let leftovers = fs::read_dir(&dir)
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .is_ok_and(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            })
            .count();
        assert_eq!(leftovers, 0);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn file_names_are_stable_and_distinct() {
        let (store, _) = store();
        let a = store.path_for("https://lists.example/a");
        assert_eq!(a, store.path_for("https://lists.example/a"));
        assert_ne!(a, store.path_for("https://lists.example/b"));
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
    }

    #[test]
    fn validation_rejects_things_that_are_not_lists() {
        assert!(validate(b"0.0.0.0 ads.example\n||tracker.example^\n").is_ok());
        assert!(validate(b"").is_err());
        assert!(validate(b"# only comments\n! here\n").is_err());
        let html = b"<!DOCTYPE html>\n<html>\n<head><title>404 Not Found</title></head>\n<body>gone</body>\n</html>\n";
        assert!(validate(html).is_err());
        let mostly_junk = b"ads.example\nnot valid!\nalso not valid!\n/regex/\n";
        assert!(validate(mostly_junk).is_err());
    }
}
