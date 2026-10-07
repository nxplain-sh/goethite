//! Loading filter lists and keeping the compiled filter current.

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use goethite_filter::{Filter, FilterBuilder, ListStats};
use goethite_resolver::Blocking;
use tracing::{error, info, warn};

use crate::config::FilterSection;

/// List files larger than this many bytes are skipped.
const MAX_LIST_LEN: usize = 128 * 1024 * 1024;

/// Reads the configured rules and lists and compiles them, for startup: if
/// compiling fails, nothing is blocked rather than nothing resolving.
pub fn build(section: &FilterSection) -> Filter {
    compile(section).unwrap_or_else(Filter::empty)
}

/// Reads the configured rules and lists and compiles them.
///
/// A list that cannot be read is logged and skipped rather than failing:
/// filtering must never take resolution down. `None` if compiling failed.
fn compile(section: &FilterSection) -> Option<Filter> {
    let mut builder = FilterBuilder::new();
    if !section.rules.is_empty() {
        let stats = builder.add_list(&section.rules.join("\n"));
        log_stats("config rules", stats);
    }
    for list in &section.list {
        let source = list.path.display().to_string();
        match read_list(&list.path) {
            Ok(text) => {
                let stats = builder.add_list(&text);
                log_stats(&source, stats);
            }
            Err(err) => error!(list = %source, "{err:#}; skipping this list"),
        }
    }
    match builder.build() {
        Ok(filter) => {
            info!(
                rules = filter.rule_count(),
                memory_kib = filter.memory_bytes() / 1024,
                "filter ready"
            );
            Some(filter)
        }
        Err(err) => {
            error!(%err, "cannot compile the filter");
            None
        }
    }
}

fn log_stats(source: &str, stats: ListStats) {
    info!(
        list = %source,
        rules = stats.rules,
        unsupported = stats.unsupported,
        invalid = stats.invalid,
        "loaded filter rules"
    );
    if stats.over_limit > 0 {
        warn!(list = %source, dropped = stats.over_limit, "filter rule limit reached");
    }
}

/// Reads a list file, refusing files over [`MAX_LIST_LEN`]. Invalid UTF-8 is
/// replaced rather than rejected, so one bad byte does not lose the list.
fn read_list(path: &Path) -> Result<String> {
    let file =
        File::open(path).with_context(|| format!("cannot open filter list {}", path.display()))?;
    let limit = u64::try_from(MAX_LIST_LEN)?.saturating_add(1);
    let mut bytes = Vec::new();
    let len = file
        .take(limit)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read filter list {}", path.display()))?;
    if len > MAX_LIST_LEN {
        bail!(
            "filter list {} is larger than {MAX_LIST_LEN} bytes",
            path.display()
        );
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Rebuilds the filter from `section` off the async runtime and swaps it in.
/// If compiling fails, the current filter stays.
pub async fn reload(blocking: &Arc<Blocking>, section: FilterSection) {
    match tokio::task::spawn_blocking(move || compile(&section)).await {
        Ok(Some(filter)) => blocking.replace(filter),
        Ok(None) => error!("filter reload failed; keeping the current filter"),
        Err(err) => error!(%err, "filter reload failed; keeping the current filter"),
    }
}

#[cfg(test)]
mod tests {
    use goethite_filter::Verdict;

    use super::*;
    use crate::config::ListSection;

    #[test]
    fn unreadable_lists_are_skipped() {
        let dir = std::env::temp_dir().join(format!("goethite-lists-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let good = dir.join("good.txt");
        std::fs::write(&good, "0.0.0.0 ads.example\n").unwrap();
        let section = FilterSection {
            rules: vec!["||tracker.example^".into()],
            list: vec![
                ListSection { path: good },
                ListSection {
                    path: dir.join("missing.txt"),
                },
            ],
            ..FilterSection::default()
        };
        let filter = build(&section);
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(filter.rule_count(), 2);
        assert_eq!(
            filter.check(&"ads.example".parse().unwrap()),
            Verdict::Blocked
        );
        assert_eq!(
            filter.check(&"x.tracker.example".parse().unwrap()),
            Verdict::Blocked
        );
    }

    #[test]
    fn oversized_lists_are_refused() {
        let path = std::env::temp_dir().join(format!("goethite-huge-{}.txt", std::process::id()));
        let file = File::create(&path).unwrap();
        file.set_len(u64::try_from(MAX_LIST_LEN).unwrap() + 1)
            .unwrap();
        let err = read_list(&path).unwrap_err();
        std::fs::remove_file(&path).unwrap();
        assert!(err.to_string().contains("larger than"), "{err:#}");
    }
}
