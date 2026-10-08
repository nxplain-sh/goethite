//! Keeping a failure in filtering from taking queries down with it.
//!
//! goethite's own code never panics on network input (the lints forbid
//! it), but the filter is a large, input-driven computation over third-party
//! code. If checking a name panics anyway, the query is not lost with it:
//! it is answered unfiltered ([`FailMode::Open`], the default, so the
//! network keeps working) or with SERVFAIL ([`FailMode::Closed`], so nothing
//! gets through unfiltered). Either way the failure is counted and logged.

use std::panic::{AssertUnwindSafe, catch_unwind};

/// What to do with a query when filtering it fails.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FailMode {
    /// Answer it unfiltered: never take the network down.
    #[default]
    Open,
    /// Answer SERVFAIL: never let a query through unfiltered.
    Closed,
}

/// Runs `check`, or returns `None` if it panicked.
pub(crate) fn guarded<T>(check: impl FnOnce() -> T) -> Option<T> {
    catch_unwind(AssertUnwindSafe(check)).ok()
}

/// Whether failure number `count` gets a log line: the 1st, 2nd, 4th, 8th
/// and so on, so a filter failing on every query cannot flood the log.
pub(crate) fn worth_logging(count: u64) -> bool {
    count.is_power_of_two()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panics_are_caught() {
        assert_eq!(guarded(|| 7), Some(7));
        let failed: Option<u8> = guarded(|| panic!("a bug in the filter"));
        assert_eq!(failed, None);
    }

    #[test]
    fn logging_is_bounded() {
        let logged = (1..=1_000_u64).filter(|n| worth_logging(*n)).count();
        assert_eq!(logged, 10);
        assert!(!worth_logging(0));
    }
}
