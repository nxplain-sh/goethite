//! Filter rules for goethite.
//!
//! Parses blocklists and allowlists (hosts files, plain domain lists and the
//! core of the AdGuard/uBlock DNS filter syntax, see [`rule`]) and compiles
//! them into an FST with a Bloom prefilter, so that millions of rules fit in
//! a small, bounded amount of memory and a lookup is a single walk over the
//! name. A compiled [`Filter`] is immutable; to update the rules, build a new
//! one and swap it in.

#![forbid(unsafe_code)]

mod bloom;
mod filter;
pub mod rule;

pub use filter::{
    Filter, FilterBuilder, FilterError, ListStats, MAX_RULES, Verdict, reference_check,
};
pub use rule::{Action, LineKind, Rule, Scope, parse_line};
