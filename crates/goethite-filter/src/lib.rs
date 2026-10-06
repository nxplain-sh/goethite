//! Filter rules for goethite.
//!
//! Parses blocklists and allowlists (hosts files, plain domain lists and the
//! AdGuard/uBlock DNS filter syntax) and compiles them into an FST plus a Bloom
//! prefilter so that a million rules fit in a small, bounded amount of memory.
//! Compiled filters are swapped atomically so lookups never block.
//!
//! Status: empty skeleton. The filter engine arrives in Phase 1.

#![forbid(unsafe_code)]
