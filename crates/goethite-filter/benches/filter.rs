//! Filter benchmarks: lookups against a million rules, and compile time.
//!
//! Run with `cargo bench -p goethite-filter --bench filter`. The memory used
//! by the compiled rules is printed once before the measurements.

#![allow(
    clippy::unwrap_used,
    clippy::print_stdout,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::doc_markdown,
    missing_docs,
    reason = "benchmark harness, not product code"
)]

use std::fmt::Write as _;
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use goethite_filter::{Filter, FilterBuilder};
use goethite_proto::Name;

const RULES: usize = 1_000_000;

/// Synthetic list lines shaped like real blocklists: tracker hosts spread
/// over many registered domains and a few TLDs, a mix of hosts and AdGuard
/// syntax.
fn lines(count: usize) -> String {
    let tlds = ["com", "net", "org", "io", "info", "co", "xyz", "online"];
    let mut text = String::with_capacity(count * 40);
    for i in 0..count {
        let tld = tlds[i % tlds.len()];
        if i % 3 == 0 {
            writeln!(text, "||ad{i}.track{}.{tld}^", i % 50_000).unwrap();
        } else {
            writeln!(text, "0.0.0.0 px{i}.cdn{}.{tld}", i % 50_000).unwrap();
        }
    }
    text
}

fn filter(count: usize) -> Filter {
    let mut builder = FilterBuilder::new();
    builder.add_list(&lines(count));
    builder.build().unwrap()
}

fn lookups(c: &mut Criterion) {
    let filter = filter(RULES);
    println!(
        "{} rules compiled into {:.1} MiB",
        filter.rule_count(),
        filter.memory_bytes() as f64 / (1024.0 * 1024.0)
    );
    // `||ad0.track0.com^` is rule 0.
    let blocked: Name = "sub.ad0.track0.com".parse().unwrap();
    assert_eq!(filter.check(&blocked), goethite_filter::Verdict::Blocked);
    // `ad300.track300` exists, but under `.info`: a long shared prefix.
    let near_miss: Name = "sub.ad300.track300.com".parse().unwrap();
    let miss: Name = "www.example.com".parse().unwrap();
    let unknown_tld: Name = "www.example.dev".parse().unwrap();

    for (label, name) in [
        ("blocked", &blocked),
        ("near miss", &near_miss),
        ("miss", &miss),
        ("miss, unknown TLD", &unknown_tld),
    ] {
        c.bench_function(&format!("filter/check {label} (1M rules)"), |b| {
            b.iter(|| black_box(filter.check(black_box(name))));
        });
    }
}

fn build(c: &mut Criterion) {
    let text = lines(100_000);
    let mut group = c.benchmark_group("filter/build");
    group.sample_size(10);
    group.bench_function("parse and compile 100k rules", |b| {
        b.iter(|| {
            let mut builder = FilterBuilder::new();
            builder.add_list(black_box(&text));
            black_box(builder.build().unwrap())
        });
    });
    group.finish();
}

criterion_group!(benches, lookups, build);
criterion_main!(benches);
