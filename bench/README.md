# Benchmarks

Every performance claim goethite makes needs a benchmark here: a criterion bench in the code, or a
reproducible dnsperf run (see [`AGENTS.md`](../AGENTS.md#performance-rules)). Record each run with
the date, commit, machine and command, so a later run can be compared with it.

## Criterion micro-benchmarks

```sh
cargo bench -p goethite-resolver --bench cache
```

| Benchmark | What it measures |
| --- | --- |
| `cache/get hit (10k entries)` | Looking up a cached answer and building the response (TTL count-down, client case) |
| `cache/get miss (10k entries)` | A lookup that misses |
| `cache/insert (10k entries)` | Deciding what to cache and storing it, evicting when a shard is full |
| `resolve/cached answer` | The whole pipeline in front of the network for a cached name: query-type policy, local records, cache |

Results:

| Date | Commit | Machine | hit | miss | insert | resolve (cached) |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-10-07 | M2 (sharded TTL cache) | Apple M3 Pro, macOS, `cargo bench` (release) | 306 ns | 72 ns | 458 ns | 319 ns |

These cover the resolver only. Decoding the query and encoding the response, and the socket round
trip, come on top; the end-to-end number below is the one the p99 target refers to.

## End-to-end with dnsperf

[`dnsperf.sh`](dnsperf.sh) drives a running goethite with
[dnsperf](https://www.dns-oarc.net/tools/dnsperf) (from `dnsperf` packages, or built from
DNS-OARC's source) using the names in [`queries.txt`](queries.txt):

```sh
cargo build --release
./target/release/goethite run --config config/goethite.example.toml &
bench/dnsperf.sh 127.0.0.1 15353 30     # server, port, seconds
```

The first pass fills the cache from the upstreams; the script then runs a second, measured pass
that is served from the cache. Record the queries per second and the latency percentiles that
dnsperf reports, together with the machine and the upstreams used.

No end-to-end run has been recorded yet, so goethite makes no end-to-end performance claim yet.
