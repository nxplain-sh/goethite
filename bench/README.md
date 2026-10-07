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

### Filter

```sh
cargo bench -p goethite-filter --bench filter
```

A synthetic list of 1,000,000 rules (a third AdGuard `||...^`, the rest hosts entries, over
50,000 registered domains and 8 TLDs) compiles into **6.2 MiB** (FST plus Bloom prefilter).
Lookups, median, Apple M3 Pro, 2026-10-07:

| Name | Bloom + FST | FST walk only | Note |
| --- | --- | --- | --- |
| blocked | 157 ns | 146 ns | a blocked name always walks the whole FST |
| near miss | 68 ns | 133 ns | shares a long prefix with rules |
| miss | 67 ns | 87 ns | `www.example.com` |
| miss, unknown TLD | 62 ns | 62 ns | `www.example.dev` |

Most queries are misses, so the Bloom prefilter stays (it costs about 11 ns on blocked names and
1.25 MiB at a million rules). Parsing and compiling 100,000 rules takes about 100 ms; a million,
about a second, off the async runtime.

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
dnsperf reports, together with the machine and the upstreams used. For percentiles, add
`-O latency-histogram` and sum the buckets.

Rate limiting does not apply to loopback clients. Driving goethite from another host, turn it off
(`[server.rate_limit] queries_per_second = 0`), or dnsperf measures the limiter.

### Results

2026-10-07, commit `be255dd` (the code of v0.1.0), release build. Linux arm64 in a podman (libkrun) VM with 5 vCPUs
on an Apple M3 Pro; dnsperf 2.14.0 runs in the same VM, so it competes with goethite for the
CPUs. goethite uses the example config (5 `SO_REUSEPORT` UDP sockets, upstreams Quad9 over DNS
over TLS) and answers from its cache; the 96 names in `queries.txt` are cached in a warm-up pass
first. Each run lasts 20 s with `-c 4`:

| Offered load | Answered | Lost | p50 | p90 | p99 | p99.9 |
| --- | --- | --- | --- | --- | --- | --- |
| 50,000 q/s (`-Q 50000`) | 49,671 q/s | 0 | 44 µs | 73 µs | 117 µs | 303 µs |
| 100,000 q/s (`-Q 100000`) | 99,973 q/s | 0 | 43 µs | 115 µs | 735 µs | 1.6 ms |
| as fast as possible (`-T 4`) | 153,773 q/s | 0 | | | | |

Percentiles are bucket upper bounds from dnsperf's latency histogram. The slowest 0.03% (at
50,000 q/s) include names whose TTL ran out during the run and were fetched from Quad9 again.

So the target of a sub-millisecond p99 for cached answers holds at up to 100,000 queries per
second on this machine. A bare-metal run with dnsperf on a separate host is still to be
recorded.
