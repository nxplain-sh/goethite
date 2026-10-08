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
| `resolve/cached answer, 100k rules, groups, 100 clients` | The same with a policy: client identification among 100 clients, the group's sources, a filter check against 100,000 rules in two lists, CNAME uncloaking |

Results:

| Date | Commit | Machine | hit | miss | insert | resolve (cached) |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-10-07 | M2 (sharded TTL cache) | Apple M3 Pro, macOS, `cargo bench` (release) | 306 ns | 72 ns | 458 ns | 319 ns |
| 2026-10-07 | Phase 2 policy (groups, sources) | same | 303 ns | 99 ns | 449 ns | 341 ns; with policy 393 ns |

Identifying the client, choosing the group's sources and checking the filter add about 50 ns to
a cached answer.

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

After rules gained a source (the list they came from, so groups can pick lists) and the lookup key
moved from the heap to a stack buffer, same machine and list, 2026-10-07:

| Name | Bloom + FST |
| --- | --- |
| blocked | 122 ns |
| near miss | 30 ns |
| miss | 26 ns |
| miss, unknown TLD | 26 ns |

Memory stays at 6.2 MiB (the per-name entries are shared: a million rules from one list use a
handful) and compiling 100,000 rules still takes 98 ms.

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

2026-10-08, v0.2.0 against v0.1.0 (commit `cd519c2`), same VM, image and command, with the query
log on (the default): every answer is now also checked against a client policy, counted in the
metrics and queued for the log. The Mac was busy this time (load average 7 to 8), so the two
versions ran interleaved in the same session, 20 s each, and only those runs compare:

| Offered load | Version | p50 | p90 | p99 | p99.9 |
| --- | --- | --- | --- | --- | --- |
| 50,000 q/s, 3 rounds | v0.1.0 | 46–49 µs | 81–103 µs | 251–303 µs | 1.3–1.8 ms |
| | v0.2.0 | 35–36 µs | 71–73 µs | 295–367 µs | 1.8–1.9 ms |
| 100,000 q/s, 2 rounds | v0.1.0 | 65–81 µs | 231–303 µs | 863–911 µs | 1.3 ms |
| | v0.2.0 | 125–131 µs | 407–471 µs | 0.98–1.09 ms | 1.9–2.1 ms |

Flat out (`-T 4`), v0.2.0 answered 178,155 q/s with no query log entries dropped.

At 50,000 q/s the two versions are alike and the p99 stays well under a millisecond. At 100,000
q/s, writing a log entry for every query costs CPU that the DNS workers, dnsperf and the writer
share on 5 vCPUs: the median doubles and the p99 reaches a millisecond, where v0.1.0 was just
under it on the same busy host. Turning the query log off removes that cost. Making the writer
cheaper is in the [backlog](../docs/BACKLOG.md).

The first v0.2.0 run was worse (p99 1.6 ms at 50,000 q/s, 140,000 q/s flat out, 5.7% of log
entries dropped): the log writer waited on its queue, so every query had to wake it with a
system call. It now empties the queue every 50 ms instead and is never woken by queries.

2026-10-08, v0.3.0 against v0.2.0 (commit `f9805ff`), same VM and command, each with its own
example config, interleaved in the same session (load average 5 to 6 on the Mac). v0.3.0 puts
every filter check behind a guard that catches a panic (fail-open), and the metrics observer
looks out for the health-check name:

| Offered load | Version | p50 | p90 | p99 | p99.9 |
| --- | --- | --- | --- | --- | --- |
| 50,000 q/s, 3 rounds | v0.2.0 | 34–43 µs | 62–123 µs | 111–927 µs | 1.0–4.6 ms |
| | v0.3.0 | 33–34 µs | 61–63 µs | 127–263 µs | 1.2–2.6 ms |
| 100,000 q/s, 2 rounds | v0.2.0 | 99–109 µs | 319–335 µs | 607–799 µs | 1.7–2.0 ms |
| | v0.3.0 | 97–99 µs | 263–271 µs | 607–655 µs | 1.6–1.7 ms |

No query was lost. The two versions are within each other's noise (the first round at 50,000
q/s ran while the host was busiest), and the p99 stays under a millisecond at 100,000 q/s.
