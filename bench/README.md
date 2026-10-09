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

### Release profile

The workspace's `[profile.release]` (which `cargo bench` inherits) uses thin LTO and one codegen
unit since 2026-10-09; the results above were taken with Cargo's default profile. Both profiles,
measured back to back on the same code (`98d470d`), Apple M3 Pro, macOS, with the default one
selected by `CARGO_PROFILE_{RELEASE,BENCH}_LTO=false` and `..._CODEGEN_UNITS=16` and recorded as a
criterion baseline (`-- --save-baseline default`, then `-- --baseline default`). Times are
criterion's point estimates; Change is its estimate of the difference:

| | Default profile | Thin LTO, 1 codegen unit | Change |
| --- | --- | --- | --- |
| `goethite` binary (release) | 24.9 MB | 19.0 MB | −24% |
| Release build of `goethite`, clean | 76 s | 94 s | +24% |
| `cache/get hit (10k entries)` | 319 ns | 302 ns | −4% |
| `cache/get miss (10k entries)` | 97.6 ns | 76.9 ns | −18% |
| `cache/insert (10k entries)` | 479 ns | 493 ns | +4% |
| `resolve/cached answer` | 403 ns | 385 ns | −4% |
| `resolve/cached answer, 100k rules, groups, 100 clients` | 459 ns | 467 ns | no change (p = 0.57) |
| `filter/check blocked (1M rules)` | 122 ns | 120 ns | −2% |
| `filter/check near miss (1M rules)` | 29.1 ns | 30.4 ns | +4% |
| `filter/check miss (1M rules)` | 26.6 ns | 27.2 ns | +2% |
| `filter/check miss, unknown TLD (1M rules)` | 26.8 ns | 27.0 ns | +2% |
| `filter/build/parse and compile 100k rules` | 93.7 ms | 88.8 ms | −5% |

The lookups move by a few nanoseconds either way; the profile is kept for the 24% smaller binary
(less to download, verify and map on small arm64 hosts) at the cost of slower release builds.

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

2026-10-09, v0.4.0 against v0.3.0 (commit `6c3a4d8`), release builds, same VM, image and command,
each with its own example config, interleaved in the same session, alternating which goes first.
v0.4.0's example config starts with the recommended lists (414,791 rules where v0.3.0's has one),
and every query also passes the DNS leak test's name check and the EDNS padding decision. The Mac
was much busier than in earlier runs (load average 16 to 22, an antivirus scan taking over three
cores), which shows in both versions:

| Offered load | Version | p50 | p90 | p99 | p99.9 |
| --- | --- | --- | --- | --- | --- |
| 50,000 q/s, 3 rounds | v0.3.0 | 40–58 µs | 119–479 µs | 1.02–2.17 ms | 2.6–7.3 ms |
| | v0.4.0 | 45–63 µs | 151–415 µs | 1.01–1.92 ms | 3.1–6.1 ms |
| 100,000 q/s, 2 rounds | v0.3.0 | 121–139 µs | 415–527 µs | 1.25–1.38 ms | 2.3–2.7 ms |
| | v0.4.0 | 151–179 µs | 511–607 µs | 1.25–1.50 ms | 2.6–3.1 ms |

Flat out (`-T 4`), v0.4.0 answered 144,274 q/s and v0.3.0 131,498 q/s. No query was lost.

The two versions overlap in every column, so v0.4.0 shows no regression. On this busy host
neither kept the p99 under a millisecond, where v0.3.0 did the day before; the sub-millisecond
target needs a rerun on a quiet machine before it can be claimed for v0.4.0.

2026-10-09, v0.5.0 against v0.4.0 (commit `5f96b19`), release builds, same VM, image and command,
each with its own example config (both start with the same recommended lists, 415,263 rules),
interleaved in the same session, alternating which goes first, 20 s each. v0.5.0 checks every
query against the access lists and the local records, counts TCP and encrypted queries against
the rate limiter, and runs under its sandbox: seccomp checks every system call (Landlock costs
nothing per query). The Mac was busy again (load average 7.7 to 11.6, the release fuzz run taking
a core):

| Offered load | Version | Answered | p50 | p90 | p99 | p99.9 |
| --- | --- | --- | --- | --- | --- | --- |
| 50,000 q/s, 3 rounds | v0.4.0 | 49,508–49,926 q/s | 69–121 µs | 391–639 µs | 1.47–1.82 ms | 2.9–6.7 ms |
| | v0.5.0 | 49,678–49,981 q/s | 51–89 µs | 215–575 µs | 1.06–1.63 ms | 2.4–3.2 ms |
| 100,000 q/s, 2 rounds | v0.4.0 | 94,294–98,650 q/s | 231–343 µs | 799–990 µs | 1.66–1.86 ms | 3.0–3.3 ms |
| | v0.5.0 | 89,991–96,368 q/s | 191–211 µs | 639–799 µs | 1.44–1.66 ms | 2.8 ms |

Flat out (`-T 4`), v0.5.0 answered 173,734 q/s and v0.4.0 123,469 q/s. No query was lost.

v0.5.0 is within v0.4.0's range or better in every column, so the sandbox and the new checks show
no regression. As in v0.4.0's run, neither version kept the p99 under a millisecond on this busy
host; the sub-millisecond target still needs a run on a quiet machine before it can be claimed.
