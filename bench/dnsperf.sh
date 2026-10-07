#!/usr/bin/env bash
# Runs dnsperf against a running goethite: one warm-up pass to fill the cache,
# then a measured pass. Usage: bench/dnsperf.sh [server] [port] [seconds]
set -euo pipefail

server="${1:-127.0.0.1}"
port="${2:-15353}"
seconds="${3:-30}"
queries="$(dirname "$0")/queries.txt"

if ! command -v dnsperf >/dev/null; then
    echo "dnsperf is not installed (https://www.dns-oarc.net/tools/dnsperf)" >&2
    exit 1
fi

echo "warm-up: filling the cache from the upstreams"
dnsperf -s "$server" -p "$port" -d "$queries" -n 1 -q 10 >/dev/null

echo "measured: ${seconds}s of cached answers"
dnsperf -s "$server" -p "$port" -d "$queries" -l "$seconds" -c 4 -Q 50000 -S 5
