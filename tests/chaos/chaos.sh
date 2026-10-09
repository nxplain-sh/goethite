#!/usr/bin/env bash
# Chaos tests: a goethite cluster of two nodes, with a floating IP, and a
# witness, and a client, in network namespaces on one bridge. Each scenario
# breaks something while the client queries the floating IP, and checks
# that goethite recovers.
#
#   sudo tests/chaos/chaos.sh path/to/goethite [scenario ...]
#
# Scenarios: baseline, upgrade, kill-dns, kill-helper, partition,
# isolate-leader, kill-witness, corrupt-list (all by default). Needs root, iproute2, nftables, dnsperf, dig and curl; on macOS,
# run it in the container from tests/chaos/Containerfile (see README.md).
# The namespaces and the bridge are removed on exit; the logs stay in
# /tmp/goethite-chaos.

# pass, fail and note always return 0, so `check && pass ... || fail ...`
# is an if-then-else here.
# shellcheck disable=SC2015

set -uo pipefail

BIN=$(realpath "${1:?usage: chaos.sh path/to/goethite [scenario ...]}")
shift
SCENARIOS=("$@")
[ ${#SCENARIOS[@]} -eq 0 ] && SCENARIOS=(baseline upgrade kill-dns kill-helper partition isolate-leader kill-witness corrupt-list)

W=/tmp/goethite-chaos
VIP=10.53.0.53
NET=10.53.0
declare -A ADDRESS=([a]=$NET.11 [b]=$NET.12 [w]=$NET.13 [c]=$NET.100)
declare -A PEER=([a]=b [b]=a)
declare -A NODE=([a]=dns1 [b]=dns2 [w]=witness)
declare -A NAMESPACE=([dns1]=a [dns2]=b [witness]=w)
declare -A PRIORITY=([a]=150 [b]=100)
FAILED=0

# --- Output ------------------------------------------------------------------

step() { printf '\n== %s\n' "$*"; }
note() { printf '   %s\n' "$*"; }
pass() { printf '   ok: %s\n' "$*"; }
fail() { printf '   FAIL: %s\n' "$*"; FAILED=$((FAILED + 1)); }
expect() { # actual expected what
  if [ "$1" = "$2" ]; then pass "$3 ($1)"; else fail "$3: got '$1', expected '$2'"; fi
}
elapsed_ms() { echo $(( ($(date +%s%N) - $1) / 1000000 )); }

# --- The lab -----------------------------------------------------------------

cleanup() {
  for n in a b w c; do
    ip netns pids $n 2>/dev/null | xargs -r kill -9 2>/dev/null
    ip netns del $n 2>/dev/null
  done
  ip link del chaos-br 2>/dev/null
}

# The [cluster] table of the member in namespace $1: a starts the
# cluster, and every member lists the other two.
cluster_table() {
  printf '[cluster]\nnode = "%s"\nlisten = "%s:8054"\nca = "%s"\ncert = "%s"\nkey = "%s"\n' \
    "${NODE[$1]}" "${ADDRESS[$1]}" "$W/certs/ca.crt" "$W/certs/${NODE[$1]}.crt" "$W/certs/${NODE[$1]}.key"
  [ "$1" = a ] && printf 'bootstrap = true\n'
  for m in a b w; do
    [ "$m" = "$1" ] && continue
    printf '\n[[cluster.member]]\nnode = "%s"\naddress = "%s:8054"\n' "${NODE[$m]}" "${ADDRESS[$m]}"
  done
}

lab() {
  cleanup
  rm -rf $W && mkdir -p $W/lists $W/certs
  ip link add chaos-br type bridge && ip link set chaos-br up
  for n in a b w c; do
    ip netns add $n
    ip link add chaos-$n type veth peer name eth0 netns $n
    ip link set chaos-$n master chaos-br up
    ip -n $n link set lo up
    ip -n $n link set eth0 up
    ip -n $n addr add "${ADDRESS[$n]}/24" dev eth0
  done
  printf '||blocked.chaos.test^\n' > $W/lists/chaos.txt
  for command in init "cert dns1" "cert dns2" "cert witness"; do
    # shellcheck disable=SC2086
    "$BIN" cluster $command --dir $W/certs > /dev/null || { echo "cannot create certificates"; exit 1; }
  done
  for n in a b; do
    mkdir -p $W/$n
    cat > $W/$n/goethite.toml <<EOF
[server]
listen = ["$VIP:53", "${ADDRESS[$n]}:53", "127.0.0.1:53"]

[server.rate_limit]
# The one client stands in for a whole network.
queries_per_second = 0

[[upstream]]
# Unreachable: the scenarios ask only for names goethite answers itself.
address = "192.0.2.1"

[filter]
local_lists_dir = "$W/lists"
[[filter.list]]
path = "$W/lists/chaos.txt"

[api]
listen = "127.0.0.1:8053"

$(cluster_table $n)

[vrrp]
interface = "eth0"
address = "$VIP"
peer = "${ADDRESS[${PEER[$n]}]}"
router_id = 53
priority = ${PRIORITY[$n]}
EOF
  done
  mkdir -p $W/w
  cat > $W/w/goethite.toml <<EOF
[store]
path = "$W/w/goethite.redb"

$(cluster_table w)
EOF
  # The client's queries: names goethite answers itself, and a blocked one.
  printf 'goethite.test A\nblocked.chaos.test A\n' > $W/queries.txt
}

start_dns() {
  ip netns exec "$1" "$BIN" run -c "$W/$1/goethite.toml" >> "$W/$1/run.log" 2>&1 &
  echo $! > "$W/$1/run.pid"
}
start_helper() {
  ip netns exec "$1" "$BIN" vrrp -c "$W/$1/goethite.toml" >> "$W/$1/vrrp.log" 2>&1 &
  echo $! > "$W/$1/vrrp.pid"
}
start_witness() {
  ip netns exec w "$BIN" witness -c "$W/w/goethite.toml" >> "$W/w/witness.log" 2>&1 &
  echo $! > "$W/w/witness.pid"
}
# The DNS server's process: after an upgrade, no longer the one started.
dns_pid() { ip netns pids "$1" | while read -r pid; do
  tr '\0' ' ' < /proc/"$pid"/cmdline 2>/dev/null | grep -q ' run ' && echo "$pid"; done | head -1; }
stop_all() {
  for n in a b; do
    [ -f $W/$n/vrrp.pid ] && kill "$(cat $W/$n/vrrp.pid)" 2>/dev/null
  done
  sleep 1
  for n in a b; do pid=$(dns_pid $n); [ -n "$pid" ] && kill "$pid" 2>/dev/null; done
  [ -f $W/w/witness.pid ] && kill "$(cat $W/w/witness.pid)" 2>/dev/null
  sleep 1
}

holds() { ip -n "$1" -4 addr show dev eth0 | grep -q "inet $VIP/32"; }
holder() { local h=""; for n in a b; do holds $n && h=$h$n; done; echo "${h:-none}"; }
wait_holder() { # expected seconds
  local start; start=$(date +%s%N)
  for _ in $(seq 1 $(($2 * 10))); do
    if [ "$(holder)" = "$1" ]; then note "holder: $1 after $(elapsed_ms "$start") ms"; return 0; fi
    sleep 0.1
  done
  fail "holder: $(holder) after $2 s, expected $1"; return 1
}
ask() { ip netns exec c dig +short +tries=1 +time=1 "@$1" "$2" 2>&1 | head -1; }
api() { # node method path [body]
  ip netns exec "$1" curl -s -o /dev/stderr -w '%{http_code}' -X "$2" \
    -H 'Content-Type: application/json' ${4:+--data "$4"} "http://127.0.0.1:8053$3" 2>/dev/null
}
api_body() { ip netns exec "$1" curl -s "http://127.0.0.1:8053$2"; }
# The cluster's leader as node $1 sees it (dns1, dns2), and its namespace.
leader() { api_body "$1" /api/v1/cluster | sed -n 's/.*"leader":"\([^"]*\)".*/\1/p'; }
leader_ns() { local l; l=$(leader "$1"); echo "${NAMESPACE[$l]:-}"; }
voters() { api_body "$1" /api/v1/cluster | grep -o '"membership":"voter"' | wc -l; }
writable() { api_body "$1" /api/v1/cluster | grep -q '"writable":true'; }
# Cuts namespace $1 off from the cluster addresses $2... (and VRRP).
cut_off() {
  local n=$1; shift
  ip netns exec "$n" nft -f - <<EOF
table inet chaos {
  chain input { type filter hook input priority 0; $(for addr in "$@"; do printf 'ip saddr %s drop; ' "$addr"; done) }
  chain output { type filter hook output priority 0; $(for addr in "$@"; do printf 'ip daddr %s drop; ' "$addr"; done) ip daddr 224.0.0.18 drop; }
}
EOF
}
heal() { for n in "$@"; do ip netns exec "$n" nft delete table inet chaos 2>/dev/null; done; }

# Waits until both nodes answer, the floating IP is on a, and the cluster
# has three voters and takes changes through either node.
healthy_cluster() {
  for n in a b; do
    for _ in $(seq 1 100); do
      [ "$(ask "${ADDRESS[$n]}" goethite.test)" = "127.0.0.53" ] && break
      sleep 0.1
    done
  done
  wait_holder a 15 || return 1
  for _ in $(seq 1 150); do
    [ "$(voters a)" -eq 3 ] && writable a && writable b && return 0
    sleep 0.2
  done
  fail "the cluster did not come together: $(api_body a /api/v1/cluster | head -c 600)"
}

# Runs dnsperf from the client against the floating IP in the background:
# load <name> <queries per second> <seconds>.
load() {
  ip netns exec c dnsperf -s $VIP -d $W/queries.txt -Q "$2" -l "$3" -t 1 -c 4 \
    > "$W/$1.dnsperf" 2>&1 &
  echo $! > "$W/$1.load"
}
# Waits for the load to finish (in this shell: dnsperf is its child), and
# sets COMPLETED and LOST.
finish_load() {
  wait "$(cat "$W/$1.load")" 2>/dev/null
  COMPLETED=$(awk '/Queries completed:/ {print $3}' "$W/$1.dnsperf")
  LOST=$(awk '/Queries lost:/ {print $3}' "$W/$1.dnsperf")
  COMPLETED=${COMPLETED:-0} LOST=${LOST:-?}
  note "dnsperf: $COMPLETED completed, $LOST lost"
}
# Retries an API call until it gets the expected status:
# eventually <seconds> <status> <node> <method> <path> [body]
eventually() {
  local seconds=$1 status=$2 got=""; shift 2
  for _ in $(seq 1 $((seconds * 5))); do
    got=$(api "$@" 2> /dev/null)
    [ "$got" = "$status" ] && break
    sleep 0.2
  done
  echo "$got"
}

# --- Scenarios ----------------------------------------------------------------

# Load with nothing broken: the control for the scenarios that count
# losses.
baseline() {
  step "baseline: nothing breaks, at 2000 queries/s"
  load baseline 2000 6
  finish_load baseline
  expect "$LOST" 0 "queries lost"
}

# Upgrading the node that holds the floating IP, under load: no query lost.
upgrade() {
  step "upgrade: SIGUSR2 on the node holding the floating IP, at 2000 queries/s"
  load upgrade 2000 8
  sleep 3
  local before; before=$(dns_pid a)
  kill -USR2 "$before"
  for _ in $(seq 1 100); do
    grep -q "answering in place of the previous goethite" $W/a/run.log && break
    sleep 0.1
  done
  finish_load upgrade
  expect "$LOST" 0 "queries lost during the upgrade"
  [ "$(dns_pid a)" != "$before" ] && pass "a new process answers" || fail "no new process"
  expect "$(holder)" a "the floating IP stayed"
}

# The DNS server on the holder dies: the floating IP moves to the replica,
# which keeps answering with its copy and refuses changes.
kill_dns() {
  step "kill-dns: SIGKILL the DNS server holding the floating IP, at 500 queries/s"
  load kill-dns 500 12
  sleep 2
  local start led; start=$(date +%s%N)
  led=$(leader_ns b)
  kill -9 "$(dns_pid a)"
  wait_holder b 10
  note "moved $(elapsed_ms "$start") ms after the kill"
  if [ "$led" = a ]; then
    for _ in $(seq 1 200); do
      [ "$(leader_ns b)" = b ] && break
      sleep 0.1
    done
    note "b took the lead $(elapsed_ms "$start") ms after the kill"
  fi
  finish_load kill-dns
  [ "$LOST" != "?" ] && [ "$LOST" -lt 2500 ] && pass "fewer than 5 s of queries lost" \
    || fail "$LOST queries lost"
  expect "$(ask $VIP goethite.test)" 127.0.0.53 "the floating IP answers"
  expect "$(ask $VIP blocked.chaos.test)" 0.0.0.0 "b still filters"
  expect "$(eventually 20 201 b POST /api/v1/rules '{"rule":"||during-outage.test^"}')" 201 \
    "changes through b go on: it leads with the witness's vote, if a did"

  step "kill-dns: a comes back"
  start_dns a
  wait_holder a 15
  expect "$(eventually 20 201 a POST /api/v1/rules '{"rule":"||after-outage.test^"}')" 201 \
    "changes through a work again"
  for _ in $(seq 1 100); do
    [ "$(ask "${ADDRESS[a]}" during-outage.test)" = "0.0.0.0" ] && break
    sleep 0.1
  done
  expect "$(ask "${ADDRESS[a]}" during-outage.test)" 0.0.0.0 \
    "a caught up with the change made while it was down"
}

# The helper on the holder dies without handing over: the replica takes
# the floating IP, and the helper removes its stale copy when it restarts.
kill_helper() {
  step "kill-helper: SIGKILL the VRRP helper holding the floating IP"
  local start; start=$(date +%s%N)
  kill -9 "$(cat $W/a/vrrp.pid)"
  for _ in $(seq 1 100); do holds b && break; sleep 0.1; done
  holds b && note "b holds it after $(elapsed_ms "$start") ms" || fail "b did not take over"
  expect "$(holder)" ab "a's stale copy stays until its helper restarts"
  expect "$(ask $VIP goethite.test)" 127.0.0.53 "the floating IP answers"
  start_helper a
  wait_holder a 15
  grep -q "earlier run left behind" $W/a/vrrp.log && pass "a removed its stale copy" \
    || fail "a did not report removing its stale copy"
}

# The nodes cannot reach each other, but both reach the witness: both
# answer and both hold the floating IP; the leader's side takes changes and
# the other refuses them. Once healed, one holder, and the other node has
# what changed meanwhile.
partition() {
  local l f
  l=$(leader_ns a)
  [ -z "$l" ] && { fail "no leader before the partition"; return; }
  f=$([ "$l" = a ] && echo b || echo a)
  step "partition: a and b cannot reach each other ($l leads; both reach the witness)"
  cut_off a "${ADDRESS[b]}"
  cut_off b "${ADDRESS[a]}"
  wait_holder ab 10
  expect "$(ask "${ADDRESS[a]}" goethite.test)" 127.0.0.53 "a answers"
  expect "$(ask "${ADDRESS[b]}" goethite.test)" 127.0.0.53 "b answers"
  expect "$(eventually 15 201 "$l" POST /api/v1/rules '{"rule":"||during-partition.test^"}')" 201 \
    "the leader, $l, takes changes"
  expect "$(eventually 15 503 "$f" POST /api/v1/rules '{"rule":"||refused.test^"}')" 503 \
    "$f, cut off from it, refuses them"
  expect "$(leader_ns "$l")" "$l" "$l keeps the lead"
  api_body "$f" /api/v1/cluster | grep -q '"role":"[a-z]*","state":"leader"' \
    && fail "$f took the lead too" || pass "$f does not take the lead: the witness refuses it"

  step "partition: healed"
  heal a b
  wait_holder a 10
  local start; start=$(date +%s%N)
  for _ in $(seq 1 400); do
    [ "$(ask "${ADDRESS[$f]}" during-partition.test)" = "0.0.0.0" ] && break
    sleep 0.1
  done
  expect "$(ask "${ADDRESS[$f]}" during-partition.test)" 0.0.0.0 \
    "$f has the change made during the partition"
  note "caught up $(elapsed_ms "$start") ms after healing"
}

# The leader is cut off from both other members: they elect a new leader
# and take changes. Once healed, the old leader follows the new one.
isolate_leader() {
  local l f
  l=$(leader_ns a)
  [ -z "$l" ] && { fail "no leader to isolate"; return; }
  f=$([ "$l" = a ] && echo b || echo a)
  step "isolate-leader: ${NODE[$l]} cannot reach $f or the witness"
  cut_off "$l" "${ADDRESS[$f]}" "${ADDRESS[w]}"
  cut_off w "${ADDRESS[$l]}"
  local start; start=$(date +%s%N)
  for _ in $(seq 1 200); do
    [ "$(leader_ns "$f")" = "$f" ] && break
    sleep 0.1
  done
  expect "$(leader_ns "$f")" "$f" "$f leads with the witness's vote"
  note "elected $(elapsed_ms "$start") ms after the cut"
  expect "$(eventually 15 201 "$f" POST /api/v1/rules '{"rule":"||new-leader.test^"}')" 201 \
    "changes through $f go on"
  expect "$(ask "${ADDRESS[$l]}" goethite.test)" 127.0.0.53 "the old leader still answers DNS"

  step "isolate-leader: healed"
  heal "$l" w
  for _ in $(seq 1 200); do
    [ "$(leader_ns "$l")" = "$f" ] && break
    sleep 0.1
  done
  expect "$(leader_ns "$l")" "$f" "the old leader follows $f"
  for _ in $(seq 1 100); do
    [ "$(ask "${ADDRESS[$l]}" new-leader.test)" = "0.0.0.0" ] && break
    sleep 0.1
  done
  expect "$(ask "${ADDRESS[$l]}" new-leader.test)" 0.0.0.0 "and has the change it missed"
}

# The witness stops: two voters of three remain, and changes go on. It
# catches up when it is back.
kill_witness() {
  step "kill-witness: SIGKILL the witness"
  kill -9 "$(cat $W/w/witness.pid)"
  expect "$(eventually 15 201 a POST /api/v1/rules '{"rule":"||no-witness.test^"}')" 201 \
    "changes through a go on"
  expect "$(eventually 15 201 b POST /api/v1/rules '{"rule":"||no-witness-b.test^"}')" 201 \
    "and through b"

  step "kill-witness: back"
  start_witness
  for _ in $(seq 1 150); do
    api_body a /api/v1/cluster | grep -q '"node":"witness"[^}]*"reachable":true' && break
    sleep 0.2
  done
  api_body a /api/v1/cluster | grep -q '"node":"witness"[^}]*"reachable":true' \
    && pass "the witness is back" || fail "the witness did not come back"
  # Its configuration version, as a last saw it, matches a's own.
  local want got=""
  want=$(api_body a /api/v1/cluster | grep -o '"config":{[^}]*}' | head -1)
  for _ in $(seq 1 100); do
    got=$(api_body a /api/v1/cluster | grep -o '"node":"witness"[^}]*}' | grep -o '"config":{[^}]*}')
    [ "$got" = "$want" ] && break
    sleep 0.2
  done
  expect "$got" "$want" "it caught up"
}

# A list file turns to garbage, then disappears: goethite keeps answering
# through reloads and says what is wrong; restored, it filters again.
corrupt_list() {
  step "corrupt-list: the list file turns to garbage, at 500 queries/s"
  cp $W/lists/chaos.txt $W/lists/chaos.good
  head -c 65536 /dev/urandom > $W/lists/chaos.txt
  load corrupt 500 6
  for n in a b; do kill -HUP "$(dns_pid $n)"; done
  finish_load corrupt
  expect "$LOST" 0 "queries lost while reloading"
  expect "$(ask $VIP goethite.test)" 127.0.0.53 "still answering"
  local lists
  lists=$(api_body a /api/v1/status)
  echo "$lists" | grep -q '"invalid":[1-9]' && pass "the list reports its invalid lines" \
    || fail "the list reports no invalid lines"

  step "corrupt-list: the list file disappears"
  rm $W/lists/chaos.txt
  for n in a b; do kill -HUP "$(dns_pid $n)"; done
  sleep 2
  expect "$(ask $VIP goethite.test)" 127.0.0.53 "still answering"
  lists=$(api_body a /api/v1/status)
  echo "$lists" | grep -q '"error":"' && pass "the list reports its error" \
    || fail "no error reported for the list"

  step "corrupt-list: restored"
  mv $W/lists/chaos.good $W/lists/chaos.txt
  for n in a b; do kill -HUP "$(dns_pid $n)"; done
  for _ in $(seq 1 50); do
    [ "$(ask $VIP blocked.chaos.test)" = "0.0.0.0" ] && break
    sleep 0.1
  done
  expect "$(ask $VIP blocked.chaos.test)" 0.0.0.0 "filtering again"
}

# --- Main ---------------------------------------------------------------------

trap cleanup EXIT
lab
step "start: two nodes, a (priority 150, starts the cluster) and b (100), and a witness"
for n in a b; do start_dns $n; done
start_witness
for n in a b; do start_helper $n; done
healthy_cluster || { tail -n 20 $W/a/run.log $W/b/run.log $W/w/witness.log; exit 1; }
expect "$(ask $VIP goethite.test)" 127.0.0.53 "the floating IP answers"
expect "$(ask $VIP blocked.chaos.test)" 0.0.0.0 "and filters"
sleep 1 # The query log writes in batches.
names=$(api_body a "/api/v1/querylog?limit=1000" | grep -o '"name":"[^"]*"' | sort | uniq -c)
note "query log names on a: $(tr -s ' \n' '  ' <<< "$names")"
echo "$names" | grep -q '"goethite.test' && pass "the client's queries are in the query log" \
  || fail "the client's queries are not in the query log"
echo "$names" | grep -q 'health.goethite.test' && fail "health checks are in the query log" \
  || pass "health checks stay out of it"

for scenario in "${SCENARIOS[@]}"; do
  case $scenario in
    baseline) baseline ;;
    upgrade) upgrade ;;
    kill-dns) kill_dns ;;
    kill-helper) kill_helper ;;
    partition) partition ;;
    isolate-leader) isolate_leader ;;
    kill-witness) kill_witness ;;
    corrupt-list) corrupt_list ;;
    *) fail "unknown scenario $scenario" ;;
  esac
  healthy_cluster > /dev/null || fail "the cluster did not recover after $scenario"
done

stop_all
step "done: $FAILED failed"
if [ $FAILED -gt 0 ]; then
  for f in $W/a/run.log $W/a/vrrp.log $W/b/run.log $W/b/vrrp.log $W/w/witness.log; do
    printf '\n--- %s (last 30 lines)\n' "$f"
    tail -n 30 "$f"
  done
  exit 1
fi
