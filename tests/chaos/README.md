# Chaos tests

`chaos.sh` builds a two-node goethite cluster with a floating IP, and a client, in Linux network
namespaces on one bridge, then breaks things while the client queries the floating IP. The nodes
use goethite 0.4's `[cluster]` tables, so `a` (the primary) starts the cluster as its only voter
and leader, and `b` (the replica) follows it as a learner:

| Scenario | What breaks | What must hold |
| --- | --- | --- |
| `upgrade` | `SIGUSR2` on the node holding the floating IP, at 2000 queries/s | No query lost; the address stays |
| `kill-dns` | `SIGKILL` to the DNS server holding the floating IP, at 500 queries/s | The address moves to the replica within seconds; it answers and filters with its copy, and refuses changes until the primary is back |
| `kill-helper` | `SIGKILL` to the VRRP helper holding the floating IP | The replica takes the address; the helper removes its stale copy when it restarts |
| `partition` | The nodes cannot reach each other | Both answer; the replica refuses changes; once healed, one node holds the address and the replica copies what changed |
| `corrupt-list` | A filter list turns to garbage, then disappears, with a reload each time | No query lost; the list reports its invalid lines, then its error; restored, it filters again |

It needs root, `iproute2`, `nftables`, `dnsperf`, `dig` and `curl`. On Linux:

```sh
cargo build --release
sudo tests/chaos/chaos.sh target/release/goethite            # every scenario
sudo tests/chaos/chaos.sh target/release/goethite partition  # one
```

On macOS, build a Linux binary and run the script in a privileged container:

```sh
docker build --load -t goethite-chaos -f tests/chaos/Containerfile tests/chaos
docker run --rm --privileged -v "$PWD/tests/chaos:/chaos:ro" \
  -v /path/to/linux/goethite:/goethite:ro goethite-chaos /chaos/chaos.sh /goethite
```

It exits non-zero if a check fails, after printing the nodes' last log lines. The
[chaos workflow](../../.github/workflows/chaos.yaml) runs it weekly and on demand.
