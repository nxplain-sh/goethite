# Chaos tests

`chaos.sh` builds a goethite cluster in Linux network namespaces on one bridge: two nodes, `a`
(dns1, which starts the cluster) and `b` (dns2), sharing a floating IP, a witness `w`, and a
client. It then breaks things while the client queries the floating IP:

| Scenario | What breaks | What must hold |
| --- | --- | --- |
| `baseline` | Nothing, at 2000 queries/s | No query lost |
| `upgrade` | `SIGUSR2` on the node holding the floating IP, at 2000 queries/s | No query lost; the address stays |
| `kill-dns` | `SIGKILL` to the DNS server holding the floating IP, at 500 queries/s | The address moves to `b` within seconds; it answers and filters, and takes changes, leading with the witness's vote if `a` led. Back, `a` catches up |
| `kill-helper` | `SIGKILL` to the VRRP helper holding the floating IP | `b` takes the address; the helper removes its stale copy when it restarts |
| `partition` | `a` and `b` cannot reach each other; both reach the witness | Both answer and both hold the address; the leader's side takes changes, the other refuses them and cannot take the lead; once healed, one holder, and the other node has what changed |
| `isolate-leader` | The leader cannot reach the other two members | They elect a new leader and take changes; the old leader keeps answering DNS, then follows the new one and catches up |
| `kill-witness` | `SIGKILL` to the witness | Changes go on through either node; back, the witness catches up |
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
