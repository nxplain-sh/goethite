# ADR 0013: A floating IP with VRRP, in a helper process

- **Status:** Accepted
- **Date:** 2026-10-08

## Context

Phase 3 asks for a floating IP: one DNS address for clients, held by whichever node of a pair is
healthy. Clients and DHCP servers often take one DNS server, or try the first of two for seconds
before the second. A floating IP makes a failed node a pause of a few seconds instead of an
outage.

Moving an address between hosts on a LAN takes three things:

- an election between the nodes;
- adding and removing the address on an interface (`CAP_NET_ADMIN`);
- telling switches and hosts where the address went, with gratuitous ARP (`CAP_NET_RAW`).

The DNS server runs with no capabilities at all once its sockets are bound (ADR 0005), and that
should not change for a feature many installations will not use.

## Decision

**VRRP version 3 (RFC 5798)** elects the holder. It is the standard for exactly this job, so
packet captures, switches and network staff understand it, and keepalived interoperates: a
goethite node and a keepalived node elect each other correctly (tested both ways). goethite adds
one state to the RFC's: a node whose DNS server fails its health checks is in *fault*. It neither
advertises nor holds the address, and it starts there, so a node holds the address only once its
DNS server has answered.

**A helper process, `goethite vrrp`,** runs it, from the same binary, under its own systemd unit
(`goethite-vrrp.service`):

- it opens its raw VRRP sockets, its packet socket for ARP and its netlink socket, then keeps
  only `CAP_NET_ADMIN`, which every address change needs;
- it checks its own node once a second with a DNS query for `health.goethite.test`, answered
  locally and kept out of the query log. Three failures in a row hand the address over, and two
  successes make the node a candidate again;
- the DNS server binds the floating IP with `IP_FREEBIND`, so both nodes listen on it all the
  time and answer the moment it arrives;
- stopping the helper, or the DNS server (the unit is `PartOf=goethite.service`), hands the
  address over at once with a priority-0 advertisement. A helper that starts removes the address
  if an earlier run left it behind.

**Advertisements are checked beyond the RFC.** VRRP version 3 has no authentication. goethite
accepts an advertisement only from the configured peer, with a TTL of 255 (from the same link),
for the configured router ID and address. `unicast = true` sends advertisements straight to the
peer, for networks that drop multicast.

**No netlink crate.** The three netlink messages goethite needs are built and parsed by hand in
about 200 lines, and fuzzed (`parse_netlink`), like the VRRP parser (`parse_vrrp`). Sending ARP
needs a link-layer address (`struct sockaddr_ll`). rustix has no type for one, and handing one to
the kernel takes an `unsafe impl` of rustix's `SocketAddrArg` for a `#[repr(C)]` copy of the
struct. That is the one `unsafe` in `goethite-cluster`, with a `SAFETY` comment and a
compile-time size check.

## Consequences

- Measured on Linux network namespaces with the default 1 s interval, the address moves:
  - 0.7 s after the holder's helper is stopped;
  - 3.1 s after the holder's DNS server dies;
  - 3.6 s after the holder falls silent (the RFC's master-down interval).
- Clients keep one address through failures, upgrades and maintenance.
- A host on the same network segment can forge advertisements and take the address, as it could
  forge ARP without VRRP. The threat model and the HA guide say so: run the floating IP on a
  network you trust. Advertisements from other hosts or networks are ignored.
- IPv4 only for now. An IPv6 floating IP (VRRPv3 over IPv6, with unsolicited neighbor
  advertisements) is in the backlog.
- The helper is Linux only, like production.

## Alternatives considered

- **keepalived beside goethite.** It works, and goethite interoperates with it, but it is another
  daemon to install, configure and secure, with health checks written as shell scripts.
- **VRRP inside the DNS server.** One process fewer, but the DNS server would keep
  `CAP_NET_ADMIN` for its whole life.
- **A netlink crate (`rtnetlink`, `neli`).** More code than the three messages needed, and more
  dependencies for `cargo-deny` to watch.
- **Our own election over the cluster's TLS channel.** Authenticated, but unknown to every network
  tool, and it fails exactly when the cluster network does, which is when it matters.
