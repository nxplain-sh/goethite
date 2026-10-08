# ADR 0016: Serving DNS over QUIC

- **Status:** Accepted
- **Date:** 2026-10-08

## Context

DNS over QUIC (RFC 9250) is the third encrypted transport for clients, beside DNS over TLS and
HTTPS ([ADR 0015](0015-encrypted-dns-serving.md)). The user approved `quinn` for it. QUIC differs
from TCP in two ways that matter here. There is no kernel handshake before goethite sees a
connection, so packets with spoofed source addresses reach it. And a QUIC endpoint is one UDP
socket that every connection shares, which both goethite processes read during an upgrade.

## Decision

**quinn 0.11 with rustls and ring, without default features** (no logging bridge, platform
verifier or token Bloom filter). It adds `quinn`, `quinn-proto`, `quinn-udp`, `lru-slab`,
`rustc-hash` and `rand_pcg`; `cargo deny` passes and no crate is duplicated.

**One endpoint, on one UDP socket, per `[server.tls] doq` address.** QUIC connections cannot be
spread over `SO_REUSEPORT` sockets by address and port without routing by connection ID.

**Addresses are validated before a connection takes a slot.** A client whose address is not
validated yet gets a Retry; only one that returns its token is accepted. This is QUIC's SYN
cookie: DoQ connections then count against the same limits as TCP, DoT and DoH
(`max_tcp_connections`, and per client), and spoofed packets cannot fill those slots. The cost is
one round trip on each new connection.

**The protocol, bounded.** ALPN `doq`, TLS 1.3 without 0-RTT (no replayed queries). One query per
bidirectional stream, read to its end: a 2-byte length that must match, a message of at most
65,535 bytes with ID 0, within the idle timeout. A client may have 64 streams open and no
unidirectional ones; the connection's receive window is 256 KiB and its send window 1 MiB; it
closes after 30 seconds without traffic. A stream that breaks the protocol (wrong length, nonzero
ID, not DNS) closes the connection with `DOQ_PROTOCOL_ERROR`, as RFC 9250 says. Answers come from
the same engine as every transport, with client IDs from the TLS server name and
`require_client_id` applied alike. Connection migration stays on, for phones that change networks.

**Upgrades.** The DoQ sockets are handed over like the others (`dns-doq-<n>`). While both
processes read a socket, each receives some of the other's packets. quinn makes connection IDs
with a random key per endpoint and ignores packets for IDs it did not make, so neither process
resets the other's connections; QUIC resends what the wrong process received. The old endpoint,
shutting down, ignores new connection attempts, so their clients resend and reach the new one,
finishes the queries in progress within the grace period, and closes its connections with
`DOQ_NO_ERROR`.

## Consequences

- The parsing without I/O, the stream framing, is in `goethite_server::doq`, fuzzed by
  `parse_doq`.
- Returning clients do not skip the Retry round trip: that needs address validation tokens
  (NEW_TOKEN), which quinn keeps in its `bloom` feature. Backlog.
- DoH over HTTP/3, which would share the QUIC stack, is not served yet. Backlog.
