# ADR 0015: Serving DNS over TLS and HTTPS, and client IDs

- **Status:** Accepted
- **Date:** 2026-10-08

## Context

Phase 4 adds encrypted listeners for clients: DNS over TLS (RFC 7858) and DNS over HTTPS (RFC
8484) first, DNS over QUIC next. They protect queries on networks goethite does not control, such
as a café's Wi-Fi, and let a phone keep its filtering away from home. Away from home a device
has no stable address, so the per-client policy, which knows clients by address, needs another
way to tell who is asking. AdGuard Home and NextDNS solve this with a client ID in the TLS
server name or the DoH path; the user approved the same.

The listeners face untrusted input like port 53 does, and more of it: TLS handshakes and HTTP/1.1
and HTTP/2 framing come before any DNS message.

## Decision

**Both listeners live in `goethite-server`, beside UDP and TCP, and share one engine.** A query
over any transport is decoded, resolved and encoded by the same code, observed the same way (the
query log records `dot` and `doh`), and limited the same way: TCP, DoT and DoH connections count
against one total (`max_tcp_connections`) and one per-client limit. DoT reuses the TCP framing
code over a TLS stream; its idle timeout is 30 seconds instead of TCP's 10, since encrypted
connections cost more to set up and clients keep them.

**DoH is hyper, not axum.** The data plane does not depend on the API's framework. One handler
answers `GET /dns-query?dns=` and `POST /dns-query` (and `/dns-query/<client ID>`), over HTTP/1.1
or HTTP/2 chosen by ALPN. Everything an HTTP peer controls is bounded: 64 KiB of request head, 10
seconds to send it, 64 concurrent HTTP/2 streams, bodies of at most 65,535 bytes that must arrive
within the idle timeout, and a connection with no request for 30 seconds is closed. Answers carry
`Cache-Control: max-age` of their shortest TTL. Errors are plain HTTP statuses with a short text
(404 for other paths, 405, 413, 415, 400 for anything that is not a DNS query). The parsing that
needs no I/O (path, `dns` parameter, base64url, server name) is in `goethite_server::doh`, fuzzed
by `parse_doh`.

**One certificate for both, from the config file, reloadable.** `[server.tls]` names a PEM chain
and key, read before privileges drop like the API's, and handed over on an upgrade. rustls (ring,
TLS 1.2 and 1.3, no 0-RTT) asks a certificate resolver at every handshake; the resolver holds the
certificate behind an `ArcSwap`, so `SIGHUP` reads renewed files and swaps them in without
dropping a connection. A file that does not hold a matching certificate and key leaves the one in
use. The API's certificate now works the same way. ALPN is `dot` for DoT and `h2`, `http/1.1` for
DoH.

**Client IDs are names, checked like DNS labels.** A client has up to 16 IDs of 1 to 63
lowercase letters, digits and hyphens, unique across clients. A query carries one in the DoH path
or, when `server_name` is configured, as the single label in front of it in the TLS server name
(`anna-phone.dns.example`); the path wins. A known ID identifies the client before its address
does; an unknown or absent one falls back to the address. Clients may now have IDs and no
address.

**Exposing the listeners is opt-in guarded.** `require_client_id = true` answers only DoT and DoH
queries that carry a known client ID, and refuses the rest with `REFUSED`; UDP and TCP are not
affected. It is the switch for listeners reachable from the internet, which would otherwise be an
open resolver. It is not strong authentication: an ID travels in the clear in the TLS server name
(until ECH), so DoH with the ID in the path keeps it private on the wire.

**The listeners are ordinary sockets for upgrades and restarts.** They are bound before
privileges drop, named `dns-dot-<n>` and `dns-doh-<n>`, handed to a new goethite on an upgrade and
kept by systemd across restarts, like the others ([ADR 0012](0012-zero-downtime-upgrades.md)).

## Consequences

- No new dependencies: rustls, tokio-rustls, hyper, hyper-util and http-body-util were already
  approved, for upstream TLS and the API.
- `/api/v1/status` reports the encrypted listeners and server name, so the web UI can show a
  device the exact DoH URL and DoT name for its client ID.
- DoT answers one query at a time per connection, like TCP; pipelining with out-of-order answers
  stays in the backlog.
- DoH behind a reverse proxy (plain HTTP from a trusted proxy, client address from a header) is
  not supported yet; it needs a trusted-proxy setting first.
- The certificate must cover `*.<server_name>` for client IDs in the server name; goethite does
  not check that, since it would need an X.509 parser.
