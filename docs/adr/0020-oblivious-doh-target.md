# ADR 0020: Oblivious DoH, as a target

- **Status:** Accepted
- **Date:** 2026-10-08

## Context

Oblivious DNS over HTTPS (RFC 9230) splits a resolver in two: a client encrypts its query to a
*target*'s public key and sends it through a *proxy*. The proxy sees who asks but not what, the
target sees what but not who. Phase 4 plans ODoH for goethite, and the approved dependency is the
`hpke` crate (RFC 9180, pure Rust). `ring`, which goethite already uses, cannot hold a static
X25519 private key, which a target needs.

## Decision

**goethite is a target.** With `[server.tls] odoh = true`, the DNS over HTTPS listeners also
answer `POST /dns-query` (and `/dns-query/<client ID>`) with an
`application/oblivious-dns-message` body, and serve the target's configuration at
`/.well-known/odohconfigs`. The decrypted query goes through the same pipeline as any other:
filtering, cache, upstreams, the query log (as `odoh`) and metrics. Answers are padded to a
multiple of 468 bytes (RFC 8467's block) and marked `no-cache, no-store`. A query for an unknown
key gets 401, so the client fetches the configuration again; anything else wrong gets 400. Being
a proxy, or sending goethite's own upstream queries over ODoH, is left for later.

**One suite.** DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-128-GCM, the suite RFC 9230
requires every implementation to support. `hpke` does the KEM, the query's HPKE context and its
exporter (features `x25519`, `aes`, `alloc`; no `getrandom`); `ring` does ODoH's own HKDF steps,
the response's AES-128-GCM and all randomness.

**Keys in memory, rotated daily.** A target key is made from the system's random number
generator at start, replaced every 24 hours as the RFC recommends, and the previous key is
accepted for another 24 hours, so a client that cached the configuration keeps working. Keys are
never written to disk: stealing a node's files, or its memory later, does not decrypt traffic
recorded earlier. The price is a 401 and one more round trip for a client after a restart, an
upgrade or a move of the floating IP to the other node, which RFC 9230 provides for. Each node of
a cluster has its own keys.

**Checked against an independent implementation.** Unit tests use Cloudflare's ODoH test vectors
(odoh-go, whose HPKE is circl): key derivation, key ID, configuration bytes, query decryption and
response encryption match byte for byte. Cloudflare's Go client was also run against the binary
over HTTP/2. The message parsers and decryption are fuzzed (`parse_odoh`).

## Consequences

- ODoH clients are filtered as their proxy's address is, unless they name themselves with a
  client ID in the target path, which tells the target who they are.
- All ODoH queries come from the proxy's addresses, so the per-client connection limit applies to
  the proxy; HTTP/2 lets a proxy send 64 queries at once on each connection.
- `hpke` adds RustCrypto's AES-GCM, HKDF, SHA-2 and curve25519-dalek to the build.
- Discovery through DNS (an `HTTPS` record with the configuration) is not done.
