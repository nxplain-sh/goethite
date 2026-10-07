# ADR 0003: Encrypted upstreams with rustls, ring and bundled roots

- **Status:** Accepted
- **Date:** 2026-10-07

## Context

Phase 1 adds DNS over TLS (RFC 7858) and DNS over HTTPS (RFC 8484) to the upstream resolvers, so
that queries leaving the network cannot be read or changed on the path (B2 in the
[threat model](../THREAT_MODEL.md)). That needs a TLS library, a source of trusted certificate
authorities, and an HTTP/2 client. goethite ships as a single binary for Linux amd64 and arm64,
including musl builds, and must behave the same on every host.

## Decision

- **TLS:** rustls 0.23 through tokio-rustls, TLS 1.2 and 1.3 only, with the **ring** crypto
  provider. Default features are off, so neither aws-lc nor the `log` crate is pulled in.
- **Trust roots:** the Mozilla root program compiled into the binary (webpki-roots), not the
  operating system's store. The library also accepts an explicit set of CA certificates
  (`TlsRoots::Custom`), which the tests use and a private CA could use later. It is not exposed in
  the config file yet.
- **Server identity:** DoT upstreams name the certificate's identity explicitly (`tls_name`); DoH
  upstreams use the host of their `url`. The upstream's IP address is always configured, so no
  bootstrap resolution is needed and the certificate check is the only identity check.
- **DoT:** RFC 7766 framing over TLS; up to four idle connections per upstream are reused, one
  query at a time. A reused connection the server has closed is retried once on a new one.
  No ALPN is sent, because some servers abort the handshake on unknown ALPN values.
- **DoH:** hyper 1 HTTP/2 client; queries are multiplexed over one connection per upstream. Only
  POST with `application/dns-message`, ID 0 (RFC 8484 4.1), status 200, the right content type
  and a 64 KiB body limit are accepted. ALPN `h2` is required.

## Consequences

Positive:

- ring needs no cmake or C toolchain beyond what `cc` handles, so cross-compiling to arm64 and
  musl stays simple.
- Every installation trusts exactly the same CAs, and an outdated host CA bundle cannot weaken it.
  Root updates arrive by bumping webpki-roots, which cargo-deny and cargo-audit watch.
- Connection reuse keeps the TLS handshake off the path of most queries.

Negative:

- A host's own CA additions (e.g. a corporate TLS-inspecting proxy) are ignored. Such
  environments need `TlsRoots::Custom` exposed in the config, which is not done yet.
- Root certificate updates need a goethite release.
- No FIPS-validated crypto, which aws-lc-rs would offer.
- The TLS stack adds the ISC, BSD-3-Clause and CDLA-Permissive-2.0 (root data only) licenses to
  `deny.toml`.

## Alternatives considered

- **aws-lc-rs** (rustls's default provider): FIPS path and fast, but it needs cmake and a C/C++
  toolchain at build time and complicates arm64/musl cross builds. Rejected for now.
- **The OS trust store** (rustls-platform-verifier or rustls-native-certs): honours admin-installed
  CAs, but behaviour differs between distributions and the appliance would depend on a maintained
  CA bundle. Rejected; may return as an opt-in.
- **reqwest** for DoH: convenient, but a much larger dependency tree for one POST request.
- **One new TLS connection per query:** simplest, but a full handshake per query adds latency
  and load on the upstream.
