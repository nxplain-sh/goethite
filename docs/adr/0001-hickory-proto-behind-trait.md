# ADR 0001: Wrap hickory-proto behind our own trait and types

- **Status:** Accepted
- **Date:** 2026-10-06

## Context

goethite needs a DNS wire-format parser and encoder from day one. That code sits on the most
exposed attack surface (B1 in the [threat model](../THREAT_MODEL.md)) and on the hottest path.

[hickory-proto](https://crates.io/crates/hickory-proto) is the most complete and widely used Rust
DNS protocol crate. However:

- It is pre-1.0 and has broken its API across minor releases (record types, `Name`, EDNS and
  feature flags have all moved over time).
- Its `Message` model is general-purpose and allocates per message (vectors of records, owned
  names). That is fine for correctness, but it is not the zero-allocation hot path we eventually
  want.
- If its types leak into every crate (filter, resolver, server, API, store), any upgrade or
  replacement becomes a workspace-wide refactor.
- Validation policy for untrusted input (what to drop, what to answer with FORMERR or NOTIMP, which
  size limits apply) should live in exactly one place.

## Decision

`goethite-proto` owns a small set of public types and a codec trait. No hickory type appears in
its public API.

- Types:
  - `Name`: always valid on the wire, with case-insensitive equality and hashing. Its `Display`
    escapes unsafe bytes, so names from the wire cannot inject newlines into logs.
  - `RecordType`, `RecordClass`, `Opcode`, `ResponseCode`: transparent newtypes over the wire
    value, so unknown values round-trip.
  - `Query`: id, the RD, CD and AD flags, exactly one `Question`, and optional `Edns` (UDP payload
    size and the DO bit; versions other than 0 are rejected)
  - `Response`: built from a `Query`, carrying an rcode and answer `Record`s
- Trait `DnsCodec`:
  - `decode_query(&self, &[u8]) -> Result<Query, DecodeError>`
  - `encode_query(&self, &Query, &mut Vec<u8>) -> Result<(), EncodeError>`
  - `encode_response(&self, &Response, max_len, &mut Vec<u8>) -> Result<(), EncodeError>`, which
    sets TC and drops the answers when the encoded response would exceed `max_len`
- One implementation for now: `HickoryCodec`, built on hickory-proto 0.26 with default features off
  except `std`.
- Decode policy, defined in `goethite-proto` (`DecodeError::response` says whether to answer) and
  followed by the server:

  | Input                                                        | Result                                     |
  | ------------------------------------------------------------ | ------------------------------------------ |
  | Shorter than a header, or the question cannot be read        | `DecodeError`: dropped and logged at debug |
  | QR=1 (a response)                                            | Dropped, to prevent reflection and loops   |
  | opcode other than QUERY                                      | NOTIMP                                     |
  | QDCOUNT other than 1, any answer or authority records, or more than 2 additional records | FORMERR |
  | Readable question, unreadable additional section (two OPT records, malformed EDNS option, truncated OPT) | FORMERR (RFC 6891, RFC 7871) |
  | EDNS version other than 0                                    | BADVERS                                    |

  The header counts are checked before hickory parses anything. hickory pre-allocates vectors
  from the header counts, so without this check a 12-byte message claiming 65,535 questions makes
  it allocate megabytes before failing. Error replies are header-only (plus OPT for BADVERS), so
  they are never larger than the message that caused them.

- hickory-proto logs its own warnings about some malformed input (for example EDNS options with a
  wrong length), quoting the attacker's bytes. The binary turns `hickory_proto` logging off unless
  `RUST_LOG` names it. Error text that goethite does log is escaped to printable ASCII.

- Size limits: UDP queries are read into a 4096-byte buffer. Responses advertise an EDNS UDP size
  of 1232 and are fitted to the client's limit (512 bytes without EDNS).

The rest of the workspace depends only on `goethite-proto`'s types and the `DnsCodec` trait.

## Consequences

Positive:

- hickory API churn is isolated to one crate. Upgrades touch `HickoryCodec` and its conversions
  only.
- A future zero-copy, zero-allocation fast-path decoder can be added behind `DnsCodec` without
  touching callers. It must be justified by a criterion bench.
- Two implementations behind one trait enable differential fuzzing: the same bytes must decode to
  the same `Query` in both.
- Bounds and validation policy for untrusted input live in one place, which is also where the
  fuzz targets point.
- Our types expose only what goethite uses, which keeps the vocabulary small and the invariants
  checkable (for example, a `Query` always has exactly one question).

Negative:

- Conversions between hickory and goethite types cost allocations and CPU on every query until a
  fast path exists.
- A second type vocabulary to learn and maintain. Features hickory already models (new record
  types, EDNS options) must be mapped explicitly before callers can use them.
- The trait is a seam with a single implementation today. We accept that because of the planned
  fast path and differential fuzzing.

## Alternatives considered

- **Use hickory types everywhere.** Least code now, but couples every crate to a pre-1.0 API and
  scatters validation policy. Rejected.
- **Hand-written parser now.** Maximum control and performance, but a large, security-critical
  surface to write and fuzz before anything else works. Deferred: it can arrive later behind the
  trait, with benchmarks.
- **Other crates (`domain`, `simple-dns`).** `domain` (NLnet Labs) is high quality but has a
  different, larger model that we would also want to wrap. `simple-dns` is smaller and less
  complete for EDNS, DNSSEC and future recursion needs. Neither removes the reason for a wrapper,
  and hickory gives the broadest coverage for the later forwarding, DoH/DoT/DoQ and DNSSEC phases.
