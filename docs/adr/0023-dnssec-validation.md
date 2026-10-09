# ADR 0023: DNSSEC validation in the recursor

- **Status:** Accepted, extends ADR 0021
- **Date:** 2026-10-08

## Context

With recursion (ADR 0021), goethite believes authoritative servers only about their own zones,
and every query is hard to spoof. A server can still lie about its own zone, and anyone on the
path can still change an answer. DNSSEC (RFC 4033 to 4035, RFC 5155) lets a resolver check
both. The plan approved our own validator, using hickory-proto's `dnssec-ring` feature only for
the cryptography: verifying signatures, DS digests and NSEC3 hashes.

## Decision

**Validation is on with recursion,** and can be turned off with `[recursion] dnssec = false`.
A client that sets CD (checking disabled) gets answers unvalidated. Each answer is one of:

- **secure:** every RRset is signed and every signature checks, back to the root's trust anchor;
  the response gets the AD bit, for clients that set AD or DO (RFC 6840);
- **insecure:** it is in a part of the DNS its signed parent proves is unsigned; answered as
  before, without AD;
- **bogus:** it should be signed and is not, or the signatures or proofs do not check; answered
  with SERVFAIL and counted.

Clients that set DO get the RRSIGs, and for negative answers the NSEC or NSEC3 proofs, with
the answer. The cache keeps them, and the AD bit, for those clients.

**The trust anchors are built in:** the root zone's KSK-2017 (20326) and KSK-2024 (38696) as
DS records, from IANA's `root-anchors.xml`. Updates come with releases; RFC 5011 tracking is in
the backlog.

**The chain of trust is walked one label at a time,** from the closest name whose trust is
known down to the zone that signed an answer. Each signed zone is asked for its child's DS
records:

- signed DS records lead to the child's DNSKEY set, which one of them must match and sign;
- a signed NSEC or NSEC3 at the child showing NS without DS, or an NSEC3 opt-out span covering
  it, proves an unsigned delegation: everything below is insecure;
- a signed proof that the child has no DS and is no delegation keeps the walk in the same zone;
- anything else is bogus.

Only signed proofs move a name out of a signed zone. A forged or missing answer can make a
name bogus, never insecure. A signature that names its owner as the signer, hoping to be taken
for an unsigned zone of its own, finds the parent's signed proof that there is no zone there,
and the answer is bogus. Unsigned data walks to its own name the same way, and is insecure only
below a proven unsigned delegation. What each name was found to be is kept, bounded, in the
infrastructure tables:
- secure zones' keys, for at most the DNSKEY and DS TTLs and a day;
- unsigned delegations and names without a cut, for their proofs' TTL;
- bogus names, for a minute.

**Checks:**
- answers by RRset, with TTLs capped to the signature's (RFC 4035 5.3.3);
- wildcard answers, with proof that the name itself does not exist;
- unsigned CNAMEs, only when a signed DNAME synthesizes them;
- NXDOMAIN and NODATA, with NSEC (including empty non-terminals and wildcard NODATA) or NSEC3
  (closest encloser proofs, RFC 5155 8);
- signatures, valid at the current time with a tenth of their validity and at most an hour of
  slack for clocks.

**Supported algorithms:** RSA/SHA-256 (8), RSA/SHA-512 (10), ECDSA P-256 (13) and P-384 (14),
and Ed25519 (15). SHA-1 algorithms (5, 7) and others count as unsigned, as RFC 4035 5.2 asks
for algorithms a validator does not support. DS digests are SHA-1, SHA-256 or SHA-384, and
SHA-1 is ignored when SHA-256 is present (RFC 4509).

**Bounds against hostile zones:**
- at most 64 signature checks for one client query (KeyTrap, CVE-2023-50387);
- 4 keys tried per key tag;
- 8 signatures per RRset;
- 8 NSEC or NSEC3 records checked per answer;
- 128 DNSSEC records kept from a response;
- NSEC3 proofs with more than 150 iterations count as insecure without being hashed
  (RFC 9276), and at most 64 hashes are computed per proof.

Running out of checks is SERVFAIL, but is not remembered as bogus. The validation lookups (DS
and DNSKEY) share the client query's budget of 64 queries and 6 seconds.

**Proofs are pure functions** (`recurse::dnssec`) over records, tested with zones signed in
the tests (Ed25519), and fuzzed (`check_dnssec`) with real responses as seeds. The recursor
(`recurse::validate`) does the fetching and caching. A simulated signed internet tests:
- secure answers, wildcards and empty non-terminals;
- NSEC and NSEC3 denial;
- unsigned delegations under NSEC and NSEC3 parents;
- tampered, stripped and expired signatures;
- the forged-signer downgrade;
- a wrong trust anchor;
- CD.

## Verification

Against the internet, goethite agreed with Cloudflare's and Google's public resolvers on 58
names: secure, insecure and bogus answers (`dnssec-failed.org`, `sigfail.verteiltesysteme.net`),
NSEC, NSEC3 and compact denial, opt-out NXDOMAIN under `com` and `org` (insecure), DS and
DNSKEY questions, the root and top-level domains. One disagreement was Cloudflare's, and went
away on retry.

## Consequences

- A domain with broken DNSSEC fails with SERVFAIL, as on any validating resolver. Clients can
  set CD; negative trust anchors (RFC 7646) to exempt a domain are in the backlog.
- The first query into a signed zone costs a DS and a DNSKEY query per zone on the way; they
  are cached after that.
- Forwarding does not validate: an upstream's AD bit is not passed on. Validating forwarded
  answers is in the backlog.
- The built-in anchors need a release when the root KSK rolls.
