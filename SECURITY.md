# Security policy

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for security problems.**

Report vulnerabilities privately through GitHub's private vulnerability reporting:

<https://github.com/nxplain-sh/goethite/security/advisories/new>

If that form is unavailable, open an issue that asks the maintainers for a private contact
and contains **no details** about the problem. We will reply with a private channel.

Please include:

- the affected component (crate, listener, CLI, website, CI workflow) and commit or version
- a description of the issue and its impact (for example: crash or panic, memory exhaustion, cache
  poisoning, filter bypass, privilege escalation, information disclosure)
- steps to reproduce, ideally a minimal packet capture, raw bytes or a config file
- any suggested fix or mitigation
- whether and how you would like to be credited

## What to expect

goethite is a pre-alpha project maintained by volunteers. Best effort applies:

- We aim to acknowledge reports within **7 days**.
- We will confirm the issue, agree on a fix and timeline with you, and keep you updated.
- We practice **coordinated disclosure**. Please give us a reasonable amount of time to release a
  fix before you publish details. We will publish a GitHub Security Advisory once a fix is
  available and credit you unless you prefer otherwise.
- There is no bug bounty.

## Fuzzing

Every parser has a fuzz target. Fuzzing runs on maintainers' machines before every release
(`cargo xtask fuzz`), never in this public repository's CI, where a crash it found would be
public before its fix; CI only checks that the targets build. If you fuzz goethite and find a
crash, report it privately as described above, without posting the input publicly.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.5.x | Yes: security fixes are released as 0.5.y |
| Before 0.5 | No: upgrade to 0.5 |

0.5.0 is the first release built and attested by the release workflow; earlier versions are tags
only. While goethite is pre-alpha, only the newest minor version gets fixes.

## Scope

In scope:

- code in this repository: all crates, the `goethite` binary, fuzz targets, the website in `site/`
- the build and CI configuration in `.github/` (for example, workflow injection or unpinned
  third-party actions)
- dependency issues that are exploitable through goethite

Out of scope:

- findings that require a compromised host or root access on the machine running goethite
- issues in third-party dependencies that goethite does not expose. Please report those upstream
  (we still appreciate a heads-up).
- denial of service by sheer traffic volume beyond the documented bounds

See the [threat model](docs/THREAT_MODEL.md) for what goethite defends against in each phase and
its explicit non-goals, and [`docs/security-review.md`](docs/security-review.md) for the brief of
the external security review of v0.5.0.
