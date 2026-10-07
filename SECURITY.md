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

## Fuzzing in public CI

The weekly fuzz job runs in this public repository, so a crash it finds is visible in the
workflow logs and artifacts (kept for 7 days). While goethite is pre-alpha with no releases, we
accept that trade-off. Before the first release, fuzzing moves to a private setup. Crashes you
find yourself should still be reported privately as described above.

## Supported versions

None yet. goethite is pre-alpha and has no releases. Fixes land on `main`. This section will list
supported release lines once releases exist.

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
its explicit non-goals.
