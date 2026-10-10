# ADR 0038: Check for updates on demand, from the node

- **Status:** Accepted
- **Date:** 2026-10-10

## Context

goethite upgrades without dropping queries ([ADR 0012](0012-zero-downtime-upgrades.md)), but
nothing tells an operator that a new release exists. A release is a GitHub tag, inherited by the
container image, the packages and the tarball ([ADR 0026](0026-release-builds.md),
[ADR 0027](0027-packages-and-container-image.md)); the package managers know about packages they
installed, and nothing knows about a binary put in place by hand.

Constraints:

- **The control plane is unprivileged.** It cannot replace `/usr/bin/goethite`, and the upgrade
  handover belongs to the operator's step (SIGUSR2, or the package postinstall).
- **Nothing is sent on its own.** Telemetry only exists once `[telemetry] endpoint` is set
  ([ADR 0034](0034-opentelemetry.md)); a version check that phones GitHub at startup would break
  that stance.
- **A node knows its own version**, reported in `GET /api/v1/status` and shown in the TUI and the
  web UI's Cluster page.

## Decision

**The node checks the project's releases when the admin asks, and only then.** A new endpoint,
`POST /api/v1/update/check`, fetches
`https://api.github.com/repos/nxplain-sh/goethite/releases/latest` through goethite's own
downloader: names resolved through its own upstreams, TLS verified against the bundled roots,
answer bounded at 256 KiB and fifteen seconds. The reply is the running version, the newest
release's version (the tag without its `v`), its page, when it was published, and whether it is
newer by `X.Y.Z` number. A release whose tag is not `X.Y.Z`, an HTTP error, a network failure or a
timeout is a 503 with the reason; nothing is guessed.

It installs nothing, writes nothing and is not audited: it is a read of GitHub, not a change. The
web UI's Settings page shows the running version and a **Check for updates** button over it; no
background polling, no check on page load. A witness does not answer the endpoint.

## Alternatives considered

- **A background check on a schedule.** Phones GitHub without anyone asking (privacy, and GitHub
  rate-limits unauthenticated callers to 60 requests an hour per source address), duplicates work
  across a cluster, and adds a task to the control plane for a convenience.
- **Installing from the API.** The API runs unprivileged inside the sandbox: it cannot write the
  binary's path, and the handover's failure handling is designed around an operator watching
  ([ADR 0012](0012-zero-downtime-upgrades.md)). A failed auto-upgrade with no one around is worse
  than no button.
- **Checking from the browser.** The web UI's CSP is strict, GitHub's API does not allow
  cross-origin reads, and the check would leak the viewer's browser to GitHub while API clients
  (TUI, scripts) get nothing.
- **Parsing `releases/latest` as HTML or the Atom feed.** The JSON API is stable and the existing
  downloader already sends a `User-Agent` (GitHub rejects requests without one) and bounds every
  answer; the feed would need its own parser for no gain.
- **A version endpoint on nxplain.sh.** One more service to run for a check that GitHub already
  answers; revisit if GitHub becomes the wrong place to ask.

## Consequences

- One small module in the binary (`update.rs`) and one typed endpoint; no new dependencies.
- Each click sends one request to `api.github.com` from the node's address. Under a rate limit or
  without egress the button shows a 503 with the reason; the node is otherwise unaffected.
- The version comparison is deliberately strict (three numbers): a tag that breaks the release
  format breaks the check, not the answer.
- A cluster's nodes each check for themselves; the Settings page shows the node it is open on.
- What would make us revisit: an update endpoint on nxplain.sh, or an operator-declared source
  for self-hosted mirrors.
