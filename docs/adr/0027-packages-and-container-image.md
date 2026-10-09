# ADR 0027: .deb and .rpm packages and a container image, from the release build

- **Status:** Accepted
- **Date:** 2026-10-09

## Context

[ADR 0026](0026-release-builds.md) gives every release a reproducible, attested tarball. Most
users install software differently: with their distribution's package manager, or as a container.
Both should hold the same binary as the tarball, be as reproducible and as verifiable, and fit
how goethite runs: under its hardened systemd unit on a host, where a fresh install often finds
port 53 taken by systemd-resolved, and where an upgrade can hand over in place without dropping a
query (SIGUSR2); or in a container, where it must bind port 53 without depending on what the
runtime allows an unprivileged process to do.

## Decision

**`cargo xtask dist` also builds a .deb and an .rpm per architecture with nfpm; `cargo xtask
image` builds a distroless container image from the release tarballs, which is pushed when a
release is published.**

Packages:

- **nfpm**, from its official image by digest, in the build image. One description,
  `deploy/package/nfpm.yaml`, gives both formats. Files are dated with `SOURCE_DATE_EPOCH`, and
  the build container has a fixed host name, which the .rpm records as its build host, so the
  packages are reproducible and the release workflow compares and attests them with the
  tarballs. The SBOMs are attested for them too.
- **Contents:** `/usr/bin/goethite`, both units in `/usr/lib/systemd/system`, the server config
  `deploy/goethite.toml` as `/etc/goethite/goethite.toml` (a conffile, `config(noreplace)` in the
  .rpm), the example config and docs, and the licences where each format expects them. The
  tarball ships the same server config.
- **Dependencies:** glibc 2.34 or newer (what `dist` enforces) and libgcc for unwinding.
- **Scripts:** a first install does not start goethite; it prints how to check the config and
  start it. An upgrade, if goethite runs, sends SIGUSR2: the running process starts the new
  binary and hands over its sockets and store. Removal stops and disables both units. The data in
  `/var/lib/goethite` (the unit's state directory) is kept.
- **Not signed with a repository key**, and not in an APT or DNF repository yet: trust comes from
  the provenance attestation, which `gh attestation verify` checks for a package file like any
  other. A repository needs a signing key and hosting (backlog).

Container image:

- **Base:** Google's distroless image for glibc programs (`gcr.io/distroless/cc-debian12`, by
  digest): glibc, libgcc, CA certificates and time zone data, no shell or package manager.
- **No compilation:** `cargo xtask image` takes the binaries out of the release tarballs in
  `target/dist` and copies them in, one per architecture, with buildx. With `SOURCE_DATE_EPOCH`,
  `rewrite-timestamp=true` and buildx's own provenance off, the same tarballs give the same
  image; the release workflow builds it twice and compares.
- **Privileges:** the image starts goethite as root, and its config sets `server.user =
  "nonroot"`, so goethite binds port 53, switches to uid 65532 and gives up every capability
  before it reads the store or a packet: the same code path as on a host without systemd. Not
  every runtime lets an unprivileged process bind port 53 (rootless podman and Kubernetes do not
  by default), so starting as root is what works everywhere; started with `--user 65532` where
  the runtime allows it, goethite stays that user.
- **Config:** the image's own (`deploy/container/goethite.toml`) listens on IPv4 only, since
  container networks often have no IPv6, and keeps the store and lists in the
  `/var/lib/goethite` volume.
- **Publishing:** `image.yaml` runs when a release is published, not when it is drafted, so
  nothing is public before a maintainer publishes. It downloads the release's tarballs, checks
  them against `SHA256SUMS` and their provenance attestations, builds and pushes
  `ghcr.io/nxplain-sh/goethite` (the version, the minor version and `latest`; a pre-release only
  its version), and attests the image, with the attestation pushed to the registry beside it.

Tests: `tests/packages/install.sh` installs the packages on Debian 12, Ubuntu 22.04 and 24.04,
Rocky Linux 9 and Fedora, checks the binary and the shipped config, and removes them. On Debian 12
under systemd it starts goethite from its unit, queries it, upgrades in place by reinstalling,
and removes it. The release workflow runs it on both architectures.

## Alternatives considered

- **cargo-deb and cargo-generate-rpm:** two tools with two configurations in Cargo.toml for one
  layout. nfpm reads one file and is a single static binary.
- **An APT and a DNF repository now:** convenient upgrades, but a long-lived signing key to guard
  and somewhere to host it; the attested files come first.
- **Building the image by compiling in a Dockerfile:** a second build path, whose binary is not
  the one released and compared.
- **A `scratch` image with a static binary:** needs musl (ADR 0026), and loses the time zone data
  schedules use.
- **Running as an unprivileged user from the start:** fails to bind port 53 on runtimes that keep
  ports below 1024 privileged; listening on a high port instead would make every deployment remap
  it.
- **Pushing the image when the release is drafted:** it would be public before the release, and
  stay public if the draft were dropped.

## Consequences

- One `cargo xtask dist` gives the tarball, both packages and the SBOMs; `cargo xtask image` the
  image. All are reproducible from a commit and attested by the release and image workflows.
- `dnf` warns that it skipped OpenPGP checks for a package installed from a file; the
  attestation is the check.
- The shipped config listens on `[::]:53` too; a host without IPv6 must drop that address.
- A container restart drops queries for a moment: the in-place handoff needs the new binary in
  the same container. Two containers behind the floating IP are the answer where that matters.
- The ghcr.io package must be made public once, after its first push (a package setting).
