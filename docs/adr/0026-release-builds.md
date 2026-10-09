# ADR 0026: Reproducible release builds, attested with Sigstore

- **Status:** Accepted
- **Date:** 2026-10-09

## Context

Through v0.4 goethite had tags but no release files: users built from source. The threat model
lists tampered releases (B7) as a Phase 5 threat, answered by reproducible, signed builds and an
SBOM. A user who downloads a binary should be able to check three things without trusting the
download location: that the project's release workflow built it, from which commit, and, if they
want, that the same commit builds the same bytes on their own machine.

Several inputs could make two builds of one commit differ: the Rust and C compilers, Node.js and
the npm packages that build the web UI, absolute paths compiled into the binary (panic locations,
`__FILE__`), file times and order in the tarball, and whatever happens to be installed on the
build host. A release also has to state which glibc it needs.

## Decision

**Releases are built by `cargo xtask dist` in a pinned image, built twice and compared, and
attested with GitHub's keyless Sigstore attestations.**

- **One build path, local and in CI.** `cargo xtask dist` builds `xtask/dist/Containerfile`
  and runs the build in it, from a `git archive` of the last commit on stdin; the results come
  back as a tar stream on stdout, so nothing is mounted. It needs only docker or podman.
- **Pinned inputs.** The official Rust 1.99.0 image for Debian 12 by digest (rustc, GCC 12, GNU
  tar, glibc 2.36), Node.js and npm from the official Node.js image by digest, cargo-auditable and
  cargo-cyclonedx at fixed versions with `--locked`, `Cargo.lock` and `package-lock.json`. The
  build refuses to run when the image's Rust or Node.js differs from `rust-toolchain.toml` or
  `web/.node-version`. No cache is used in CI.
- **Fixed paths and times.** `--remap-path-prefix` and `-ffile-prefix-map` give the source and the
  Cargo registry fixed names; the source sits at the same path in every build anyway.
  `SOURCE_DATE_EPOCH` is the commit time. The tarball is written with sorted names, the commit
  time, root as owner and normalised modes, and `gzip --no-name`. rust-embed embeds the web UI in
  name order with fixed timestamps.
- **What a release holds**, per architecture (`x86_64` and `aarch64`, `unknown-linux-gnu`): a
  tarball with the binary, the licences, README, changelog, example config and systemd units; a
  CycloneDX SBOM of the crates in the binary (cargo-cyclonedx, for that target); and one CycloneDX
  SBOM of the npm packages in the web UI. The binary also carries its dependency list in a
  `.dep-v0` section (cargo-auditable), which `cargo audit bin` and other scanners read. npm's
  random serial number is dropped and its timestamp set to the commit time, so the SBOMs are
  reproducible too.
- **glibc.** The image has glibc 2.36, but `dist` fails if the binary needs a symbol newer than
  glibc 2.34, so releases run on RHEL 9, Ubuntu 22.04, Debian 12 and anything newer.
- **Checked reproducibility.** The release workflow builds each architecture twice on separate
  runners and fails unless the files are the same bytes. It also runs weekly and on changes to
  the build, so a regression shows before a release needs it.
- **Attestations, not keys.** On a `v*` tag that is on `main` and matches the version in
  `Cargo.toml`, the workflow writes `SHA256SUMS`, attests the tarballs' build provenance (SLSA v1)
  and their SBOMs with `actions/attest-build-provenance` and `actions/attest-sbom`, and drafts a
  GitHub Release with the files, the provenance bundle and the changelog section as notes. The
  signing certificate is issued to the workflow by Sigstore's Fulcio from GitHub's OIDC token
  and logged in Rekor; there is no long-lived key to store, rotate or lose. A maintainer reviews
  the draft and publishes it.

## Alternatives considered

- **A maintainer-held signing key** (minisign, GPG, cosign with a key): simple to verify, but the
  key must be kept offline, backed up and rotated, and a stolen key signs anything. Keyless
  attestations tie each signature to one workflow run on one commit, in a public log.
- **Building on the runner without an image**, with `rustup` and `setup-node`: reproducible only
  between identical runner images, which change weekly, and not reproducible by users.
- **musl and a static binary**: runs on any Linux, but musl's allocator is markedly slower under
  the multi-threaded load goethite runs; it needs another allocator and a bench first (backlog).
- **cargo-dist or similar release tooling**: more than goethite needs, with its own conventions
  and generated workflows to keep in step; the build here is a few hundred lines of xtask and one
  workflow.
- **An SBOM only from `cargo auditable` data**: the embedded list has no licences or hashes, and
  does not cover the web UI.

## Consequences

- Anyone can rebuild a release: check out the tag, run `cargo xtask dist`, compare with
  `SHA256SUMS`. A mismatch is a bug, or a tampered release.
- Bumping Rust or Node.js means bumping the image too; `dist` says so when they disagree.
  Renovate updates the image digests with the other dependencies.
- The web UI's `package.json` carries the workspace version, since it names the web UI in its
  SBOM; `cargo xtask versions` (in `cargo xtask ci`) checks that every version agrees.
- Releases depend on GitHub (Actions, the attestation store) and Sigstore's public good instance.
  Verifying needs `gh` or another Sigstore client; `SHA256SUMS` alone only shows a download is
  complete.
- The .deb and .rpm packages and the container image come from the same build
  ([ADR 0027](0027-packages-and-container-image.md)).
