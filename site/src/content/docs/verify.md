---
title: Verifying releases
description: Check that a goethite release was built by its release workflow from a tagged commit, and rebuild it yourself to get the same bytes.
---

A goethite release is built by a GitHub Actions workflow from a tagged commit, twice per
architecture on separate machines, and published only if both builds are the same bytes. The
workflow signs a statement of what it built and from which commit, with a short-lived
certificate from [Sigstore](https://www.sigstore.dev): there is no signing key that could leak.
This page shows three checks, from quick to thorough.

## What a release holds

For amd64 (`x86_64`) and arm64 (`aarch64`):

| File                                                   | What it is                                                                                   |
| ------------------------------------------------------ | -------------------------------------------------------------------------------------------- |
| `goethite-<version>-<arch>-unknown-linux-gnu.tar.gz`   | The binary (web UI included), the systemd units, a server config, the example config, the docs and the third-party licence notices |
| `goethite_<version>-1_<arch>.deb`                      | The Debian and Ubuntu package (`amd64`, `arm64`)                                             |
| `goethite-<version>-1.<arch>.rpm`                      | The RHEL and Fedora package (`x86_64`, `aarch64`)                                            |
| `goethite-<version>-<arch>-unknown-linux-gnu.cdx.json` | A [CycloneDX](https://cyclonedx.org) SBOM of the Rust crates built into that binary          |

And once:

| File                                          | What it is                                                     |
| --------------------------------------------- | -------------------------------------------------------------- |
| `goethite-<version>-web.cdx.json`             | A CycloneDX SBOM of the npm packages built into the web UI     |
| `goethite-<version>.provenance.sigstore.json` | The build provenance of the tarballs and packages, as a Sigstore bundle |
| `SHA256SUMS`                                  | The SHA-256 checksums of the tarballs, the packages and the SBOMs        |

The container image `ghcr.io/nxplain-sh/goethite:<version>` is built from the release's tarballs
once the release is published, and attested the same way.

The binary also carries its own dependency list (from
[cargo-auditable](https://github.com/rust-secure-code/cargo-auditable)), so
`cargo audit bin /usr/bin/goethite` checks an installed goethite against the RustSec advisory
database without the SBOM.

## 1. Check the download

```sh
sha256sum --check --ignore-missing SHA256SUMS
```

This shows that the files arrived whole. It does not show who made them: `SHA256SUMS` came from
the same place.

## 2. Check who built it

The [GitHub CLI](https://cli.github.com) checks a file against the attestation the release
workflow signed:

```sh
gh attestation verify goethite-0.5.0-x86_64-unknown-linux-gnu.tar.gz \
  --repo nxplain-sh/goethite \
  --signer-workflow nxplain-sh/goethite/.github/workflows/release.yaml \
  --source-ref refs/tags/v0.5.0 \
  --deny-self-hosted-runners
```

It passes only if the file's SHA-256 is in a statement signed by goethite's release workflow,
running on a tag `v0.5.0` on GitHub's own runners, with a certificate Sigstore issued for that run
and recorded in its public transparency log. The output names the commit it was built from.

`gh` fetches the attestation from GitHub. To use the bundle from the release instead, add
`--bundle goethite-0.5.0.provenance.sigstore.json`. The packages are checked the same way, and the
SBOMs are attested for the tarballs and packages; check one with
`--predicate-type https://cyclonedx.org/bom`.

For the container image, name it with `oci://`; the image workflow pushed it, from the release
it checked first:

```sh
gh attestation verify oci://ghcr.io/nxplain-sh/goethite:0.5.0 \
  --repo nxplain-sh/goethite \
  --signer-workflow nxplain-sh/goethite/.github/workflows/image.yaml \
  --source-ref refs/tags/v0.5.0 \
  --deny-self-hosted-runners
```

## 3. Rebuild it

A release is reproducible: the same commit builds the same bytes. Everything the build uses is
pinned in an image (the Rust and Node.js versions, the C compiler, the tools), and paths, times
and file order are fixed. You need git, [rustup](https://rustup.rs) and docker or podman, on a
machine of the architecture you want to check:

```sh
git clone https://github.com/nxplain-sh/goethite && cd goethite
git checkout v0.5.0
cargo xtask dist
cd target/dist && sha256sum --check --ignore-missing /path/to/SHA256SUMS
```

`cargo xtask dist` builds from the checked-out commit inside the pinned image (uncommitted changes
are left out) and writes the tarball, the packages and the SBOMs to `target/dist`. With docker
and buildx, `cargo xtask image` then builds the container image from the tarballs there, as an OCI
archive in `target/dist`. If a file differs, please
[report it](https://github.com/nxplain-sh/goethite/security/advisories/new): either the build is
not reproducible in a way the release workflow missed, or the release is not what the source
says. [`diffoscope`](https://diffoscope.org) shows where two files differ.

How the build works, and why, is in
[ADR 0026](https://github.com/nxplain-sh/goethite/blob/main/docs/adr/0026-release-builds.md).
