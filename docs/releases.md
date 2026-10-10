# Releases

A release is a `vX.Y.Z` tag on `main` and what the release workflow builds from it: for amd64 and
arm64, a tarball, a .deb, an .rpm and their SBOMs, built twice to prove they are reproducible and
attested with Sigstore, plus a container image
([ADR 0026](adr/0026-release-builds.md), [ADR 0027](adr/0027-packages-and-container-image.md)).
People run a tag, not a branch. How the branches feed a release is in [branching.md](branching.md).

## Versioning

[Semantic versioning](https://semver.org), one version for everything in the repository: the
crates, the web UI and the OpenAPI document. `cargo xtask versions` checks that they agree.

Take the number from what is under `## [Unreleased]` in [`CHANGELOG.md`](../CHANGELOG.md):

- Only `Fixed` or `Security` entries: a **patch**, `X.Y.(Z+1)`.
- Anything under `Added`, `Changed`, `Deprecated` or `Removed`: a **minor**, `X.(Y+1).0`. Before
  1.0 a minor may also change the configuration format or `/api/v1` incompatibly, said so in the
  changelog. A patch never does.
- From 1.0 on, an incompatible change to the configuration, the CLI or `/api/v1` is a **major**.

There is no schedule. A minor goes out when a coherent set of features is done and documented, a
patch when a fix matters to users, a security fix as soon as it is ready. A release from
`development` carries everything merged there, so merge finished work only; the rest waits on its
branch.

## Cutting a release

From `development`: every minor, and a patch when `development` holds only fixes.
`cargo xtask dist` builds the release files for your machine's architecture locally, the same way
the workflow does (it needs docker or podman), if you want to try the build first.

1. **Prepare it on a branch off `development`:**

   ```sh
   git switch development && git pull
   git switch -c chore/release-X.Y.Z
   ```

   - Bump the version: `workspace.package.version` and the internal crates in
     `[workspace.dependencies]` in `Cargo.toml`, `version` in `web/package.json` and both places
     in `web/package-lock.json`, and, for a minor, the image tag (`X.Y`) in every `compose.yaml`
     under `deploy/container/`. `cargo xtask versions` checks they agree. Regenerate the OpenAPI
     document (`GOETHITE_UPDATE_OPENAPI=1 cargo test -p goethite-api --test openapi`), whose
     version follows.
   - In `CHANGELOG.md`, turn `## [Unreleased]` into `## [X.Y.Z] - <date>`, add a new empty
     `## [Unreleased]` above it, and update the compare links at the bottom. The release notes are
     taken from this section, so it reads as sentences for users, not as a list of commits.
   - Nothing else goes on this branch: a release commit that also fixes something cannot be
     reverted cleanly.

2. **Fuzz every target** on the branch: `cargo xtask fuzz`, about 90 minutes, on a machine that
   does not sleep. A finding is fixed privately first (see [`SECURITY.md`](../SECURITY.md)).
3. **Merge the branch into `development`**: a pull request titled `chore: prepare X.Y.Z`, merged
   once CI passes. From here until step 4 is merged, merge nothing else into `development`, so
   that `main` gets exactly what the changelog describes.
4. **Merge `development` into `main`**:

   ```sh
   gh pr create --base main --head development --title "release: X.Y.Z"
   ```

   A merge commit once CI passes. The `source branch` check fails it while `## [Unreleased]` has
   entries or the version matches `main`'s. The API compatibility check compares the API with
   `main`'s, the last release: if the release holds an intended breaking change, this pull request
   needs the `api-breaking` label too.
5. **Tag the merge commit** and push the tag:

   ```sh
   git switch main && git pull
   git tag -a vX.Y.Z -m "goethite X.Y.Z"
   git push origin vX.Y.Z
   ```

6. **Check the draft and publish it.** The release workflow builds both architectures twice,
   fails unless the builds match, refuses a tag that is not on `main` or does not match the
   version, then attests the files and drafts the GitHub Release. Check the draft
   (`gh attestation verify` on a downloaded tarball, see
   [Verifying releases](../site/src/content/docs/verify.md)) and publish it.
7. Publishing runs `image.yaml`, which checks the published tarballs, then builds, pushes and
   attests `ghcr.io/nxplain-sh/goethite`. `cargo xtask image` builds the same image locally from
   `target/dist`, as an OCI archive.

## Patch releases from main (hotfixes)

When `development` holds changes that must not ship yet, a patch is cut from `main` instead
([branching.md](branching.md#hotfixes) says why):

1. Branch off `main`: `git switch -c hotfix/X.Y.Z origin/main`.
2. Fix it, with a regression test. Bump the version and write the changelog as in step 1 above,
   with the fix's entry straight under a new `## [X.Y.Z] - <date>`.
3. Fuzz every target, as in step 2.
4. Open the pull request into `main` (`gh pr create --base main --title "release: X.Y.Z"`) and
   merge it once CI passes.
5. Tag, check and publish as in steps 5 to 7.
6. **The same day, merge `main` back into `development`**, through a branch, since neither
   long-lived branch takes a push:

   ```sh
   git switch -c chore/merge-X.Y.Z origin/development
   git merge origin/main
   git push -u origin chore/merge-X.Y.Z
   gh pr create --base development --title "chore: merge X.Y.Z into development"
   ```

   In `CHANGELOG.md`, `development`'s `## [Unreleased]` stays on top, then the new `## [X.Y.Z]`
   section, then the older ones.

## Security fixes

A security fix is a hotfix prepared in private: in the advisory's temporary private fork (see
[`SECURITY.md`](../SECURITY.md)) or on a maintainer's machine, fuzzing included. It reaches `main`
as a `hotfix/X.Y.Z` pull request in this repository, never through the advisory's merge button:
GitHub runs no checks in a temporary private fork and
[skips the branch rules](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/collaborating-in-a-temporary-private-fork-to-resolve-a-repository-security-vulnerability)
when merging from it, so the fix would land on `main` untested. Push the finished branch only when
everything else is ready, then merge, tag and publish in one sitting, and publish the advisory once
the release is out. The fix is public from the push; keep that window short.

## Tags

A release tag is an annotated `vX.Y.Z` on `main`, created by hand. A `v*` tag is never moved or
deleted, and the tag ruleset refuses both: people and package mirrors may already have fetched it.
If a release run fails or a published release turns out wrong, fix the cause and release the next
patch; the skipped version keeps its tag and gets no GitHub Release.

## Done

A release is done when:

- the GitHub Release is published and `gh attestation verify` passes on its files;
- `image.yaml` pushed the image;
- for a hotfix, `main` is merged back into `development`.
