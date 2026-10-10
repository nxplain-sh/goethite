# Branching

Two long-lived branches. Every other branch lives only as long as the change it carries.

| Branch        | What it is                                                                                           |
| ------------- | ---------------------------------------------------------------------------------------------------- |
| `main`        | The latest release. It moves only when a release is cut, and every release is a `v*` tag on it.      |
| `development` | Where the work comes together. Every feature, fix and chore lands here first, through a pull request. |

Topic branches start from `development` and go back into it through a pull request; a hotfix starts
from `main` and goes back into `main`. Nobody pushes to either long-lived branch, maintainers
included: the [rulesets](../CONTRIBUTING.md#repository-settings-maintainers) and CI's
`source branch` check enforce it. How a release is cut is in [releases.md](releases.md).

## main is the latest release

`main` moves in two ways only: a release merge of `development`, or a hotfix. The `source branch`
check holds it to that: a pull request into `main` must come from `development` or a `hotfix/`
branch, change the version, and leave nothing under `## [Unreleased]` in `CHANGELOG.md`. So `main`
always holds the newest release, and that is what these rely on:

- The website deploys from `main` (`pages.yaml`), so it documents the version people can
  download. A site fix merged into `development` goes live with the next release.
- The release workflow refuses a tag that is not on `main`.
- `main` is the default branch: the README a visitor sees on GitHub describes the released
  version, and Renovate reads its configuration from there, so a change to `renovate.json` takes
  effect with the next release.

The cost: GitHub proposes `main` as the base of a new pull request, which is wrong for almost every
pull request. Name the base:

```sh
gh pr create --base development
```

## A unit of work

```sh
git switch development && git pull
git switch -c feature/doh-padding
# commits, with the changelog entry, the docs and an ADR if there was a decision
cargo xtask ci
git push -u origin feature/doh-padding
gh pr create --base development
```

While the branch is open, keep it current by merging `development` into it. Rebase only what you
have not pushed yet: once someone may have fetched the branch, rewriting it costs them more than
the tidier history is worth.

## Branch names

`<kind>/<what-it-does>`, kebab-case:

| Prefix      | For                                                                         |
| ----------- | --------------------------------------------------------------------------- |
| `feature/`  | Something a user can notice that was not there                              |
| `fix/`      | Something that was supposed to work and did not                             |
| `refactor/` | The same behaviour, with better structure or speed                          |
| `chore/`    | Dependencies, CI, build, tests, tooling, release preparation                |
| `docs/`     | Documentation only: `docs/`, `site/`, the Markdown files at the top level   |
| `hotfix/`   | A patch release cut from `main`, named for its version: `hotfix/0.5.1`      |

Renovate's branches are `renovate/…`. The prefix sorts the branch list; the commits on a branch
still use the [Conventional Commit](../CONTRIBUTING.md#commit-conventions) types (`feat`, `perf`,
`test`, `ci` …). Rename a branch that a tool named some other way before its first push:
`git branch -m feature/<what>`.

For branches in this repository, the `source branch` check fails a pull request from a branch
named any other way. Branches in forks are named as their authors like.

## Merging

Into either branch: **a merge commit**. Not a squash, not a rebase. The merge commit keeps the pull
request number in `git log` (`Merge pull request #47 from nxplain-sh/fix/…`), so the review behind
a change can be found later, and the commits on the branch stay as written, one logical change
each. Delete the branch after the merge.

Into `main` this is not a preference. A squash of `development` into `main` gives a commit whose
content matches `development` but whose ancestry does not: `development` stops being an ancestor
of `main`, and every later release merge presents changes that are already released again, as
conflicts. The rulesets allow merge commits only.

## Hotfixes

A hotfix is a fix that cannot wait for the next release and must not carry what is waiting on
`development` with it. It is a patch release cut from `main`:

1. Branch off `main`, not `development`: `git switch -c hotfix/X.Y.Z origin/main`, where `X.Y.Z`
   is the next patch version. A branch off `development` would drag everything waiting there into
   the release.
2. Fix it, with a regression test, and prepare the release on the same branch.
3. Open the pull request into `main`. Same checks, smaller diff. Merge it, tag it and publish it.
4. **Merge `main` back into `development` the same day.** A fix that lives only on `main` is one
   the next release quietly reverts.

[releases.md](releases.md#patch-releases-from-main-hotfixes) has the steps. Only the newest minor
version gets fixes ([SECURITY.md](../SECURITY.md#supported-versions)), so hotfixes always start
from `main`, and there are no branches for older versions.
