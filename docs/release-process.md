# Release process

Releases are published by the autorelease system, not by a person. There is no
tag-triggered release workflow: `autorelease-publish.yml` only runs through
`workflow_dispatch` with an admitted action key, exact merged commit, and the
investigation run holding the retained evidence. Pushing a version tag by hand
therefore publishes nothing. See [`AUTORELEASE.md`](../AUTORELEASE.md) for the
full contract.

## What the automation does

1. The daily watcher captures upstream evidence and, when it changes, admits an
   evidence-bound plan.
2. For an ordinary stable patch the plan requires no edit and goes straight to
   the publish transaction. A recipe change is implemented offline, sealed,
   validated in a clean checkout, and merged through exact-SHA admission first.
3. The publish transaction rebuilds on macOS 26 arm64 in a separate job with a
   read-only token, verifies the exact module baseline and deployment target,
   packages the archive, and writes `SHA256SUMS`. The write-scoped release job
   checks those bytes against the digests the build reported, creates the
   annotated tag and draft, verifies the draft bytes through a temporary
   install, then publishes the unchanged bytes and verifies the public install
   through `mise-php`.
4. It advances one legal state at a time, reuses an existing release's assets
   instead of the fresh build, and never overwrites, deletes, or retags a
   published release.

A first release on a new PHP branch additionally waits for exact-commit
`php_bin_ready` and `mise_ready` records.

## Changing the recipe by hand

A human changes what gets built, never how it gets released:

1. Update `expected-modules/<minor>.txt` only from a reviewed module baseline.
   It lists every module loaded by default: the static binary plus the
   default-on shared extensions.
2. Update the recipe: `stages/s4.txt` for modules compiled into the binary,
   `stages/s4-shared.txt` for shared extensions, their default state, and
   the stable release each new extension is pinned to.
3. Run `scripts/build.sh <minor> s4` on macOS arm64. Its module gate must pass
   and report a macOS 26.0 deployment target for the binary and every `.so`.
4. Package the build with `scripts/package.sh` and install the archive through
   `mise-php` from a local server to confirm `php --ini` and the default
   extensions.
5. Confirm `scripts/test.sh` and public-language checks pass.
6. Open a pull request with the build log and module diff.

After that merges, the watcher sees which published versions were built from
a different recipe and rebuilds them one per run as revisions such as
`8.4.5-1`. A change to one branch's `expected-modules/<branch>.txt` rebuilds
only that branch; a change to a shared recipe input rebuilds every maintained
version. Each release records the identity of the recipe it was built from
in its notes, and a version is rebuilt when its newest revision records a
different identity or none. The watcher selects the version and revision
deterministically, the investigation confirms it as a
`recipe_rebuild:<version>:<n>` plan, and admission accepts only that key, so a
revision is never chosen by hand. See "Recipe rebuilds" in
[`AUTORELEASE.md`](../AUTORELEASE.md).

Never upload a locally built replacement over an existing release asset. A
changed recipe or artifact requires a new rebuild revision.
