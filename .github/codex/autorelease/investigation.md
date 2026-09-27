# Investigation phase

Observable goal: classify exactly one action key from retained evidence and
produce a schema-valid, evidence-bound autorelease plan without modifying a
repository or causing a GitHub mutation.

For every material release or lifecycle claim, cite one captured body by
capture ID and SHA-256 digest and provide a locator that resolves in that body.
State exact repository and support-policy preconditions, repository work,
allowed paths, checks, stable release intent, risk, notification summary, and
downstream success conditions. Live research is context only and cannot replace
captured evidence.

Plan evidence `captureId` values may name only a capture in the evidence
manifest or the two deterministic runtime inputs `evidence_manifest` and
`watch_decision`. Those runtime IDs resolve only to
`autorelease-run/evidence/evidence-manifest.json` and
`autorelease-run/watch-decision.json`; no other runtime or repository file is
admissible as plan evidence. Every plan evidence `digest` is the SHA-256 of
the cited file's bytes: for `evidence_manifest`, hash the manifest file
itself rather than copying its embedded `manifestDigest` field, which covers
only the capture identities and never matches the file's own hash. The
`no_change` action key is the one place that uses the embedded field instead;
see below.

The required runtime inputs are generated before this phase and are available
at these exact paths:

- `autorelease-run/evidence/evidence-manifest.json`
- the captured bodies named by each manifest entry, resolved relative to
  `autorelease-run/evidence/`
- `autorelease-run/preconditions.json`
- `autorelease-run/watch-decision.json`

These runtime files are intentionally gitignored, so discovery commands that
respect `.gitignore` (including `rg --files`) may omit them. Read the exact paths
directly before deciding that evidence is missing. A read-only sandbox permits
reads; it is not evidence that an input is unavailable. Verify the mise-php
precondition from the captured `mise_php_state` body and the supplied exact
precondition; a second repository checkout is neither supplied nor required.

Return GO only when the action is unambiguous, all criteria passed with
resolving evidence, preconditions remain exact, and unresolved is empty.
Otherwise return `blocked` or `needs_human` and NO-GO. Make no edit.

Treat `requiredChecks` as downstream exact-head gates, not investigation-phase
advisory checks. Declare them in the plan, but do not run them in this read-only
phase or treat their not-yet-run status as unresolved; writable deterministic
jobs execute them before merge.

If changed evidence has no autorelease consequence, use action `no_change`. Its
key is `no_change:` followed by the first 16 hexadecimal characters of the
`manifestDigest` field stored inside
`autorelease-run/evidence/evidence-manifest.json`, after its `sha256:` prefix.
`watch-decision.json` reports the same value as its own `manifestDigest`.
Never derive the key from the SHA-256 of the manifest file: that file hash is
only the `digest` of an `evidence_manifest` evidence item, and admission
rejects a key built from it. For example, a manifest whose `manifestDigest`
field is `sha256:cf27c1c17087a38632d6...` takes the key
`no_change:cf27c1c17087a386`, whatever the file's own hash is. This keeps the
reviewed snapshot uniquely auditable.

A `no_change` plan authorizes no work: set `editsRequired` to false, leave
both `allowedPaths` arrays empty, set `releaseIntent` to null, and list no
repository edit in `agentOperations`. Recording the reviewed snapshot in
`autorelease-state/last-evidence.json` is deterministic downstream work that
needs no plan authority; deterministic admission rejects any no-change plan
that requests edit authority.

A php-src tag can appear before an official stable release is published. A tag
alone is never sufficient evidence for `new_patch` or `new_branch`. For either
action, include a JSON-pointer evidence item into an official release feed
capture whose resolved value is the exact `releaseIntent.version`: either the
aggregate `php_release_feed` (for example `/8/version`) or the feed of that
version's own branch, `php_release_feed_<major>.<minor>` (for example
`/version` in `php_release_feed_8.4`). Otherwise classify the tag-only change
as `no_change` until the official feed publishes that version.

The aggregate feed names only the newest release of each major, so a patch on
an older maintained branch appears only in its branch feed. Check every
`php_release_feed_<major>.<minor>` capture: when the version it names has no
matching `tag_name` in `php_bin_releases`, that branch needs
`new_patch:<version>`. When several branches need one, propose the oldest
branch first; later runs publish the rest. Always propose the version the
branch feed names, never an older patch on that branch: admission rejects a
stable release when the branch feed or the aggregate feed names a later patch
on the same branch.

Reading every branch feed is how you classify, not what the plan cites. A
`new_patch` or `new_branch` plan cites exactly one release feed item: the
pointer that proves `releaseIntent.version`, in that version's own branch feed
when it is captured and otherwise in the aggregate feed. Do not cite other
branches' feeds, or the aggregate feed alongside the branch feed, as context.
The publish job ignores other branches' feeds, and the aggregate feed once the
branch feed is cited, so citing them adds no proof; it stops when the version's
own branch feed or any other cited capture has changed.

The plan `actionKey` identifies the classified autorelease action, not the
phase-scoped action key in the event contract. It must use one of the reviewed
forms enforced by the output schema: `no_change`, `new_patch`, `new_branch`,
`branch_eol`, `recipe_rebuild`, `repair`, `source_unhealthy`, `health_failed`,
`policy_failure`, or `auth_failure` with the required version, date, attempt,
or lowercase hexadecimal evidence suffix. When `autorelease-events/` already
holds an incomplete record for the same branch, reuse that record's `actionKey`
verbatim instead of re-deriving its date, attempt, or evidence suffix, so the
run that completes the action names the file the earlier run opened.

Every `completionAssessment.criteria[].evidence` entry is a machine-resolved
reference, never explanatory prose. Use only `evidence[N]` for an item in the
plan evidence array, `preconditions.phpBinHead`, `preconditions.misePhpHead`,
`preconditions.supportPolicyDigest`, or `researchSources[N]` for an item in the
research source array. Put explanations in the criterion status or plan summary,
not in an evidence-reference array.

A `recipe_rebuild` republishes an already published PHP version, built from
the current recipe, as a new revision tag. The watcher selects it
deterministically, so confirm it and never invent, reorder, or skip one:
`watch-decision.json` field `rebuildActionKey` names the one rebuild that is
due (empty when every maintained release was built from the current recipe),
and admission rejects any other rebuild key. Reconciling an incomplete
record, `new_branch`, `branch_eol`, and `new_patch` all take priority; propose
the rebuild only when none of them is due. For `recipe_rebuild:<version>:<n>`,
set `releaseIntent.version` to `<version>-<n>`, `editsRequired` to false, both
`allowedPaths` arrays empty, and cite the `php_bin_releases` JSON pointer to
the `tag_name` of the release being superseded: `<version>` when `<n>` is 1,
otherwise `<version>-<n-1>`. While `rebuildActionKey` is non-empty, `no_change`
is never correct: admission rejects it, because recording the evidence as
unchanged would leave the rebuild pending.
