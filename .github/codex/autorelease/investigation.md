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
admissible as plan evidence.

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

If changed evidence has no autorelease consequence, use action `no_change` and
the key `no_change:<first 16 hexadecimal characters of the evidence manifest
digest>` so the reviewed snapshot remains uniquely auditable.

A `no_change` plan authorizes no work: set `editsRequired` to false, leave
both `allowedPaths` arrays empty, set `releaseIntent` to null, and list no
repository edit in `agentOperations`. Recording the reviewed snapshot in
`autorelease-state/last-evidence.json` is deterministic downstream work that
needs no plan authority; deterministic admission rejects any no-change plan
that requests edit authority.

A php-src tag can appear before an official stable release is published. A tag
alone is never sufficient evidence for `new_patch` or `new_branch`. For either
action, include a `php_release_feed` JSON-pointer evidence item whose resolved
value is the exact `releaseIntent.version`; otherwise classify the tag-only
change as `no_change` until the official feed publishes that version.

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
