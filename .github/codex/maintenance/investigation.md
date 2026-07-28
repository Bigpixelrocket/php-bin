# Investigation phase

Observable goal: classify exactly one action key from retained evidence and
produce a schema-valid, evidence-bound maintenance plan without modifying a
repository or causing a GitHub mutation.

For every material release or lifecycle claim, cite one captured body by
capture ID and SHA-256 digest and provide a locator that resolves in that body.
State exact repository and support-policy preconditions, repository work,
allowed paths, checks, stable release intent, risk, notification summary, and
downstream success conditions. Live research is context only and cannot replace
captured evidence.

The required runtime inputs are generated before this phase and are available
at these exact paths:

- `maintenance-run/evidence/evidence-manifest.json`
- the captured bodies named by each manifest entry, resolved relative to
  `maintenance-run/evidence/`
- `maintenance-run/preconditions.json`
- `maintenance-run/watch-decision.json`

These runtime files are intentionally gitignored, so discovery commands that
respect `.gitignore` (including `rg --files`) may omit them. Read the exact paths
directly before deciding that evidence is missing. A read-only sandbox permits
reads; it is not evidence that an input is unavailable. Verify the mise-php
precondition from the captured `mise_php_state` body and the supplied exact
precondition; a second repository checkout is neither supplied nor required.

Return GO only when the action is unambiguous, all criteria passed with
resolving evidence, preconditions remain exact, and unresolved is empty.
Otherwise return `blocked` or `needs_human` and NO-GO. Make no edit.

If changed evidence has no maintenance consequence, use action `no_change` and
the key `no_change:<first 16 hexadecimal characters of the evidence manifest
digest>` so the reviewed snapshot remains uniquely auditable.

The plan `actionKey` identifies the classified maintenance action, not the
phase-scoped action key in the event contract. It must use one of the reviewed
forms enforced by the output schema: `no_change`, `new_patch`, `new_branch`,
`branch_eol`, `recipe_rebuild`, `repair`, `source_unhealthy`, `health_failed`,
`policy_failure`, or `auth_failure` with the required version, date, attempt,
or lowercase hexadecimal evidence suffix.

Every `completionAssessment.criteria[].evidence` entry is a machine-resolved
reference, never explanatory prose. Use only `evidence[N]` for an item in the
plan evidence array, `preconditions.phpBinHead`, `preconditions.misePhpHead`,
`preconditions.supportPolicyDigest`, or `researchSources[N]` for an item in the
research source array. Put explanations in the criterion status or plan summary,
not in an evidence-reference array.
