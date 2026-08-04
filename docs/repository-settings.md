# Repository settings

The plan executor installs these settings with
`scripts/configure-github-autorelease` and verifies them with
`scripts/snapshot-github-admin-state`. Snapshots contain secret names, never
secret values.

Required repository state:

- Protect `main` with the `protect_main` repository ruleset: require a pull
  request (squash merges only, CODEOWNER review, review-thread resolution),
  require the status checks below on an up-to-date branch, require linear
  history, and block force pushes and branch deletion. Repository
  administrators are bypass actors in `pull_request` mode only: the solo
  owner can merge a pull request past a failing rule but can never push,
  force-push, or delete `main` directly. Classic branch protection (and its
  `enforce_admins` toggle) is retired; the configure script removes it.
- Require the `Script checks` status check.
- Require the base-controlled `Protected controls` status check. It passes
  automatically for unprotected generated paths and for owner-authored pull
  requests (a solo owner cannot approve their own PR, so an owner review
  requirement was unsatisfiable there); any other author touching a path in
  `autorelease/protected-paths.json` requires an exact-head `loadinglucian`
  approval.
  The sole deterministic exception is `autorelease-state/last-evidence.json`:
  a same-repository `github-actions[bot]` PR may pass only when it is a direct
  child of the current base, is tied to the still-running protected watcher,
  changes exactly that file, and the record has the reviewed healthy-capture
  shape. The exact file must also have a GitHub OIDC/Sigstore attestation from
  the protected watcher workflow, bound to its source commit and run-specific
  predicate. Runtime Codex cannot mint that identity, invoke this exception,
  or edit that state.
- Bind the required checks to the GitHub Actions app, preventing another app
  from satisfying the same context name.
- Enable squash merge, auto-merge, update branch, and automatic head-branch
  deletion; disable merge commits and rebase merge.
- Keep the default Actions token read-only while enabling automation PR
  creation. Runtime Codex jobs declare read scopes; only deterministic
  downstream jobs explicitly declare the write scopes they require.
- Enable the organization setting that permits Actions to create pull requests;
  runtime workflows do not submit approving reviews. Protected-control approval
  remains owner-only except for the deterministic evidence-state proof above.
- Because GitHub suppresses ordinary PR events created by `GITHUB_TOKEN`, each
  deterministic PR coordinator explicitly dispatches `ci.yml` and
  `protected-controls.yml` at the exact PR branch, accepts only newly created
  successful validator runs for that head SHA, and only then publishes the
  Actions-owned check evidence plus PR-visible commit statuses with the exact
  validator URLs.
- Allow GitHub-owned Actions plus only `openai/codex-action` and
  `jdx/mise-action`, and require every Action reference to use a full commit
  SHA.
- Create the protected `php-autorelease-publish` environment, limited to
  protected branches, and disable administrator bypass.
- Create the protected `php-autorelease-canary` environment with the
  same protected-branch-only policy and disabled administrator bypass.
- Enable Dependabot security updates, provider-pattern secret scanning, and
  secret-scanning push protection. Request validity checks and non-provider
  patterns as well; GitHub may retain those two as disabled until the
  organization has GitHub Secret Protection.
- Enable GitHub immutable releases so future published tags and assets cannot
  be moved, replaced, or deleted.
- Set `AUTORELEASE_OWNER=loadinglucian`.
- Keep distinct repository-scoped `OPENAI_API_KEY` secrets.
- For the email digest, keep the repository-scoped `RESEND_API_KEY` secret
  (a Resend sending-only key) plus the `AUTORELEASE_EMAIL_FROM` and
  `AUTORELEASE_EMAIL_TO` repository variables. The sender address must belong
  to a domain verified in Resend. While any of the three is unset, the digest
  workflow skips without failing.
- Keep the `autorelease` and `attention-required` labels.

CODEOWNERS covers prompts, contracts, workflows, policy invariants, authority
controls, and release code. Deterministic event/state records and admitted
runtime paths are deliberately outside CODEOWNERS so their exact-SHA PRs can
merge. Runtime sealing rejects protected controls before a branch or PR is
created. Initial and later protected-control changes require an explicit
reviewed PR outside the runtime agent.

The normal verification commands are:

```bash
./scripts/snapshot-github-admin-state \
  --repo bigpixelrocket/php-bin \
  --output docs/admin-state/php-bin-after.json

./scripts/configure-github-autorelease \
  --repo bigpixelrocket/php-bin \
  --owner loadinglucian \
  --required-check "Script checks" \
  --environment php-autorelease-publish \
  --environment php-autorelease-canary
```
