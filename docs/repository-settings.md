# Repository settings

The plan executor installs these settings with
`scripts/configure-github-maintenance` and verifies them with
`scripts/snapshot-github-admin-state`. Snapshots contain secret names, never
secret values.

Required repository state:

- Require a pull request before merging.
- Require the `Script checks` status check.
- Require the base-controlled `Protected controls` status check. It passes
  automatically for unprotected generated paths and requires an exact-head
  `loadinglucian` approval for paths in `maintenance/protected-paths.json`.
  The sole deterministic exception is `maintenance-state/last-evidence.json`:
  a same-repository `github-actions[bot]` PR may pass only when it is a direct
  child of the current base, is tied to the still-running protected watcher,
  changes exactly that file, and the record has the reviewed healthy-capture
  shape. Runtime Codex cannot invoke this exception or edit that state.
- Bind the required check to the GitHub Actions app, preventing another app
  from satisfying the same context name.
- Require conversation resolution.
- Require linear history; block force pushes and branch deletion.
- Enforce protection for administrators and require CODEOWNER approval for
  protected control paths.
- Enable squash merge, auto-merge, update branch, and automatic head-branch
  deletion; disable merge commits and rebase merge.
- Keep the default Actions token read-only while enabling automation PR
  creation. Runtime Codex jobs declare read scopes; only deterministic
  downstream jobs explicitly declare the write scopes they require.
- Enable the organization setting that permits Actions to create pull requests;
  runtime workflows do not submit approving reviews. Protected-control approval
  remains owner-only except for the deterministic evidence-state proof above.
- Allow GitHub-owned Actions plus only `openai/codex-action` and
  `jdx/mise-action`, and require every Action reference to use a full commit
  SHA.
- Create the protected `php-maintenance-release` environment, limited to
  protected branches, and disable administrator bypass.
- Create the protected `php-maintenance-agent-canary` environment with the
  same protected-branch-only policy and disabled administrator bypass.
- Enable Dependabot security updates, provider-pattern secret scanning, and
  secret-scanning push protection. Request validity checks and non-provider
  patterns as well; GitHub may retain those two as disabled until the
  organization has GitHub Secret Protection.
- Enable GitHub immutable releases so future published tags and assets cannot
  be moved, replaced, or deleted.
- Set `MAINTENANCE_OWNER=loadinglucian`.
- Keep distinct repository-scoped `OPENAI_API_KEY` secrets.
- Keep the `maintenance` and `attention-required` labels.

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
  --output docs/admin-state/php-bin.json

./scripts/configure-github-maintenance \
  --repo bigpixelrocket/php-bin \
  --owner loadinglucian \
  --required-check "Script checks"
```
