# Repository settings

The plan executor installs these settings with
`scripts/configure-github-maintenance` and verifies them with
`scripts/snapshot-github-admin-state`. Snapshots contain secret names, never
secret values.

Required repository state:

- Require a pull request before merging.
- Require the `Script checks` status check.
- Require conversation resolution.
- Require linear history; block force pushes and branch deletion.
- Enforce protection for administrators and require CODEOWNER approval for
  protected control paths.
- Enable squash merge, auto-merge, update branch, and automatic head-branch
  deletion; disable merge commits and rebase merge.
- Allow Actions write permission and automation PR approval. Runtime Codex jobs
  still declare `contents: read`; only deterministic downstream jobs declare
  write scopes.
- Create the protected `php-maintenance-release` environment, limited to
  protected branches.
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
