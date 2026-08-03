# Autorelease Unattended Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix every finding from the thermo-nuclear review of the php-bin + mise-php autorelease system and guarantee fully unattended `new_patch`, `new_branch` (minor or major), and `branch_eol` releases with zero human input, while keeping every historical release installable.

**Architecture:** Two repos. `php-bin` (publisher, `/Users/lucian/Developer/bigpixelrocket/php-bin`) holds the deterministic core (`autorelease/control.py`, `autorelease/verify.py`) plus GitHub Actions workflows that let a Codex agent propose changes which deterministic Python admits, seals, and merges. `mise-php` (consumer, `/Users/lucian/Developer/bigpixelrocket/mise-php`) is a mise plugin in Lua whose autorelease consumer (`autorelease/consumer.py`, `autorelease/admission.py`) propagates php-bin policy. The plan closes automation deadlocks, removes hardcoded 8.x version assumptions, fixes verified defects, plugs authority holes, converts brittle text-grep verification to structural checks, dedupes copy-pasted admission logic, and makes post-publish transactions recoverable.

**Tech Stack:** Python 3 stdlib (no new deps), Bash + jq, GitHub Actions, Lua (vfox/mise plugin API), `unittest`.

## Global Constraints

- Never read, write, search, or reference `**/auth.json`, `**/.env`, `**/.env.*`, `~/.ssh/**`, `~/.aws/**` in any command or code.
- No AI attribution anywhere: no "Generated with", no "Co-Authored-By", nothing referencing AI in code, comments, commits, or PRs.
- Never commit to `main`/`master`. All work on branch `fix/autorelease-unattended-hardening` in each repo. Conventional Commits (`fix:`, `feat:`, `refactor:`, `test:`, `docs:`, `chore:`).
- Never move or delete published tags, releases, or release assets. EOL means "stop producing new builds", never "remove old ones".
- Every user-facing string added must pass `scripts/check-public-language.sh` (runs in both repos' `scripts/test.sh`).
- php-bin gate: `./scripts/test.sh` (the "Script checks" required check). mise-php gate: `./scripts/test.sh` (the "Plugin contract" required check; requires macOS arm64 + `mise` installed — both true on this machine).
- Behavior-preserving refactors and behavior changes go in separate commits.
- After all merges: verify with `./scripts/verify-autorelease-system` in php-bin.
- Merging: use standing admin-bypass approval — verify functional checks first, squash merge, immediately restore any temporarily relaxed protection (for these repos: lift `enforce_admins`, merge, restore).

---

## Phase 0 — Branches

### Task 0: Create working branches

**Files:** none (git only)

- [ ] **Step 1:** In `php-bin`: `git checkout main && git pull && git checkout -b fix/autorelease-unattended-hardening`
- [ ] **Step 2:** In `mise-php`: `git checkout main && git pull && git checkout -b fix/autorelease-unattended-hardening`
- [ ] **Step 3:** Copy this plan into `php-bin/docs/superpowers/plans/` (already there), `git add docs/superpowers/plans/2026-08-03-autorelease-unattended-hardening.md && git commit -m "docs: add autorelease unattended hardening plan"`

---

## Phase 1 — Unattended functional guarantee

### Task 1: mise-php — snapshot-driven maintained branches in Lua

The listing filter `version:match("^8%.[2-5]%.%d+$")` in `lib/releases.lua` and `content:match("(8%.[2-5][^%s]*)")` in `hooks/parse_legacy_file.lua` hardcode branches. A `new_branch:8.6` or `new_branch:9.0` release would never be listed by `mise ls-remote php`, and `branch_eol` would keep listing dead branches. Intended semantics (already asserted by `scripts/test.sh`): **maintained branches are listed; EOL/old versions stay installable via exact version**.

Fix: generate `lib/policy.lua` from `support-snapshot.json:maintainedBranches`, and have `releases.lua` build its filter from it. `parse_legacy_file.lua` becomes version-agnostic (exact installs of any version are allowed).

**Files:**
- Create: `mise-php/scripts/generate-policy-lua`
- Create: `mise-php/lib/policy.lua` (generated)
- Modify: `mise-php/lib/releases.lua` (`is_supported_version`)
- Modify: `mise-php/hooks/parse_legacy_file.lua:9`
- Modify: `mise-php/scripts/test.sh` (sync check + generic-branch listing test)

**Interfaces:**
- Produces: `lib/policy.lua` returning `{ maintained = { "8.2", "8.3", "8.4", "8.5" } }`; `scripts/generate-policy-lua` (no args, reads `support-snapshot.json`, writes `lib/policy.lua`, idempotent).
- Consumed by: Task 6 (admission cross-check), Task 15 (docs).

- [ ] **Step 1: Write the generator** — `mise-php/scripts/generate-policy-lua`, mode 0755:

```bash
#!/usr/bin/env bash
# Regenerates lib/policy.lua from support-snapshot.json so the Lua plugin
# lists exactly the maintained branches without hardcoding them.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
{
  echo "-- Generated by scripts/generate-policy-lua from support-snapshot.json."
  echo "-- Do not edit by hand; regenerate when the snapshot changes."
  echo "return {"
  echo "    maintained = {"
  jq -r '.maintainedBranches[] | "        \"\(.)\","' support-snapshot.json
  echo "    },"
  echo "}"
} > lib/policy.lua
```

- [ ] **Step 2: Generate** — run `./scripts/generate-policy-lua`; confirm `lib/policy.lua` contains the four branches from `support-snapshot.json`.
- [ ] **Step 3: Rewrite `is_supported_version`** in `mise-php/lib/releases.lua` — replace:

```lua
function M.is_supported_version(version)
    return version:match("^8%.[2-5]%.%d+$") ~= nil
        or version:match("^8%.[2-5]%.%d+%-[1-9]%d*$") ~= nil
end
```

with:

```lua
local policy = require("policy")

function M.is_supported_version(version)
    for _, branch in ipairs(policy.maintained) do
        local prefix = "^" .. branch:gsub("%.", "%%.") .. "%.%d+"
        if version:match(prefix .. "$") ~= nil
            or version:match(prefix .. "%-[1-9]%d*$") ~= nil
        then
            return true
        end
    end

    return false
end
```

(`local policy = require("policy")` goes at the top with the other requires.)

- [ ] **Step 4: Make legacy-file parsing version-agnostic** — in `mise-php/hooks/parse_legacy_file.lua` replace `local version = content:match("(8%.[2-5][^%s]*)")` with `local version = content:match("(%d+%.%d+[^%s]*)")`.
- [ ] **Step 5: Add the sync check to `scripts/test.sh`** — after the `validate-structured-output-schemas` line add:

```bash
"$SCRIPT_DIR/generate-policy-lua"
git -C "$PROJECT_ROOT" diff --exit-code lib/policy.lua
```

- [ ] **Step 6: Add a generic-branch listing test to `scripts/test.sh`** — the mock server serves whatever archives exist in the assets dir. After the existing `8.1.99` EOL assertions, extend the fixture with a hypothetical next branch to prove listing follows the snapshot, not the code. Immediately after `cp "$TEMP_DIR/assets/$ARCHIVE_NAME" "$TEMP_DIR/assets/$EOL_ARCHIVE_NAME"` add:

```bash
FUTURE_ARCHIVE_NAME="php-9.0.1-cli-macos-aarch64.tar.gz"
cp "$TEMP_DIR/assets/$ARCHIVE_NAME" "$TEMP_DIR/assets/$FUTURE_ARCHIVE_NAME"
```

update the `shasum` line to include `"$FUTURE_ARCHIVE_NAME"`, and after the `8.1.99` listing check add:

```bash
# A future branch appears in listings the moment the snapshot maintains it.
if grep -Fx "9.0.1" <<< "$AVAILABLE_VERSIONS"; then
  echo "Unmaintained future branch was unexpectedly listed." >&2
  exit 1
fi
ORIGINAL_POLICY="$(cat "$PROJECT_ROOT/lib/policy.lua")"
restore_policy() { printf '%s\n' "$ORIGINAL_POLICY" > "$PROJECT_ROOT/lib/policy.lua"; }
printf 'return {\n    maintained = { "8.2", "8.3", "8.4", "8.5", "9.0" },\n}\n' > "$PROJECT_ROOT/lib/policy.lua"
FUTURE_VERSIONS="$(mise ls-remote php)"
restore_policy
grep -Fx "9.0.1" <<< "$FUTURE_VERSIONS"
```

- [ ] **Step 7: Run** `./scripts/test.sh` — expect "Plugin contract test passed." (check the mock server exposes the new archive; if the server only lists archives found on disk this works as-is — read `test/mock_server.py` and if it hardcodes release JSON, extend its fixture list with `9.0.1` the same way `8.1.99` is included).
- [ ] **Step 8: Commit** — `git add lib/policy.lua lib/releases.lua hooks/parse_legacy_file.lua scripts/generate-policy-lua scripts/test.sh test/mock_server.py && git commit -m "feat: derive maintained branches from support snapshot in plugin"`

### Task 2: mise-php — require policy.lua regeneration in admitted diffs

Unattended propagation: when the consumer's admitted patch updates `support-snapshot.json`, admission must also require a matching `lib/policy.lua` in the same diff, or a stale filter ships silently.

**Files:**
- Modify: `mise-php/autorelease/admission.py` (inside the `path == "support-snapshot.json"` branch of the diff validator, around line 339)
- Test: `mise-php/test/test_autorelease.py`

**Interfaces:**
- Consumes: `lib/policy.lua` format from Task 1 (`maintained = { "<branch>", ... }`).

- [ ] **Step 1: Write the failing test** in `mise-php/test/test_autorelease.py` (match the file's existing fixture-building style — read its existing diff-admission test first and clone its setup):

```python
def test_snapshot_diff_requires_matching_policy_lua(self):
    # Build a valid admitted diff that touches support-snapshot.json but
    # leaves lib/policy.lua stale; admission must reject it.
    ...  # use the file's existing helper that assembles a passing diff case,
         # change maintainedBranches to ["8.3", "8.4", "8.5", "8.6"],
         # keep lib/policy.lua listing the old branches
    with self.assertRaises(admission.AdmissionError) as ctx:
        admission.validate_patch(...)  # same call the sibling test makes
    self.assertIn("policy.lua", str(ctx.exception))
```

(The exact helper names must be copied from the neighboring snapshot test in that file — mirror it exactly; the deliverable is: stale `lib/policy.lua` + changed snapshot ⇒ `AdmissionError` mentioning `policy.lua`.)

- [ ] **Step 2: Run it** — `python3 -m unittest test.test_autorelease -k policy_lua` — expect FAIL (no error raised).
- [ ] **Step 3: Implement** — in `admission.py`, inside the `if path == "support-snapshot.json":` branch after the snapshot JSON is parsed, add:

```python
expected_policy_lines = [
    "-- Generated by scripts/generate-policy-lua from support-snapshot.json.",
    "-- Do not edit by hand; regenerate when the snapshot changes.",
    "return {",
    "    maintained = {",
    *[f'        "{branch}",' for branch in snapshot.get("maintainedBranches", [])],
    "    },",
    "}",
]
policy_lua = repo / "lib" / "policy.lua"
if policy_lua.read_text().splitlines() != expected_policy_lines:
    raise AdmissionError("support snapshot changed without regenerating lib/policy.lua")
```

- [ ] **Step 4: Run the test** — expect PASS. Then run the full suite: `python3 -m unittest discover -s test -p 'test_*.py'`.
- [ ] **Step 5: Commit** — `git commit -am "feat: reject snapshot diffs with stale policy.lua"`

### Task 3: mise-php — unattended readiness-record merges (deadlock fix)

`autorelease-consumer.yml` creates a readiness PR touching `readiness/*` — a protected path — but `protected-controls.yml` has **no** automation exemption, so the required "Protected controls" check demands an exact-head owner review. Every consumer run therefore stalls on a human. Port php-bin's trusted-automation exemption pattern (`protected-controls.yml`, the `autorelease-events/*` branch) for readiness records.

**Files:**
- Modify: `mise-php/autorelease/admission.py` (add `validate_readiness_record`)
- Modify: `mise-php/.github/workflows/protected-controls.yml` (add exemption before the owner-approval fallback)
- Test: `mise-php/test/test_autorelease.py`

**Interfaces:**
- Produces: `admission.validate_readiness_record(record: dict) -> None` raising `AdmissionError` on any deviation from the shape produced by `consumer.readiness()` (`consumer.py:300-336`).

- [ ] **Step 1: Write the failing tests**:

```python
def test_validate_readiness_record_accepts_consumer_output(self):
    record = consumer.readiness(
        "new_patch:8.5.9",
        "a" * 40,
        "sha256:" + "b" * 64,
        "sha256:" + "c" * 64,
        "d" * 40,
        ["sha256:" + "e" * 64],
    )
    admission.validate_readiness_record(record)

def test_validate_readiness_record_rejects_tampering(self):
    record = consumer.readiness(
        "new_patch:8.5.9",
        "a" * 40,
        "sha256:" + "b" * 64,
        "sha256:" + "c" * 64,
        "d" * 40,
        ["sha256:" + "e" * 64],
    )
    for corrupt in (
        {**record, "ready": False},
        {**record, "state": "published"},
        {**record, "actionKey": "merge:now"},
        {**record, "extra": 1},
        {k: v for k, v in record.items() if k != "evidenceDigests"},
    ):
        with self.assertRaises(admission.AdmissionError):
            admission.validate_readiness_record(corrupt)
```

- [ ] **Step 2: Run** — expect FAIL with `AttributeError: ... no attribute 'validate_readiness_record'`.
- [ ] **Step 3: Implement** in `admission.py`:

```python
READINESS_RECORD_KEYS = {
    "schemaVersion", "actionKey", "state", "ready", "phpBinPolicyCommit",
    "policyDigest", "policyInvariantsDigest", "misePhpCommit",
    "evidenceDigests", "recordedAt",
}


def validate_readiness_record(record: Any) -> None:
    """Exact-shape check for records produced by consumer.readiness()."""
    if not isinstance(record, dict) or set(record) != READINESS_RECORD_KEYS:
        raise AdmissionError("readiness record has unexpected shape")
    if record["schemaVersion"] != 1 or record["state"] != "mise_ready" or record["ready"] is not True:
        raise AdmissionError("readiness record has invalid state")
    if not ACTION_KEY_RE.fullmatch(str(record["actionKey"])):
        raise AdmissionError("readiness record has invalid action key")
    for key in ("phpBinPolicyCommit", "misePhpCommit"):
        if not re.fullmatch(r"[0-9a-f]{40}", str(record[key])):
            raise AdmissionError(f"readiness record {key} is not an exact SHA")
    for key in ("policyDigest", "policyInvariantsDigest"):
        if not SHA256_RE.fullmatch(str(record[key])):
            raise AdmissionError(f"readiness record {key} is not a digest")
    digests = record["evidenceDigests"]
    if (
        not isinstance(digests, list)
        or not digests
        or digests != sorted(digests)
        or not all(isinstance(item, str) and SHA256_RE.fullmatch(item) for item in digests)
    ):
        raise AdmissionError("readiness record evidence digests are invalid")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", str(record["recordedAt"])):
        raise AdmissionError("readiness record timestamp is invalid")
```

- [ ] **Step 4: Run tests** — expect PASS; run the full unittest suite.
- [ ] **Step 5: Add the workflow exemption** — in `mise-php/.github/workflows/protected-controls.yml`, inside the inline Python after `if not protected: ... SystemExit(0)`, insert (mirroring php-bin's event exemption at `php-bin/.github/workflows/protected-controls.yml:225-260`, including its imports `base64`, `re`, `sys` and the `api_one` helper — copy `api_one` from php-bin verbatim):

```python
readiness_run = re.fullmatch(r"autorelease/readiness-(\d+)", head_ref)
if (
    len(protected) == 1
    and re.fullmatch(r"readiness/[A-Za-z0-9._-]+\.json", protected[0])
    and readiness_run
    and author == "github-actions[bot]"
    and head_repo.lower() == repo.lower()
):
    commit = api_one(f"repos/{repo}/commits/{head}")
    run = api_one(f"repos/{repo}/actions/runs/{readiness_run.group(1)}")
    content = api_one(f"repos/{repo}/contents/{protected[0]}?ref={head}")
    try:
        decoded = base64.b64decode(content["content"].replace("\n", ""), validate=True)
        record = json.loads(decoded)
        validate_readiness_record(record)
    except (KeyError, ValueError, json.JSONDecodeError, AdmissionError) as error:
        print(f"Invalid readiness record: {error}", file=sys.stderr)
        raise SystemExit(1) from error
    expected_filename = record["actionKey"].translate(str.maketrans({":": "-", "/": "-"})) + ".json"
    direct_parent = [parent.get("sha") for parent in commit.get("parents", [])] == [base]
    trusted_run = (
        protected[0] == f"readiness/{expected_filename}"
        and run.get("path") == ".github/workflows/autorelease-consumer.yml"
        and run.get("event") in {"schedule", "workflow_dispatch"}
        and run.get("head_branch") == "main"
        and run.get("status") == "in_progress"
    )
    if direct_parent and trusted_run:
        print(f"Protected readiness record approved from trusted consumer run {run['id']}.")
        raise SystemExit(0)
    print("Readiness record did not come from a trusted in-progress consumer run.", file=sys.stderr)
    raise SystemExit(1)
```

The step also needs the workflow's env to expose `BASE_SHA`, `HEAD_REF`, `HEAD_REPOSITORY`, `PR_AUTHOR` (copy the exact `env:` keys from php-bin's protected-controls step) and the inline Python needs `head_ref`, `head_repo`, `author`, `base` variables plus `sys.path.insert(0, ".")` / `from autorelease.admission import AdmissionError, validate_readiness_record` — mirror how php-bin's script imports `validate_completed_event_record` from `autorelease.control`.

- [ ] **Step 6: Static check** — `python3 -c "import yaml"` is unavailable; instead run `ruby -ryaml -e 'YAML.load_file(".github/workflows/protected-controls.yml")'` to confirm the YAML parses, then `./scripts/test.sh`.
- [ ] **Step 7: Commit** — `git commit -am "feat: admit trusted automation readiness records without owner review"`

### Task 4: php-bin — remove 8.x assumptions from the build/verify path

`scripts/build.sh:93-97` special-cases `^8\.[2-5]$`. Everything else (ACTION_KEY_RE, seal, events) is already major-agnostic — verified. A `new_branch` patch adds `expected-modules/<branch>.txt` (unprotected path — admissible by the runtime agent).

**Files:**
- Modify: `php-bin/scripts/build.sh:93-97`
- Test: `php-bin/tests/test_autorelease.py` (plan admission for future branches)

- [ ] **Step 1: Fix build.sh** — replace:

```bash
  PHP_MINOR="${PHP_VERSION%.*}"
  if [[ "$PHP_VERSION" =~ ^8\.[2-5]$ ]]; then
    PHP_MINOR="$PHP_VERSION"
  fi
```

with:

```bash
  PHP_MINOR="${PHP_VERSION%.*}"
  if [[ "$PHP_VERSION" =~ ^[0-9]+\.[0-9]+$ ]]; then
    PHP_MINOR="$PHP_VERSION"
  fi
```

- [ ] **Step 2: Write the future-branch admission test** in `php-bin/tests/test_autorelease.py` — clone the file's existing `validate_plan` happy-path test (the one using `new_patch:8.5.9`) and parameterize:

```python
def test_future_branch_action_keys_admitted(self):
    for key in ("new_patch:8.6.1", "new_patch:9.0.1", "new_branch:8.6",
                "new_branch:9.0", "branch_eol:8.2:2026-12-31"):
        self.assertIsNotNone(control.ACTION_KEY_RE.fullmatch(key), key)
```

- [ ] **Step 3: Run** — `python3 -m unittest tests.test_autorelease -k future_branch` — expect PASS (regex already generic; this is a regression pin, not TDD red).
- [ ] **Step 4: Run** `./scripts/test.sh` (full php-bin gate).
- [ ] **Step 5: Commit** — `git commit -am "fix: accept any maintained branch in stage-4 module comparison"`

---

## Phase 2 — Verified defects and authority holes

### Task 5: mise-php — fix the dead secret-scanner arm

`admission.py:337`: `r"...|github_pat_|\\bsk-[A-Za-z0-9_-]{20,}"` — `\\b` inside a raw string is literal backslash+b, so the `sk-` arm never matches. php-bin's `control.py:65-70` has it right.

**Files:**
- Modify: `mise-php/autorelease/admission.py:337`
- Test: `mise-php/test/test_autorelease.py`

- [ ] **Step 1: Failing test** (drive through the module-level regex so the test doesn't need a full diff fixture — extract the pattern to a module constant first, matching php-bin's `SECRET_PATTERNS` style):

```python
def test_secret_scanner_catches_sk_tokens(self):
    self.assertIsNotNone(admission.SECRET_RE.search("key = sk-" + "a" * 24))
    self.assertIsNotNone(admission.SECRET_RE.search("github_pat_x"))
    self.assertIsNone(admission.SECRET_RE.search("task-" + "a" * 24))
```

- [ ] **Step 2: Run** — expect FAIL (`SECRET_RE` missing).
- [ ] **Step 3: Implement** — near `ACTION_KEY_RE` add:

```python
SECRET_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    r"|github_pat_"
    r"|\bsk-[A-Za-z0-9_-]{20,}"
)
```

and replace the inline `re.search(r"-----BEGIN ...", text)` at line 337 with `SECRET_RE.search(text)`.

- [ ] **Step 4: Run** — sk-token test passes; full suite passes.
- [ ] **Step 5: Commit** — `git commit -am "fix: repair secret scanner word boundary for sk tokens"`

### Task 6: Both repos — protect the gate harness, regenerate CODEOWNERS

The admitted runtime agent can currently edit `scripts/test.sh`, `tests/**`, `scripts/build.sh`, `scripts/package.sh`, `scripts/compare-modules.sh` in php-bin (all return `path_is_protected(...) == False`), i.e. it can rewrite the very gates that admit it. CODEOWNERS has also drifted (missing `/scripts/dispatch-pr-checks`, `/scripts/serve-autorelease-artifact`, `/scripts/verify-autorelease-system`).

Ordering caution: protecting `tests/*` means unattended patches can never edit tests — Task 4 already made the test suite branch-generic, so `new_branch`/`branch_eol` need no test edits. Verify that holds before protecting.

**Files:**
- Modify: `php-bin/autorelease/protected-paths.json` (add `scripts/test.sh`, `scripts/build.sh`, `scripts/package.sh`, `scripts/compare-modules.sh`, `scripts/check-public-language.sh`, `tests/*`)
- Modify: `php-bin/.github/CODEOWNERS`
- Modify: `mise-php/autorelease/protected-paths.json` (add `scripts/test.sh`, `scripts/check-public-language.sh`, `test/*`, `scripts/consume-php-policy`, `scripts/generate-policy-lua`)
- Modify: `mise-php/.github/CODEOWNERS`
- Test: `php-bin/tests/test_autorelease.py`, `mise-php/test/test_autorelease.py`

- [ ] **Step 1: Failing test, php-bin**:

```python
def test_gate_harness_paths_are_protected(self):
    for path in ("scripts/test.sh", "scripts/build.sh", "scripts/package.sh",
                 "scripts/compare-modules.sh", "scripts/check-public-language.sh",
                 "tests/test_autorelease.py"):
        self.assertTrue(control.path_is_protected(path), path)

def test_codeowners_covers_every_protected_script(self):
    patterns = json.loads(pathlib.Path("autorelease/protected-paths.json").read_text())["patterns"]
    codeowners = pathlib.Path(".github/CODEOWNERS").read_text()
    for pattern in patterns:
        if "*" not in pattern:
            self.assertIn(f"/{pattern} ", codeowners, pattern)
```

- [ ] **Step 2: Run** — expect FAIL.
- [ ] **Step 3: Implement** — append the new patterns to `php-bin/autorelease/protected-paths.json` `patterns` array; add the missing exact-path lines to `.github/CODEOWNERS` using the same `@owner` as its existing lines (read the file; every line follows `/path @bigpixelrocket-owner-handle`). Add lines for every non-glob pattern currently missing, including the three drifted scripts.
- [ ] **Step 4: Run** php-bin suite + `./scripts/test.sh`.
- [ ] **Step 5: Repeat for mise-php** — same test shape against `admission`'s protected checker (`admission.py` exposes the `protected()`/pattern logic — mirror how its existing protected-path test calls it), same JSON+CODEOWNERS edits with mise-php's path list from **Files** above.
- [ ] **Step 6: Sanity-check unattended flows still admissible** — run existing seal/admission tests in both repos; the runtime patch surface for `new_patch` (`downloads/`-adjacent build inputs, `expected-modules/*`, `support-policy.json` special case) must not intersect the new protections. `python3 -m unittest discover` in both repos.
- [ ] **Step 7: Commit (each repo)** — `git commit -am "fix: protect gate harness scripts and tests from admitted patches"`

### Task 7: mise-php — restore validator parity with php-bin

mise-php's `scripts/validate-structured-output-schemas` lost php-bin's non-scalar-`const` rejection and the schema↔constants cross-check; consequently `schemas/implementation-plan.schema.json` carries an array `const` (line ~75) and an unpatterned `actionKey` (line ~8) that php-bin's stricter validator would reject.

**Files:**
- Modify: `mise-php/scripts/validate-structured-output-schemas` (port the two checks from `php-bin/scripts/validate-structured-output-schemas:54-55` and `:82-105`, adjusted to mise-php's schema/constants module names)
- Modify: `mise-php/schemas/implementation-plan.schema.json` (replace the array `const` with `items`+`enum` the way php-bin's plan schema does; add `"pattern"` to `actionKey` matching `ACTION_KEY_RE`'s source with anchors)
- Test: the validator script itself is the test — it runs in `scripts/test.sh`

- [ ] **Step 1:** Port the checks (copy php-bin's code blocks; adjust import paths — mise-php constants live in `autorelease/admission.py`/`consumer.py`).
- [ ] **Step 2:** Run `./scripts/validate-structured-output-schemas` — expect FAIL on the two schema defects.
- [ ] **Step 3:** Fix the schema (array const → per-item enum; actionKey pattern anchored `^...$` — derive by copying the regex source string from `admission.py` and verifying with `python3 -c` that both agree on `new_patch:9.0.1`).
- [ ] **Step 4:** Run `./scripts/test.sh` — pass.
- [ ] **Step 5: Commit** — `git commit -am "fix: restore schema validator parity with php-bin"`

---

## Phase 3 — Structural verification instead of text-grep

### Task 8: php-bin — extract merge-admission check assertions into one script

Four hand-written jq assertion blocks (watch.yml:277-278, watch.yml:360-361, implement.yml:398+502, publish.yml:361) drifted: watch asserts both "Script checks" and "Protected controls" buckets; implement/publish assert only "Script checks". The implement/publish divergence is *currently required* (sealed patches legitimately touch protected `support-policy.json`, admitted by seal verification, so their protected-controls bucket may be red) — make that divergence declared, not accidental.

**Files:**
- Create: `php-bin/scripts/assert-admission-checks`
- Modify: `php-bin/.github/workflows/autorelease-watch.yml`, `autorelease-implement.yml`, `autorelease-publish.yml` (replace 4 inline blocks + wire the new script), `php-bin/autorelease/protected-paths.json` (+ CODEOWNERS via Task 6's sync test)
- Modify: `mise-php/scripts/` gets the same script (Task 12 sync manifest covers byte-parity); replace the jq assert in `autorelease-consumer.yml`
- Test: `php-bin/tests/test_autorelease.py` runs the script against fixture JSON

- [ ] **Step 1: Write the script** — `php-bin/scripts/assert-admission-checks`, mode 0755:

```bash
#!/usr/bin/env bash
# Asserts dispatch-pr-checks output shows every required admission check
# passing. --require-protected-controls is used by flows whose PRs must not
# touch protected paths; sealed-patch flows omit it because sealed patches
# may edit support-policy.json under seal verification instead.
set -euo pipefail
require_protected="false"
checks_file=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --require-protected-controls) require_protected="true"; shift ;;
    --checks) checks_file="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -n "$checks_file" ]]
jq -e '[.[] | select(.name=="Script checks") | .bucket] == ["pass"]' "$checks_file" > /dev/null
if [[ "$require_protected" == "true" ]]; then
  jq -e '[.[] | select(.name=="Protected controls") | .bucket] == ["pass"]' "$checks_file" > /dev/null
fi
echo "Admission checks passed (protected controls required: $require_protected)."
```

- [ ] **Step 2: Test it** in `tests/test_autorelease.py`:

```python
def test_assert_admission_checks(self):
    ok = [{"name": "Script checks", "bucket": "pass"},
          {"name": "Protected controls", "bucket": "pass"}]
    missing_protected = [{"name": "Script checks", "bucket": "pass"}]
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp, "checks.json")
        path.write_text(json.dumps(ok))
        subprocess.run(["scripts/assert-admission-checks", "--checks", str(path),
                        "--require-protected-controls"], check=True)
        path.write_text(json.dumps(missing_protected))
        subprocess.run(["scripts/assert-admission-checks", "--checks", str(path)], check=True)
        result = subprocess.run(["scripts/assert-admission-checks", "--checks", str(path),
                                 "--require-protected-controls"], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
```

- [ ] **Step 3: Run test** — PASS.
- [ ] **Step 4: Replace the four inline blocks** — watch.yml's two sites call `./scripts/assert-admission-checks --require-protected-controls --checks <file>`; implement.yml's two and publish.yml's one call it without the flag. Keep each site's `<file>` argument as whatever JSON the surrounding step already produced. Replace mise-php's `jq -e '[.[] | select(.name=="Plugin contract")...` occurrences in `autorelease-consumer.yml` with a mise-php copy of the script whose required check name is parameterized: add `--check-name "Plugin contract"` support (default `"Script checks"`) — one more `case` arm and `--arg` in the jq filter:

```bash
jq -e --arg name "$check_name" '[.[] | select(.name==$name) | .bucket] == ["pass"]' "$checks_file" > /dev/null
```

- [ ] **Step 5:** Add `scripts/assert-admission-checks` to both repos' `protected-paths.json` + CODEOWNERS (Task 6's sync test enforces the latter).
- [ ] **Step 6:** Run both repos' `./scripts/test.sh`; `ruby -ryaml -e 'YAML.load_file(...)'` on each edited workflow.
- [ ] **Step 7: Commit (each repo)** — `git commit -am "refactor: unify merge admission check assertions in one script"`

### Task 9: php-bin — convert verify.py text assertions to structural checks

`verify.py` pins workflow *source text*: `release_workflow.count("current-operator.json") >= 3` (:634), `"Unattended mutation is paused" in watch_workflow` (:626), exact `cp .codex/...config.toml` strings (a07), jq literal formatting (:540-547), and `codex-action-contract.json`'s `expectedInvocations` counts string occurrences. These break on any refactor (including this plan's) without catching real regressions.

**Files:**
- Modify: `php-bin/autorelease/verify.py` (generalize `load_workflow` usage; rewrite the listed assertions)
- Modify: `php-bin/.github/codex-action-contract.json` + its checker if it counts strings (read `scripts/validate-codex-action-inputs` first)
- Test: `./scripts/verify-autorelease-system` (verify.py *is* the test)

- [ ] **Step 1:** Read `verify.py` assertions a00–a20 and list every assertion that greps YAML source text (the four above plus any found).
- [ ] **Step 2:** For each, rewrite against `load_workflow()` (existing ruby-backed parser at `verify.py:57-65`) — the structural form asserts on parsed steps. Pattern to follow (real example for :626):

```python
watch = load_workflow(".github/workflows/autorelease-watch.yml")
gate_steps = [
    step
    for job in watch["jobs"].values()
    for step in job.get("steps", [])
    if "unattendedMutation" in (step.get("run") or "")
]
require(gate_steps, "watch workflow must gate on the operator unattended state")
```

and for :634 (operator preconditions in publish):

```python
publish = load_workflow(".github/workflows/autorelease-publish.yml")
operator_steps = [
    step
    for job in publish["jobs"].values()
    for step in job.get("steps", [])
    if "current-operator.json" in (step.get("run") or "")
]
require(len(operator_steps) >= 2, "publish workflow must capture and assert operator state")
```

The invariant each assertion protects (operator pause honored; evidence captured; config copied before agent start) must be stated in the `require` message — assert presence and job placement, not byte counts.

- [ ] **Step 3:** If `expectedInvocations` in `codex-action-contract.json` is enforced by counting substrings, change the checker to count parsed workflow steps whose `uses:` matches the Codex action, and update the contract numbers to match reality per workflow.
- [ ] **Step 4:** Run `./scripts/verify-autorelease-system` — all acceptance checks pass.
- [ ] **Step 5:** Mutation-test one assertion: temporarily rename the operator step in a scratch copy of publish.yml and confirm the structural check fails, then revert.
- [ ] **Step 6: Commit** — `git commit -am "refactor: assert workflow structure instead of source text in verifier"`

### Task 10: mise-php — same conversion for its text asserts

`mise-php/test/test_autorelease.py:92-96` asserts jq literals in workflow source; completion-criteria IDs are authored as jq string literals 3× in `autorelease-consumer.yml` while php-bin has a `CRITERIA` table in `scripts/prepare-agent-task:13-80`.

**Files:**
- Create: `mise-php/scripts/prepare-agent-task` (port php-bin's, with mise-php's criteria IDs — copy the exact IDs from the three jq literals in `autorelease-consumer.yml`)
- Modify: `mise-php/.github/workflows/autorelease-consumer.yml` (replace the three inline criteria constructions with `./scripts/prepare-agent-task` calls, same argument style as php-bin's implement workflow uses)
- Modify: `mise-php/test/test_autorelease.py:92-96` (assert against the script's emitted JSON, not workflow source text)

- [ ] **Step 1:** Read `php-bin/scripts/prepare-agent-task` fully; read the three criteria sites in `autorelease-consumer.yml`.
- [ ] **Step 2:** Write `mise-php/scripts/prepare-agent-task` mirroring php-bin's structure with mise-php's criteria table.
- [ ] **Step 3:** Failing test: rewrite `test_autorelease.py:92-96` to run `./scripts/prepare-agent-task` for each action kind and assert the criteria IDs in its JSON output (exact IDs copied from the current jq literals).
- [ ] **Step 4:** Wire the workflow; `ruby -ryaml` parse check; `./scripts/test.sh`.
- [ ] **Step 5:** Add `scripts/prepare-agent-task` to mise-php `protected-paths.json` (+ CODEOWNERS).
- [ ] **Step 6: Commit** — `git commit -am "refactor: emit agent task criteria from one script"`

---

## Phase 4 — Transaction recovery (publish atomicity)

### Task 11: php-bin — resumable post-publish event record

`autorelease-publish.yml` publishes the immutable release (:281-291) then opens a separate event-record PR (:345-369); a failure between the two leaves a live release with no completed event, and the notify job (:406-444) keys on job result, screaming "critical" even when the release itself succeeded. The watcher already owns a trusted-automation record pattern (`autorelease/eol-complete-*` branches). Extend the watcher to detect *published release missing its completed event record* and file the record itself.

**Files:**
- Modify: `php-bin/autorelease/control.py` (`watch_decision` — new decision branch)
- Modify: `php-bin/.github/workflows/autorelease-watch.yml` (route the new decision to the same record-PR steps used for eol-complete; branch name `autorelease/event-<run_id>` matches the existing protected-controls exemption which already accepts `autorelease/(event|eol-complete)-<run>` — **but** its `expected_workflow` maps `event-` to publish.yml, so extend that mapping: watcher-recovered records also arrive on `eol-complete`-style branches; simplest correct move: reuse the `eol-complete` branch prefix for recovery records, which protected-controls already trusts from watch.yml with `schedule`/`workflow_dispatch` events)
- Test: `php-bin/tests/test_autorelease.py`

- [ ] **Step 1: Failing test** — read `watch_decision`'s existing tests, then add:

```python
def test_watch_flags_published_release_missing_event_record(self):
    # Evidence shows tag 8.5.9 published; event store has no completed
    # new_patch:8.5.9 record; watcher must decide to file the record,
    # not to start a new release.
    decision = control.watch_decision(...)  # mirror the sibling test's fixtures,
                                            # with release present + record absent
    self.assertEqual(decision["action"], "record_completed_event")
    self.assertEqual(decision["actionKey"], "new_patch:8.5.9")
```

(The exact fixture shape comes from the neighboring `watch_decision` tests — the deliverable: release-exists-and-record-missing ⇒ `record_completed_event`, ranked before any new-release decision.)

- [ ] **Step 2: Run** — FAIL (unknown action).
- [ ] **Step 3: Implement** the branch in `watch_decision` (before new-release selection): if evidence proves a published tag whose action key has no completed event record, return `{"action": "record_completed_event", "actionKey": ...}`.
- [ ] **Step 4:** Wire watch.yml: route `record_completed_event` through the existing eol-complete record steps (same `./autorelease/control.py` event-record invocation publish uses, same PR/merge/exemption path on an `autorelease/eol-complete-<run_id>` branch). The routing change lands in Task 13's extracted router — if executing in order, add it to the router table there; if this task runs first, add a plain `elif` now and migrate in Task 13.
- [ ] **Step 5:** Re-key the publish notify job on transaction state: replace its `if: failure()` (or result-based condition) so it distinguishes "release not published" (critical) from "release published, record pending — watcher will recover" (warning). Concretely: publish writes `autorelease-run/transaction.json` with `{"released": true/false}` after the release step; notify reads it via `actions/download-artifact` and picks the message. Keep the message wording compliant with `check-public-language.sh`.
- [ ] **Step 6:** `./scripts/test.sh`; `ruby -ryaml` parse of watch.yml + publish.yml.
- [ ] **Step 7: Commit** — `git commit -m "feat: recover missing event records from the watcher" && git commit` (split: control.py+tests as `feat:`, workflow wiring as separate `feat:` commit if both large).

---

## Phase 5 — Dedup, dead code, hygiene

### Task 12: Cross-repo shared-file sync gate

~20 files are duplicated across repos; 15 have drifted silently. Declare the intended-identical set and gate on it where the network exists (the consumer workflow already fetches php-bin at an exact commit).

**Files:**
- Create: `mise-php/autorelease/shared-files.json` — list of repo-relative paths intended byte-identical with php-bin (start with: `scripts/dispatch-pr-checks`, `scripts/assert-admission-checks`, `scripts/check-public-language.sh`, plus any file the review found byte-identical today; **exclude** legitimately divergent files)
- Modify: `mise-php/.github/workflows/autorelease-consumer.yml` — in the preflight job (where `current-support-policy.json` is fetched), add a step fetching each shared file at the pinned php-bin commit and comparing digests:

```bash
jq -r '.paths[]' autorelease/shared-files.json | while read -r path; do
  gh api "repos/bigpixelrocket/php-bin/contents/$path?ref=$PHP_BIN_COMMIT" \
    --jq .content | tr -d '\n' | base64 -d > "$RUNNER_TEMP/shared-file"
  if ! cmp -s "$RUNNER_TEMP/shared-file" "$path"; then
    echo "Shared file drifted from php-bin: $path" >&2
    exit 1
  fi
done
```

- Test: `mise-php/test/test_autorelease.py` — `shared-files.json` parses, is sorted, every listed path exists.

- [ ] **Step 1:** Diff the candidate shared files between repos (`diff php-bin/scripts/dispatch-pr-checks mise-php/scripts/dispatch-pr-checks` etc.); byte-sync the ones that should match (copy php-bin's canonical version over mise-php's), listing each in `shared-files.json`.
- [ ] **Step 2:** Failing test for manifest shape; implement; PASS.
- [ ] **Step 3:** Add the workflow step; `ruby -ryaml` parse; `./scripts/test.sh` in mise-php.
- [ ] **Step 4: Commit** — `git commit -am "feat: gate consumer runs on shared-file parity with php-bin"`

### Task 13: php-bin — extract the watch dispatch and operator gate

`watch.yml:211-378` is a 168-line if/elif that silently `exit 0`s on unrouted action combinations (e.g. `repair` with `editsRequired:false`); the operator pause gate is inlined 7× in 3 shapes while `control.mutation_allowed()` sits unreachable; `tr ':/' '--'` filename mapping has 8 definitions.

**Files:**
- Modify: `php-bin/autorelease/control.py` — add `route_watch_action(decision: dict) -> dict` returning `{"route": "<workflow-step-id>", "actionKey": ...}` and raising `ControlError` on unrouted combinations; add CLI subcommands `route-watch-action`, `operator-gate` (wraps `mutation_allowed`), `action-filename` (wraps the existing `str.maketrans` mapping)
- Modify: `php-bin/.github/workflows/autorelease-watch.yml` — the dispatch becomes: call `./autorelease/control.py route-watch-action` once, then a short `case "$route" in ... esac` with an explicit `*) echo "unrouted action" >&2; exit 1` default
- Modify: all 7 operator-gate inline sites (watch/implement/publish) — replace with `./autorelease/control.py operator-gate --operator-file <file>`
- Modify: all 8 `tr ':/' '--'` sites — replace with `"$(./autorelease/control.py action-filename "$ACTION_KEY")"` (including mise-php's copies; its Python sites import the one helper from `consumer.py`, which drops the duplicated `ACTION_KEY_RE` in `admission.py` by importing it from `consumer`)
- Test: `php-bin/tests/test_autorelease.py`

- [ ] **Step 1: Failing tests**:

```python
def test_route_watch_action_covers_every_decision(self):
    # One assertion per legal decision shape, plus:
    with self.assertRaises(control.ControlError):
        control.route_watch_action({"action": "repair", "editsRequired": False})

def test_action_filename(self):
    self.assertEqual(control.action_filename("branch_eol:8.2:2026-12-31"),
                     "branch_eol-8.2-2026-12-31.json")

def test_operator_gate_blocks_paused_state(self):
    self.assertTrue(control.mutation_allowed({"unattendedMutation": "enabled"}))
    self.assertFalse(control.mutation_allowed({"unattendedMutation": "paused"}))
```

(Adjust `mutation_allowed`'s exact signature to what `control.py:1030` already defines — wire, don't rewrite.)

- [ ] **Step 2:** Run — FAIL on the new names.
- [ ] **Step 3:** Implement the three functions/subcommands; enumerate every branch of the current watch.yml:211-378 dispatch into `route_watch_action`'s table, with `ControlError` for anything unrouted (this converts today's silent `exit 0` holes into loud failures — enumerate the legal no-op decisions explicitly as `{"route": "none"}` so genuinely idle runs stay green).
- [ ] **Step 4:** Rewire the three workflows and mise-php sites; `ruby -ryaml` parse all; both `./scripts/test.sh` gates.
- [ ] **Step 5: Commit** — `refactor: route watch actions through deterministic control table` (php-bin), `refactor: reuse canonical action filename helper` (mise-php).

### Task 14: Both repos — dead code, dead schemas, hygiene sweep

**Files (php-bin):**
- Delete: `schemas/autorelease-event.schema.json`, `schemas/policy-invariants.schema.json`, `schemas/support-policy.schema.json` (verify zero references first: `grep -rn "<name>" --exclude-dir=.build .`)
- Modify: `schemas/agent-completion-assessment.schema.json` — align its plan-fragment duplicate with the canonical plan schema (same constraints, or reference the shared definition the way sibling schemas do)
- Modify: `autorelease/control.py` — dedupe manifest-digest formula (extract `manifest_digest(captures) -> str` used by both `capture_evidence` and `indexed_captures`); use `COMMIT_SHA_RE` at the three inline re-spellings (:751, :845, :851); delete `retry_decision` and `audit_reconstruction` **only if** `grep -rn` shows no callers outside tests, else leave with a docblock stating the caller
- Modify: all 7 php-bin workflows — add top-level `defaults: run: shell: bash` (gives `pipefail` semantics per GitHub's bash invocation), drop the 4 no-op `permissions:` blocks re-declaring defaults, narrow the publish preflight job's permissions to `contents: read`
- Modify: `scripts/check-public-language.sh` — replace the rg-vs-grep dual scope with `git ls-files -z | xargs -0 grep` in both repos
- Modify: `ci.yml:27` — shellcheck glob covers extensionless scripts: `shellcheck scripts/*.sh scripts/dispatch-pr-checks scripts/assert-admission-checks` (list every extensionless bash script explicitly)
- Modify: `scripts/snapshot-github-admin-state:56-58` — import `canonical_json`/`sha256_bytes` from `autorelease.control` instead of reimplementing
- Modify: `scripts/serve-autorelease-artifact` — add a shutdown path (handle SIGTERM, exit cleanly)
- Modify: `scripts/test.sh` — write `.artifacts` under `${RUNNER_TEMP:-$(mktemp -d)}` instead of the working tree
- Modify: `scripts/lib.sh` — replace blanket `# shellcheck disable=SC2034` with per-line disables on the actually-unused vars

**Files (mise-php):**
- Delete: `autorelease-events/` dead directory + the consumer workflow's `--events autorelease-events` argument + `consumer.py`'s `event_incomplete` machinery (grep-verify no other callers)
- Modify: `autorelease/admission.py` — `from .consumer import ACTION_KEY_RE` replacing its local copy; change `fnmatch.fnmatch` (:75) to `fnmatch.fnmatchcase` (parity with `protected-controls.yml:84`)
- Modify: `schemas/implementation-plan.schema.json` + `AUTORELEASE.md:34-48` — delete the `notification` field nothing reads and the docs section describing the nonexistent notification subsystem
- Modify: `autorelease-consumer.yml:441` — merge job condition becomes `if: ${{ !cancelled() && (needs.validate.outputs.passed == 'true' || needs['validate-repair'].outputs.passed == 'true') }}` with `validate-repair` gaining the same named output `passed` as `validate` (stop keying on `.result`); fix the in-place artifact mutation at :415-416 by writing repaired artifacts to a fresh path
- Modify: workflows — same `defaults: run: shell: bash` sweep

- [ ] **Step 1:** For every deletion, run the grep proving zero references; paste the empty result into the commit message body.
- [ ] **Step 2:** Make the php-bin edits; run `./scripts/test.sh` + `shellcheck` on every touched script.
- [ ] **Step 3:** Make the mise-php edits; run `./scripts/test.sh`.
- [ ] **Step 4:** Run `./scripts/verify-autorelease-system` in php-bin — the Task 9 structural assertions must still pass after the workflow hygiene edits (this is the point of Task 9 landing first).
- [ ] **Step 5: Commits** — separate commits per concern: `chore: delete unreferenced schemas`, `refactor: dedupe digest and sha validation helpers`, `chore: enforce bash defaults and least privilege in workflows`, `fix: make repair merge condition survive skipped validate job`, etc.

### Task 15: php-bin — decompose control.py behind a façade

`control.py` is 1,269 lines with ~6 seams. Split into a package while keeping `autorelease/control.py` as the stable import surface (verify.py, tests, workflows all import/invoke it).

**Files:**
- Create: `php-bin/autorelease/_validation.py` (require/regex/digest primitives), `_admission.py` (validate_plan + seal_patch + verify_merge), `_state.py` (event/release state machines + watch/route decisions), `_evidence.py` (capture client + indexed_captures)
- Modify: `php-bin/autorelease/control.py` — imports + re-exports + `main()` CLI only; every existing public name still importable as `autorelease.control.<name>`
- Test: existing suite is the safety net — zero test-file edits allowed in this task

- [ ] **Step 1:** Move code verbatim (no behavior edits — this is the refactor-only commit), wire re-exports.
- [ ] **Step 2:** `python3 -m unittest discover` — all pass untouched.
- [ ] **Step 3:** `./scripts/test.sh` and `./scripts/verify-autorelease-system` — pass.
- [ ] **Step 4:** Confirm `autorelease/*` protected-paths glob covers the new files (it does — same directory).
- [ ] **Step 5: Commit** — `git commit -am "refactor: split control module behind stable facade"`

Also split `validate_plan`'s ~175-line body (control.py:546-719) into per-concern helpers (`_validate_plan_shape`, `_validate_plan_preconditions`, `_validate_plan_actions`) inside `_admission.py` in a **second** commit, still behavior-preserving, suite green.

---

## Phase 6 — Docs and end-to-end proof

### Task 16: Docs truth pass + full system verification

**Files:**
- Modify: `mise-php/AUTORELEASE.md:108` (drop the reference to nonexistent `docs/autorelease-verification.md` or create the file it promises), `AUTORELEASE.md:34-48` (done in Task 14 — verify)
- Modify: `php-bin/docs/repository-settings.md:70-72` (correct the snapshot output names to what `scripts/snapshot-github-admin-state` actually emits)
- Modify: both repos' `AUTORELEASE.md` — add a short "Unattended lifecycle" section documenting: new branch (any major/minor) requires zero human input end-to-end (agent patch adds `expected-modules/<branch>.txt`, policy + snapshot + `lib/policy.lua` regenerate, readiness/event records merge via trusted-automation exemptions); EOL stops new builds and delists the branch while all published releases remain installable exactly.
- [ ] **Step 1:** `markdownlint` on every touched `.md`.
- [ ] **Step 2:** php-bin: `./scripts/test.sh && ./scripts/verify-autorelease-system`. mise-php: `./scripts/test.sh`.
- [ ] **Step 3: Commit** — `docs: correct autorelease references and document unattended lifecycle`

### Task 17: Ship

- [ ] **Step 1:** Push both branches; open PRs (php-bin and mise-php) titled `fix: autorelease unattended hardening`; PR bodies summarize per-phase changes, no AI attribution.
- [ ] **Step 2:** Wait for functional checks ("Script checks" / "Plugin contract" + CI) to pass on both PRs. Note: these PRs touch protected paths, so "Protected controls" will demand owner review that the owner cannot self-approve — per standing approval: lift `enforce_admins`, squash-merge, restore `enforce_admins` immediately (both repos).
- [ ] **Step 3:** Reply to every review-bot finding on the PRs in friendly plain English (no em-dashes).
- [ ] **Step 4:** After merge, trigger `autorelease-e2e.yml` (php-bin) and `e2e.yml` (mise-php) via `gh workflow run`; confirm green.
- [ ] **Step 5:** Run `gh workflow run autorelease-watch.yml` once and confirm the watcher completes with a clean decision (no-op or legitimate action) with zero human gates.

---

## Self-review notes

- **Spec coverage:** every review finding maps to a task — verified defects (T3, T5, T6-drift, T8-drift), authority holes (T6), structural verifier regressions (T9, T10), duplication (T8, T10, T12, T13, T14), atomicity (T11), dead code/docs (T14, T16), file size (T15), unattended functional gaps (T1, T2, T3, T4, T11). The `scripts/consume-php-policy` unprotected-sibling finding is folded into T6's mise-php pattern list.
- **Known intentional divergence:** mise-php `expectedInvocations` 3 vs php-bin 4 stays divergent — excluded from T12's shared-file list, handled structurally in T9/T10.
- **Ordering constraints:** T4 (branch-generic tests) before T6 (protect tests/); T9 (structural asserts) before T13/T14 (workflow refactors that would break text asserts); T1 before T2 (policy.lua exists before admission requires it).
- **Fixture-dependent test bodies** (T2 step 1, T11 step 1) intentionally defer exact helper names to the sibling tests in the same file — the acceptance criterion in each is stated precisely; implementers must clone the adjacent test's setup rather than invent fixtures.
