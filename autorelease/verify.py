#!/usr/bin/env python3
"""Cross-repository production-control fixture verification (A00-A20)."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tarfile
import tempfile
import traceback
from typing import Any, Callable

from autorelease.control import (
    ControlError,
    action_filename,
    audit_reconstruction,
    canonical_json,
    classify_evidence,
    manifest_digest,
    mutation_allowed,
    notification_decision,
    path_is_protected,
    release_transition,
    seal_patch,
    sha256_bytes,
    sha256_file,
    transition_event,
    validate_plan,
    verify_merge,
    watch_decision,
)


PHP_ROOT = pathlib.Path(__file__).resolve().parents[1]
PIN_RE = re.compile(r"^\s*uses:\s*[^#\s]+@([0-9a-f]{40})(?:\s*#.*)?$", re.MULTILINE)
UNPINNED_RE = re.compile(r"^\s*uses:\s*[^#\s]+@(?![0-9a-f]{40}(?:\s|$))[^#\s]+", re.MULTILINE)
# Any Action published by this owner, or any reference to its credential, would bring a
# model back into a pipeline that is deterministic by design (A07).
MODEL_ACTION_PREFIX = "openai/"


def run(*args: str, cwd: pathlib.Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        cwd=cwd,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def load_workflow(path: pathlib.Path) -> dict[str, Any]:
    script = (
        "document = YAML.safe_load(File.read(ARGV.fetch(0)), aliases: true); "
        "STDOUT.write(JSON.generate(document))"
    )
    result = run("ruby", "-ryaml", "-rjson", "-e", script, str(path), cwd=PHP_ROOT)
    document = json.loads(result.stdout)
    assert_true(isinstance(document, dict), f"workflow is not an object: {path}")
    return document


def workflow_steps(document: dict[str, Any]) -> list[tuple[str, int, dict[str, Any]]]:
    """Return every (job name, position in job, step) triple of a parsed workflow.

    Acceptance checks assert on parsed structure so that reformatting a
    workflow cannot pass or fail a control it does not change.
    """
    return [
        (name, index, step)
        for name, job in (document.get("jobs") or {}).items()
        if isinstance(job, dict)
        for index, step in enumerate(job.get("steps") or [])
        if isinstance(step, dict)
    ]


def operator_gate_calls(run: str) -> list[str]:
    """Return every operator-gate invocation in a workflow step, one per line.

    The gate has two deliberate shapes. With `--require-enabled` the subcommand fails the
    job; without it the subcommand only prints the state and exits 0, so a hard site that
    loses the flag still reads like a gate while gating nothing. Callers therefore have to
    inspect the invocation itself, not merely the presence of the subcommand name.
    """
    return [line.strip() for line in run.splitlines() if "operator-gate" in line]


def credential_sites(node: Any, path: str) -> list[str]:
    """Return every path in a parsed workflow whose keys or values name a model credential.

    Both spellings once reached an agent: `openai-api-key` as an action input and
    `OPENAI_API_KEY` as an environment name. Either could be attached at the
    workflow, job, or step level, or interpolated straight into a command, so
    the whole parsed document is walked rather than one level of it.
    """
    if isinstance(node, dict):
        return [
            site
            for key, value in node.items()
            for site in ([f"{path}.{key}"] if names_credential(str(key)) else [])
            + credential_sites(value, f"{path}.{key}")
        ]
    if isinstance(node, list):
        return [site for index, item in enumerate(node) for site in credential_sites(item, f"{path}[{index}]")]
    return [path] if names_credential(str(node)) else []


def names_credential(text: str) -> bool:
    return "openai-api-key" in text.lower() or "openai_api_key" in text.lower()


def exact_head(repo: pathlib.Path) -> str:
    return run("git", "rev-parse", "HEAD", cwd=repo).stdout.strip()


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def assert_reject(callback: Callable[[], Any], contains: str | None = None) -> None:
    try:
        callback()
    except (ControlError, AssertionError) as error:
        if contains is not None:
            assert_true(contains in str(error), f"rejection did not contain {contains!r}: {error}")
        return
    raise AssertionError("unsafe input was accepted")


def init_repo(path: pathlib.Path, files: dict[str, str] | None = None) -> str:
    path.mkdir(parents=True)
    run("git", "init", "-q", cwd=path)
    run("git", "config", "user.name", "Fixture", cwd=path)
    run("git", "config", "user.email", "fixture@invalid", cwd=path)
    for name, body in (files or {"src.txt": "original\n"}).items():
        target = path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
    run("git", "add", ".", cwd=path)
    run("git", "commit", "-q", "-m", "fixture base", cwd=path)
    return exact_head(path)


FIXTURE_HEADS = {"phpBinHead": "a" * 40, "misePhpHead": "b" * 40}
FIXTURE_POLICY_DIGEST = "sha256:" + "c" * 64
# A supported-versions page in the reviewed table shape; `rows` maps each branch to
# its row class and security support end.
SUPPORT_ROW = (
    '<tr class="{state}">\n<td>\n<a href="/downloads.php?version={branch}">{branch}</a>\n</td>\n'
    "<td>1 Jan 2024</td>\n<td class=\"collapse-phone\"></td>\n<td>1 Jan 2025</td>\n"
    '<td class="collapse-phone"></td>\n<td>{until}</td>\n<td class="collapse-phone"></td>\n'
    "<td>Notes</td>\n</tr>\n"
)


def support_page(rows: dict[str, tuple[str, str]]) -> bytes:
    body = "".join(
        SUPPORT_ROW.format(state=state, branch=branch, until=until) for branch, (state, until) in rows.items()
    )
    return (
        '<table class="standard">\n<thead>\n<tr>\n<th>Branch</th>\n<th colspan="2">Initial Release</th>\n'
        '<th colspan="2">Active Support Until</th>\n<th colspan="2">Security Support Until</th>\n'
        '<th colspan="2">Notes</th>\n</tr>\n</thead>\n<tbody>\n' + body + "</tbody>\n</table>\n"
    ).encode()


def fixture_capture(
    directory: pathlib.Path,
    *,
    branch_feeds: dict[str, str],
    aggregate: str,
    page: bytes,
    releases: list[dict[str, Any]],
    rebuild: str = "",
    incomplete: list[str] | None = None,
) -> pathlib.Path:
    """Write one watcher capture set in the retained artifact layout and return its manifest.

    `directory` plays `autorelease-run/`: the manifest lives in `evidence/` and the
    watch decision beside it, exactly where the classifier and admission read them.
    """
    bodies = {
        "php_supported_versions": page,
        "php_release_feed": canonical_json({aggregate.split(".")[0]: {"version": aggregate}}),
        **{
            f"php_release_feed_{branch}": canonical_json({"version": version})
            for branch, version in branch_feeds.items()
        },
        "php_source_tags": canonical_json([]),
        "php_bin_releases": canonical_json(releases),
        "php_bin_state": canonical_json({"sha": "a" * 40}),
        "mise_php_releases": canonical_json([]),
        "mise_php_state": canonical_json({"sha": "b" * 40}),
    }
    raw = directory / "evidence/raw"
    raw.mkdir(parents=True)
    captures = []
    for capture_id, body in bodies.items():
        (raw / f"{capture_id}.body").write_bytes(body)
        captures.append(
            {
                "captureId": capture_id,
                "status": 200,
                "digest": sha256_bytes(body),
                "bodyPath": f"raw/{capture_id}.body",
            }
        )
    manifest = {
        "schemaVersion": 1,
        "capturedAt": "2026-09-28T00:00:00Z",
        "captures": captures,
        "manifestDigest": manifest_digest(captures),
    }
    manifest_path = directory / "evidence/evidence-manifest.json"
    manifest_path.write_bytes(canonical_json(manifest))
    decision = {
        "schemaVersion": 1,
        "trigger": "evidence_changed",
        "manifestDigest": manifest["manifestDigest"],
        "incompleteActions": sorted(incomplete or []),
        "action": "none",
        "actionKey": "",
        "rebuildActionKey": rebuild,
        "classify": True,
    }
    (directory / "watch-decision.json").write_bytes(canonical_json(decision))
    return manifest_path


def classify_fixture(manifest_path: pathlib.Path, events: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return classify_evidence(
        manifest_path,
        {**FIXTURE_HEADS, "supportPolicyDigest": FIXTURE_POLICY_DIGEST},
        events or [],
        ["8.4", "8.5"],
    )


def admit(plan: dict[str, Any], manifest_path: pathlib.Path, pending_rebuild: str | None = None) -> dict[str, Any]:
    return validate_plan(plan, manifest_path, FIXTURE_HEADS, FIXTURE_POLICY_DIGEST, set(), pending_rebuild)


MAINTAINED_PAGE = {"8.4": ("stable", "31 Dec 2028"), "8.5": ("stable", "31 Dec 2029")}
PUBLISHED = [{"tag_name": "8.5.9", "draft": False, "prerelease": False}, {"tag_name": "8.4.20"}]


def fixture_admission_inputs(directory: pathlib.Path, action: str = "new_patch") -> dict[str, Any]:
    """Classify one synthetic capture whose evidence calls for `action`."""
    feeds = {"8.4": "8.4.20", "8.5": "8.5.9"}
    page = dict(MAINTAINED_PAGE)
    aggregate = "8.5.9"
    rebuild = ""
    if action == "new_patch":
        feeds["8.5"] = aggregate = "8.5.10"
    elif action == "new_branch":
        page["8.6"] = ("stable", "31 Dec 2030")
        aggregate = "8.6.0"
    elif action == "branch_eol":
        page["8.4"] = ("eol", "31 Dec 2026")
    elif action == "recipe_rebuild":
        rebuild = "recipe_rebuild:8.5.9:1"
    manifest_path = fixture_capture(
        directory, branch_feeds=feeds, aggregate=aggregate, page=support_page(page), releases=PUBLISHED, rebuild=rebuild
    )
    return {
        "manifestPath": manifest_path,
        "plan": classify_fixture(manifest_path),
        # The watcher's deterministic selection, which a rebuild plan must name exactly.
        "pendingRebuild": rebuild or None,
    }


def admit_fixture(inputs: dict[str, Any]) -> dict[str, Any]:
    return admit(inputs["plan"], inputs["manifestPath"], inputs["pendingRebuild"])


class Verifier:
    def __init__(self, mise_root: pathlib.Path, php_sha: str, mise_sha: str, output: pathlib.Path):
        self.mise_root = mise_root.resolve()
        self.php_sha = php_sha
        self.mise_sha = mise_sha
        self.output = output.resolve()
        self.started = dt.datetime.now(dt.UTC)
        self.results: list[dict[str, Any]] = []
        self.evidence_dir = self.output / "evidence"

    def record(self, test_id: str, name: str, callback: Callable[[pathlib.Path], Any]) -> None:
        test_dir = self.evidence_dir / test_id
        test_dir.mkdir(parents=True, exist_ok=True)
        started = dt.datetime.now(dt.UTC)
        try:
            evidence = callback(test_dir)
            result = "passed"
            error = None
        except Exception as exception:  # report every acceptance failure
            result = "failed"
            evidence = []
            error = f"{exception}\n{traceback.format_exc()}"
            (test_dir / "failure.txt").write_text(error)
        finished = dt.datetime.now(dt.UTC)
        self.results.append(
            {
                "id": test_id,
                "name": name,
                "result": result,
                "startedAt": started.isoformat(),
                "finishedAt": finished.isoformat(),
                "evidence": evidence if isinstance(evidence, list) else [evidence],
                "error": error,
            }
        )

    def a00(self, directory: pathlib.Path) -> list[str]:
        """The classifier is a pure function of the capture: same inputs, same plan bytes."""
        first = fixture_admission_inputs(directory / "first")
        second = fixture_admission_inputs(directory / "second")
        assert_true(
            canonical_json(first["plan"]) == canonical_json(second["plan"]),
            "the classifier produced different plans from identical captures",
        )
        admission = admit_fixture(first)
        (directory / "plan.json").write_bytes(canonical_json(first["plan"]))
        (directory / "admission.json").write_bytes(canonical_json(admission))
        return ["plan.json", "admission.json"]

    def a01(self, directory: pathlib.Path) -> list[str]:
        manifest = {"manifestDigest": "sha256:" + "a" * 64, "captures": [{"status": 200}]}
        result = watch_decision(manifest, manifest, [{"actionKey": "new_patch:8.5.8", "state": "complete"}], {"healthy": True})
        assert_true(result["trigger"] == "quiet" and result["classify"] is False, "quiet run woke the classifier")
        assert_true(notification_decision({"state": "complete"}, {"fingerprint": notification_decision({"state": "complete"}, None)["fingerprint"]})["action"] == "none", "quiet replay mutated notification")
        (directory / "decision.json").write_bytes(canonical_json(result))
        return ["decision.json"]

    def a02(self, directory: pathlib.Path) -> list[str]:
        inputs = fixture_admission_inputs(directory)
        result = admit_fixture(inputs)
        (directory / "admission.json").write_bytes(canonical_json(result))
        return ["evidence/evidence-manifest.json", "admission.json"]

    def a03(self, directory: pathlib.Path) -> list[str]:
        missing = fixture_admission_inputs(directory / "missing")
        (missing["manifestPath"].parent / "raw/php_release_feed_8.5.body").unlink()
        assert_reject(lambda: admit_fixture(missing), "missing")
        altered = fixture_admission_inputs(directory / "altered")
        (altered["manifestPath"].parent / "raw/php_release_feed_8.5.body").write_text("altered")
        assert_reject(lambda: admit_fixture(altered), "digest mismatch")
        # Evidence that proves the version exists while another captured feed names a
        # later patch on the same branch is stale: publishing it would ship an
        # intermediate release. The classifier waits; a plan that insists is rejected.
        proposed = fixture_admission_inputs(directory / "proposed")
        manifest_path = fixture_capture(
            directory / "superseded",
            branch_feeds={"8.4": "8.4.20", "8.5": "8.5.10"},
            aggregate="8.5.11",
            page=support_page(MAINTAINED_PAGE),
            releases=PUBLISHED,
        )
        assert_true(classify_fixture(manifest_path)["action"] == "no_change", "the classifier proposed a superseded patch")
        # The same 8.5.10 plan, cited against a capture that also names 8.5.11.
        assert_reject(lambda: admit(proposed["plan"], manifest_path), "superseded")
        fingerprint = sha256_bytes(b"bad-evidence-rejection")
        (directory / "fingerprint.txt").write_text(fingerprint + "\n")
        return ["fingerprint.txt"]

    def a04(self, directory: pathlib.Path) -> list[str]:
        actions = {}
        for action in ("new_patch", "new_branch", "branch_eol", "recipe_rebuild"):
            inputs = fixture_admission_inputs(directory / action, action)
            assert_true(inputs["plan"]["action"] == action, f"the classifier did not classify {action}")
            admit_fixture(inputs)
            actions[action] = inputs["plan"]["actionKey"]
        # The rebuild is selected deterministically, so the classifier can only confirm it.
        for pending in (None, "recipe_rebuild:8.5.9:2"):
            assert_reject(
                lambda pending=pending: admit_fixture({**inputs, "pendingRebuild": pending}),
                "not the selected rebuild",
            )
        # A due patch outranks a due rebuild.
        both = fixture_capture(
            directory / "patch-and-rebuild",
            branch_feeds={"8.4": "8.4.21", "8.5": "8.5.9"},
            aggregate="8.5.9",
            page=support_page(MAINTAINED_PAGE),
            releases=PUBLISHED,
            rebuild="recipe_rebuild:8.5.9:1",
        )
        assert_true(
            classify_fixture(both)["actionKey"] == "new_patch:8.4.21",
            "a due rebuild was classified ahead of a due patch",
        )
        (directory / "classifications.json").write_bytes(canonical_json(actions))
        return ["classifications.json"]

    def a05(self, directory: pathlib.Path) -> list[str]:
        inputs = fixture_admission_inputs(directory / "admission")
        admit_fixture(inputs)
        assert_true(inputs["plan"]["editsRequired"] is False, "no-edit patch requested implementation")
        assets = directory / "assets"
        assets.mkdir()
        (assets / "x").write_text("staged")
        digests = {"x": sha256_file(assets / "x")}
        transaction = release_transition({"state": "requested", "history": []}, "built", assets, digests)
        assert_true(transaction["state"] == "built", "release intent did not enter transaction")
        (directory / "transaction.json").write_bytes(canonical_json(transaction))
        return ["transaction.json"]

    def a06(self, directory: pathlib.Path) -> list[str]:
        """A failed check stops the run with retained logs; nothing retries or repairs it."""
        workflows = {
            "php-bin": PHP_ROOT / ".github/workflows/autorelease-implement.yml",
            "mise-php": self.mise_root / ".github/workflows/autorelease-consumer.yml",
        }
        for name, path in workflows.items():
            document = load_workflow(path)
            jobs = document.get("jobs", {})
            assert_true(
                not {"repair", "validate-repair"} & set(jobs),
                f"{name} still has a repair phase",
            )
            validation = jobs.get("validate", {})
            steps = [step for step in validation.get("steps") or [] if isinstance(step, dict)]
            assert_true(
                any("authoritative-checks.log" in (step.get("run") or "") for step in steps),
                f"{name} does not retain deterministic failure logs",
            )
            assert_true(
                any(
                    "status != 'passed'" in str(step.get("if") or "") and "exit 1" in (step.get("run") or "")
                    for step in steps
                ),
                f"{name} does not fail the run on a failed authoritative check",
            )
        notify = load_workflow(workflows["php-bin"]).get("jobs", {}).get("notify-failure", {})
        assert_true(
            (notify.get("permissions") or {}).get("issues") == "write"
            and any("notify-autorelease" in (step.get("run") or "") for step in notify.get("steps") or []),
            "a failed php-bin implementation does not raise the owner issue",
        )
        evidence = {name: sha256_file(path) for name, path in workflows.items()}
        (directory / "no-repair.json").write_bytes(canonical_json(evidence))
        return ["no-repair.json"]

    def a07(self, directory: pathlib.Path) -> list[str]:
        """No workflow in either repository invokes a model or can read a model credential."""
        observed = {}
        for name, root in {"php-bin": PHP_ROOT, "mise-php": self.mise_root}.items():
            for path in sorted((root / ".github/workflows").glob("*.yml")):
                document = load_workflow(path)
                actions = [
                    str(step.get("uses") or "")
                    for _job, _index, step in workflow_steps(document)
                    if str(step.get("uses") or "").startswith(MODEL_ACTION_PREFIX)
                ]
                sites = credential_sites(document, path.name)
                assert_true(not actions, f"{name}/{path.name} invokes a model action: {actions}")
                assert_true(not sites, f"{name}/{path.name} names a model credential: {sites}")
                observed[f"{name}/{path.name}"] = sha256_file(path)
            for leftover in (".codex", ".github/codex", ".github/codex-action-contract.json"):
                assert_true(not (root / leftover).exists(), f"{name} still carries {leftover}")
        (directory / "workflows.json").write_bytes(canonical_json(observed))
        return ["workflows.json"]

    def a08(self, directory: pathlib.Path) -> list[str]:
        protected_classes = [
            ".github/workflows/evil.yml",
            "schemas/autorelease-plan.schema.json",
            "autorelease/control.py",
            "autorelease/policy-invariants.json",
            "unadmitted.txt",
        ]
        rejected = []
        for index, path in enumerate(protected_classes):
            repo = directory / f"repo-{index}"
            base = init_repo(repo)
            target = repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("unsafe\n")
            plan = {"actionKey": "new_branch:8.6", "allowedPaths": {"php-bin": ["safe.txt"]}}
            expected = "unadmitted path" if path == "unadmitted.txt" else "protected path"
            assert_reject(
                lambda repo=repo, base=base, plan=plan, index=index: seal_patch(
                    repo, base, plan, directory / f"sealed-{index}"
                ),
                expected,
            )
            rejected.append(path)
        (directory / "rejected.json").write_bytes(canonical_json(rejected))
        return ["rejected.json"]

    def a09(self, directory: pathlib.Path) -> list[str]:
        repo = directory / "repo"
        base = init_repo(repo)
        (repo / "src.txt").write_text("coordinated\n")
        run("git", "add", "src.txt", cwd=repo)
        run("git", "commit", "-q", "-m", "validated autorelease", cwd=repo)
        head = run("git", "rev-parse", "HEAD", cwd=repo).stdout.strip()
        manifest = {
            "baseSha": base,
            "files": [{"path": "src.txt", "digest": sha256_file(repo / "src.txt"), "mode": "0o644"}],
        }
        checks = {"Script checks": "success"}
        preconditions = {"policy": "same"}
        assert_reject(lambda: verify_merge(repo, head, manifest, checks, preconditions, preconditions, [{"ready": False}]))
        readiness = [
            {"ready": True, "commit": "a" * 40, "repo": "php-bin"},
            {"ready": True, "commit": "b" * 40, "repo": "mise-php"},
        ]
        result = verify_merge(repo, head, manifest, checks, preconditions, preconditions, readiness)
        # php-bin files an event record under a name derived from the action key and
        # mise-php reads that record back by the same derivation. A disagreement on any
        # key form leaves one repository waiting on a file the other never wrote. This
        # goes through mise-php's own entry point rather than its source text, so a
        # differently written mapping that behaves identically still passes.
        # One fixture per form both alphabets admit; a new form belongs here.
        action_keys = [
            "new_patch:8.5.9",
            "new_branch:8.6",
            "branch_eol:8.2:2026-12-31",
            "recipe_rebuild:8.5.9:2",
            "repair:8.5.9:deadbeef",
            "source_unhealthy:deadbeef",
            "health_failed:deadbeef",
            "policy_failure:deadbeef",
            "auth_failure:deadbeef",
        ]
        for action_key in action_keys:
            mise_name = run(
                "./scripts/consume-php-policy", "action-filename", action_key, cwd=self.mise_root
            ).stdout.strip()
            assert_true(
                mise_name == action_filename(action_key),
                f"mise-php names {action_key} {mise_name}, php-bin names it {action_filename(action_key)}",
            )
        # The one asymmetry is deliberate: a quiet run files no event record, so mise-php
        # refuses to name a file for it rather than inventing one it will never read.
        quiet = run(
            "./scripts/consume-php-policy", "action-filename", "no_change:0123456789abcdef",
            cwd=self.mise_root, check=False,
        )
        assert_true(quiet.returncode != 0, "mise-php names a record file for a quiet run")
        # mise-php's byte-parity gate fails closed on the first step of every consumer
        # run when a shared file drifts, and only a human can re-sync its protected copy.
        # A shared file that either repository lets automation rewrite is therefore a
        # cross-repository stall, and neither repository's own tests can see it: each
        # checks the manifest against its own pattern list alone. The verdicts come from
        # mise-php's own admission module so a rewritten matcher still has to answer.
        shared_paths = json.loads((self.mise_root / "autorelease/shared-files.json").read_text())["paths"]
        assert_true(bool(shared_paths), "the shared-file manifest is empty, so it gates nothing")
        mise_protection = json.loads(
            run(
                "python3", "-c",
                "import json, sys; sys.path.insert(0, '.'); "
                "from autorelease.admission import protected; "
                "print(json.dumps({path: protected(path) for path in json.loads(sys.argv[1])}))",
                json.dumps(shared_paths),
                cwd=self.mise_root,
            ).stdout
        )
        for path in shared_paths:
            assert_true(path_is_protected(path), f"php-bin does not protect shared file {path}")
            assert_true(mise_protection[path], f"mise-php does not protect shared file {path}")
        (directory / "coordination.json").write_bytes(canonical_json(result))
        (directory / "action-filenames.json").write_bytes(
            canonical_json({key: action_filename(key) for key in action_keys})
        )
        (directory / "shared-file-protection.json").write_bytes(
            canonical_json(
                {path: {"php-bin": path_is_protected(path), "mise-php": mise_protection[path]} for path in shared_paths}
            )
        )
        return ["coordination.json", "action-filenames.json", "shared-file-protection.json"]

    def a10(self, directory: pathlib.Path) -> list[str]:
        releases = (self.mise_root / "lib/releases.lua").read_text()
        available = (self.mise_root / "hooks/available.lua").read_text()
        install = (self.mise_root / "hooks/pre_install.lua").read_text()
        policy = (self.mise_root / "lib/policy.lua").read_text()
        maintained = json.loads((self.mise_root / "support-snapshot.json").read_text())["maintainedBranches"]
        assert_true(
            "M.is_supported_version" in releases and "policy.maintained" in releases,
            "active shorthand boundary is not derived from the maintained policy",
        )
        assert_true(
            re.findall(r'"(\d+\.\d+)"', policy) == maintained,
            "the plugin maintained branch set is not the reviewed support snapshot",
        )
        assert_true("is_supported_version" in available, "EOL versions can be discovered")
        assert_true("is_exact_stable_version" in install, "historical exact installation is blocked")
        (directory / "eol-policy.txt").write_text("discovery=maintained-only\ninstallation=exact-stable-history\npublication=maintained-only\n")
        return ["eol-policy.txt"]

    def a11(self, directory: pathlib.Path) -> list[str]:
        """An unrecognised lifecycle page is an owner issue, never a guess."""
        inputs = fixture_admission_inputs(directory / "reviewed")
        admit_fixture(inputs)
        redesigned = fixture_capture(
            directory / "redesigned",
            branch_feeds={"8.4": "8.4.20", "8.5": "8.5.10"},
            aggregate="8.5.10",
            page=b"<main><h1>Supported Versions</h1><ul><li>8.5</li></ul></main>\n",
            releases=PUBLISHED,
        )
        plan = classify_fixture(redesigned)
        assert_true(
            plan["action"] == "blocked" and plan["actionKey"].startswith("source_unhealthy:"),
            "an unrecognised lifecycle page did not stop classification",
        )
        assert_true(
            plan["editsRequired"] is False and plan["releaseIntent"] is None,
            "a blocked plan authorizes work",
        )
        admit(plan, redesigned)
        registry = (PHP_ROOT / "autorelease/control.py").read_text()
        assert_true("supported-versions.php" in registry, "the authoritative source registry left the control surface")
        (directory / "blocked-plan.json").write_bytes(canonical_json(plan))
        return ["blocked-plan.json"]

    def a12(self, directory: pathlib.Path) -> list[str]:
        repo = directory / "repo"
        base = init_repo(repo)
        (repo / "src.txt").write_text("validated\n")
        run("git", "add", "src.txt", cwd=repo)
        run("git", "commit", "-q", "-m", "validated autorelease", cwd=repo)
        head = run("git", "rev-parse", "HEAD", cwd=repo).stdout.strip()
        manifest = {
            "baseSha": base,
            "files": [{"path": "src.txt", "digest": sha256_file(repo / "src.txt"), "mode": "0o644"}],
        }
        checks = {"Script checks": "success"}
        run("git", "commit", "--allow-empty", "-q", "-m", "post-validation mutation", cwd=repo)
        assert_reject(lambda: verify_merge(repo, head, manifest, checks, {}, {}), "head")
        run("git", "reset", "--hard", "-q", head, cwd=repo)
        result = verify_merge(repo, head, manifest, checks, {}, {})
        (repo / "extra.txt").write_text("unsealed\n")
        run("git", "add", "extra.txt", cwd=repo)
        run("git", "commit", "-q", "--amend", "--no-edit", cwd=repo)
        mutated_head = run("git", "rev-parse", "HEAD", cwd=repo).stdout.strip()
        assert_reject(lambda: verify_merge(repo, mutated_head, manifest, checks, {}, {}), "final diff")
        (directory / "merge.json").write_bytes(canonical_json(result))
        return ["merge.json"]

    def a13(self, directory: pathlib.Path) -> list[str]:
        workflows = list((PHP_ROOT / ".github/workflows").glob("*.yml")) + list((self.mise_root / ".github/workflows").glob("*.yml"))
        for path in workflows:
            body = path.read_text()
            assert_true(not UNPINNED_RE.search(body), f"workflow has unpinned Action: {path}")
        pins = json.loads((PHP_ROOT / ".github/autorelease-pins.json").read_text())
        e2e = PHP_ROOT / ".github/workflows/autorelease-e2e.yml"
        assert_true(
            pins["workflows"][".github/workflows/autorelease-e2e.yml"] == sha256_file(e2e),
            "reviewed production-parity workflow digest changed",
        )
        assert_true(
            not any(action.startswith(MODEL_ACTION_PREFIX) for action in pins["actions"]),
            "a model Action is still pinned",
        )
        e2e_document = load_workflow(e2e)
        # YAML 1.1 reads the bare `on` key as the boolean true.
        triggers = e2e_document.get("on") or e2e_document.get("true") or {}
        suites = triggers.get("workflow_dispatch", {}).get("inputs", {}).get("suite", {})
        assert_true(
            suites.get("options") == ["production-parity", "notification-canary", "live-canary"],
            "the e2e suites are not the reviewed deterministic set",
        )
        watch_document = load_workflow(PHP_ROOT / ".github/workflows/autorelease-watch.yml")
        workflow_permissions = watch_document.get("permissions", {})
        investigate = watch_document.get("jobs", {}).get("investigate", {})
        investigate_permissions = investigate.get("permissions", workflow_permissions)
        assert_true(
            isinstance(investigate_permissions, dict)
            and investigate_permissions.get("contents") == "read",
            "runtime classification does not have resolved read-only contents permission",
        )
        admin = PHP_ROOT / "docs/autorelease-admin-evidence.json"
        assert_true(admin.is_file(), "redacted administrator evidence is missing")
        evidence = json.loads(admin.read_text())
        assert_true(evidence.get("canary", {}).get("removed") is True, "admin canary was not removed")
        assert_true(evidence.get("protectionRestored") is True, "fixture bypass protection was not restored")
        assert_true(evidence.get("immutableReleasesEnabled") is True, "immutable releases were not enabled")
        shutil.copy(admin, directory / admin.name)
        (directory / "pins.json").write_bytes(canonical_json(pins))
        return [admin.name, "pins.json"]

    def a14(self, directory: pathlib.Path) -> list[str]:
        assets = directory / "assets"
        assets.mkdir()
        (assets / "archive").write_text("immutable bytes")
        digests = {"archive": sha256_file(assets / "archive")}
        transaction = {"state": "draft_created", "history": [], "assetDigests": digests}
        resumed = release_transition(transaction, "draft_verified", assets, digests)
        assert_true(resumed["state"] == "draft_verified", "matching partial draft did not resume")
        (directory / "resumed.json").write_bytes(canonical_json(resumed))
        return ["resumed.json"]

    def a15(self, directory: pathlib.Path) -> list[str]:
        assets = directory / "assets"
        assets.mkdir()
        (assets / "archive").write_text("staged")
        digests = {"archive": sha256_file(assets / "archive")}
        transaction = {"state": "draft_verified", "history": [], "publishedAssets": {"archive": "sha256:" + "0" * 64}}
        assert_reject(lambda: release_transition(transaction, "published", assets, digests), "inconsistency")
        (directory / "result.txt").write_text("critical-stop; no overwrite; no delete; no retag\n")
        return ["result.txt"]

    def a16(self, directory: pathlib.Path) -> list[str]:
        manifest = {"manifestDigest": "sha256:" + "a" * 64, "captures": [{"status": 200}]}
        decision = watch_decision(manifest, manifest, [{"actionKey": "new_patch:8.5.8", "state": "complete"}], {"healthy": True})
        event = {"actionKey": "new_patch:8.5.8", "state": "complete", "finalResult": "passed"}
        first = notification_decision(event, None)
        replay = notification_decision(event, {"fingerprint": first["fingerprint"]})
        assert_true(not decision["classify"] and replay["action"] == "none", "completed replay caused side effect")
        assert_reject(lambda: transition_event({"state": "complete"}, "released", [{"digest": "x"}]))
        (directory / "replay.json").write_bytes(canonical_json({"watch": decision, "notification": replay}))
        return ["replay.json"]

    def a17(self, directory: pathlib.Path) -> list[str]:
        created_event = {"actionKey": "new_branch:8.6", "state": "detected", "evidenceDigest": "a"}
        create = notification_decision(created_event, None)
        same = notification_decision(created_event, {"fingerprint": create["fingerprint"]})
        changed_event = {**created_event, "state": "php_bin_ready"}
        comment = notification_decision(changed_event, {"fingerprint": create["fingerprint"]})
        recovery = notification_decision({**changed_event, "failureFingerprint": "recovered"}, {"fingerprint": comment["fingerprint"]})
        close = notification_decision({**changed_event, "state": "complete", "finalResult": "passed"}, {"fingerprint": recovery["fingerprint"]})
        assert_true([create["action"], same["action"], comment["action"], recovery["action"], close["action"]] == ["create", "none", "comment", "comment", "comment_and_close"], "notification transitions are not deduplicated")
        (directory / "notifications.json").write_bytes(canonical_json({"create": create, "same": same, "comment": comment, "recovery": recovery, "close": close}))
        return ["notifications.json"]

    def a18(self, directory: pathlib.Path) -> list[str]:
        assert_true(not mutation_allowed({"unattendedMutation": "paused"}), "paused control allowed mutation")
        assert_true(mutation_allowed({"unattendedMutation": "enabled"}), "enabled control blocked mutation")
        watch_steps = workflow_steps(load_workflow(PHP_ROOT / ".github/workflows/autorelease-watch.yml"))
        dispatch_steps = [step for _, _, step in watch_steps if "gh workflow run" in (step.get("run") or "")]
        assert_true(dispatch_steps, "watcher no longer dispatches downstream mutation")
        assert_true(
            all("operator-gate" in step["run"] for step in dispatch_steps),
            "watcher pause does not stop downstream mutation",
        )
        # The watcher gates are the soft shape on purpose: they log their own message and
        # exit 0. That is only safe while they test the reported state, so assert the
        # comparison and assert the absence of the flag, keeping them distinguishable from
        # the hard sites rather than letting either shape satisfy one check.
        soft_gate_calls = [call for _, _, step in watch_steps for call in operator_gate_calls(step.get("run") or "")]
        assert_true(soft_gate_calls, "the watcher no longer reads the operator control")
        assert_true(
            all('"enabled"' in call and "--require-enabled" not in call for call in soft_gate_calls),
            "a watcher operator gate neither tests the reported state nor fails the job",
        )
        # Every gate outside the watcher must fail its job, which is the flag rather than
        # the subcommand: without it the gate reports the state and the job releases anyway.
        hard_gate_calls = [
            call
            for name in ("autorelease-publish.yml", "autorelease-implement.yml")
            for _, _, step in workflow_steps(load_workflow(PHP_ROOT / ".github/workflows" / name))
            for call in operator_gate_calls(step.get("run") or "")
        ]
        assert_true(hard_gate_calls, "the release and implementation workflows no longer read the operator control")
        assert_true(
            all("--require-enabled" in call for call in hard_gate_calls),
            "an operator gate that must fail its job only reports the state",
        )
        release_steps = workflow_steps(load_workflow(PHP_ROOT / ".github/workflows/autorelease-publish.yml"))
        effect_steps = [
            (job_name, step)
            for job_name, _, step in release_steps
            if "./scripts/publish-release" in (step.get("run") or "")
        ]
        assert_true(effect_steps, "release workflow performs no release transition")
        assert_true(
            all(
                job_name == "release"
                and "operator-gate --operator-file release-run/current-operator.json --require-enabled" in step["run"]
                for job_name, step in effect_steps
            ),
            "release effects are not gated by the live operator state",
        )
        mise_steps = workflow_steps(load_workflow(self.mise_root / ".github/workflows/autorelease-consumer.yml"))
        # The compare job binds the synchronization plan to the operator commit and state;
        # the merge job re-reads both at merge time and refuses on any change.
        operator_bound_jobs = {
            job_name
            for job_name, _, step in mise_steps
            if ("phpBinOperatorCommit" in (step.get("run") or "") and "operatorState" in (step.get("run") or ""))
            or ("--operator-commit" in (step.get("run") or "") and "--operator-state" in (step.get("run") or ""))
        }
        assert_true(
            {"compare", "merge-and-record-readiness"} <= operator_bound_jobs,
            "mise synchronization is not bound to the php-bin operator control",
        )
        event = {"actionKey": "new_patch:8.5.9", "state": "release_requested", "history": []}
        resumed = transition_event(event, "released", [{"digest": "sha256:" + "a" * 64}])
        assert_true(resumed["state"] == "released", "resume did not take next legal transition")
        (directory / "pause-resume.json").write_bytes(canonical_json(resumed))
        return ["pause-resume.json"]

    def a19(self, directory: pathlib.Path) -> list[str]:
        evidence = directory / "evidence.json"
        evidence.write_text('{"captured":true}\n')
        event = {
            "actionKey": "new_patch:8.5.9",
            "state": "complete",
            "history": [{"from": "public_install_verified", "to": "complete"}],
            "auditEvidence": [{"path": "evidence.json", "digest": sha256_file(evidence)}],
        }
        complete = audit_reconstruction(event, directory)
        blocked = audit_reconstruction({**event, "actionKey": "repair:8.5.9:deadbeef", "state": "blocked"}, directory)
        (directory / "audit.json").write_bytes(canonical_json({"complete": complete, "blocked": blocked}))
        return ["audit.json", "evidence.json"]

    def a20(self, directory: pathlib.Path) -> list[str]:
        # The system documentation lives in AUTORELEASE.md; each README only
        # points at it.
        for doc in (PHP_ROOT / "AUTORELEASE.md", self.mise_root / "AUTORELEASE.md"):
            body = doc.read_text()
            assert_true("```mermaid" in body, f"AUTORELEASE.md has no Mermaid flow: {doc}")
            assert_true("verify-autorelease-system" in body, f"AUTORELEASE.md lacks verifier command: {doc}")
            assert_true("AUTORELEASE_OWNER" in body, f"AUTORELEASE.md lacks notification configuration: {doc}")
        for readme in (PHP_ROOT / "README.md", self.mise_root / "README.md"):
            body = readme.read_text()
            assert_true("AUTORELEASE.md" in body, f"README does not link AUTORELEASE.md: {readme}")
        run("./scripts/test.sh", cwd=PHP_ROOT)
        run("./scripts/test.sh", cwd=self.mise_root)
        (directory / "commands.txt").write_text("(cd php-bin && ./scripts/test.sh)\n(cd mise-php && ./scripts/test.sh)\nverification: passed\n")
        return ["commands.txt"]

    def execute(self) -> int:
        self.output.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        assert_true(exact_head(PHP_ROOT) == self.php_sha, "php-bin checkout does not match --php-bin-sha")
        assert_true(exact_head(self.mise_root) == self.mise_sha, "mise-php checkout does not match --mise-php-sha")
        checks = [
            ("A00", "Deterministic classification", self.a00),
            ("A01", "Quiet run", self.a01),
            ("A02", "Evidence-bound plan", self.a02),
            ("A03", "Bad evidence rejection", self.a03),
            ("A04", "Classification fixtures", self.a04),
            ("A05", "No-edit release", self.a05),
            ("A06", "Failure stops without repair", self.a06),
            ("A07", "No model invocation", self.a07),
            ("A08", "Forbidden diff", self.a08),
            ("A09", "New branch coordination", self.a09),
            ("A10", "EOL behavior", self.a10),
            ("A11", "Source-format change", self.a11),
            ("A12", "Exact-SHA merge", self.a12),
            ("A13", "Executor and runtime authority boundaries", self.a13),
            ("A14", "Partial draft recovery", self.a14),
            ("A15", "Published inconsistency", self.a15),
            ("A16", "Idempotent replay", self.a16),
            ("A17", "Notification deduplication", self.a17),
            ("A18", "Pause and resume", self.a18),
            ("A19", "Audit reconstruction", self.a19),
            ("A20", "Documentation accuracy", self.a20),
        ]
        for test_id, name, callback in checks:
            self.record(test_id, name, callback)
        finished = dt.datetime.now(dt.UTC)
        workflows = list((PHP_ROOT / ".github/workflows").glob("*.yml")) + list((self.mise_root / ".github/workflows").glob("*.yml"))
        pins = sorted(
            set(
                match.group(1)
                for path in workflows
                for match in PIN_RE.finditer(path.read_text())
            )
        )
        configuration_paths = [
            PHP_ROOT / "support-policy.json",
            PHP_ROOT / "autorelease/protected-paths.json",
            self.mise_root / "support-snapshot.json",
        ]
        control_digests = {
            f"autorelease/{path.name}": sha256_file(path)
            for path in sorted((PHP_ROOT / "autorelease").glob("_*.py"))
        }
        report = {
            "schemaVersion": 1,
            "verifierVersion": "2.0.0",
            "startedAt": self.started.isoformat(),
            "finishedAt": finished.isoformat(),
            "repositories": {"php-bin": self.php_sha, "mise-php": self.mise_sha},
            "actionPins": pins,
            "controlDigests": control_digests,
            "configurationDigests": {path.name: sha256_file(path) for path in configuration_paths},
            "tests": self.results,
            "result": "passed" if all(item["result"] == "passed" for item in self.results) else "failed",
        }
        report_path = self.output / "autorelease-verification.json"
        report_path.write_bytes(canonical_json(report))
        report_digest = sha256_file(report_path)
        lines = [
            "# Autorelease verification",
            "",
            f"- Result: **{report['result']}**",
            f"- php-bin: `{self.php_sha}`",
            f"- mise-php: `{self.mise_sha}`",
            f"- Report digest: `{report_digest}`",
            "",
            "| ID | Acceptance test | Result |",
            "| --- | --- | --- |",
        ]
        lines.extend(f"| {item['id']} | {item['name']} | {item['result']} |" for item in self.results)
        (self.output / "autorelease-verification.md").write_text("\n".join(lines) + "\n")
        print(json.dumps({"result": report["result"], "report": str(report_path), "digest": report_digest}))
        return 0 if report["result"] == "passed" else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mise-repo", required=True, type=pathlib.Path)
    parser.add_argument("--php-bin-sha", required=True)
    parser.add_argument("--mise-php-sha", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.php_bin_sha):
        parser.error("--php-bin-sha must be an exact 40-character commit")
    if not re.fullmatch(r"[0-9a-f]{40}", args.mise_php_sha):
        parser.error("--mise-php-sha must be an exact 40-character commit")
    return Verifier(args.mise_repo, args.php_bin_sha, args.mise_php_sha, args.output).execute()


if __name__ == "__main__":
    raise SystemExit(main())
