#!/usr/bin/env python3
"""Cross-repository production-control fixture verification (A00-A20)."""

from __future__ import annotations

import argparse
import copy
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
    audit_reconstruction,
    canonical_json,
    instruction_digest,
    mutation_allowed,
    notification_decision,
    release_transition,
    retry_decision,
    seal_patch,
    sha256_bytes,
    sha256_file,
    transition_event,
    validate_completion_assessment,
    validate_plan,
    verify_merge,
    watch_decision,
)


PHP_ROOT = pathlib.Path(__file__).resolve().parents[1]
PIN_RE = re.compile(r"^\s*uses:\s*[^#\s]+@([0-9a-f]{40})(?:\s*#.*)?$", re.MULTILINE)
UNPINNED_RE = re.compile(r"^\s*uses:\s*[^#\s]+@(?![0-9a-f]{40}(?:\s|$))[^#\s]+", re.MULTILINE)


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


def fixture_contract(phase: str = "investigation") -> dict[str, Any]:
    return {
        "contractVersion": 1,
        "phase": phase,
        "goal": f"Complete the {phase} fixture goal.",
        "actionKey": "new_patch:8.5.9",
        "preconditions": {},
        "allowedAuthority": ["read_repository"] if phase == "investigation" else ["workspace_write_admitted_paths"],
        "nonGoals": ["irreversible_github_effect"],
        "completionCriteria": [
            {
                "id": "goal-correct",
                "requirement": "Goal remains correct.",
                "evidenceRequired": "Exact evidence reference.",
            },
            {
                "id": "work-complete",
                "requirement": "All phase work is complete.",
                "evidenceRequired": "Exact evidence reference.",
            },
        ],
        "stopConditions": ["changed_precondition", "protected_change"],
    }


def assessment(contract: dict[str, Any], digests: dict[str, str], status: str = "passed") -> dict[str, Any]:
    passed = status == "passed"
    return {
        "contractVersion": 1,
        "instructionDigests": digests,
        "phaseStatus": "complete" if passed else "blocked",
        "criteria": [
            {
                "id": item["id"],
                "status": status,
                "evidence": ["evidence[0]"] if passed else [],
            }
            for item in contract["completionCriteria"]
        ],
        "goNoGo": "go" if passed else "no_go",
        "unresolved": [] if passed else ["fixture unresolved"],
        "summary": "Fixture assessment.",
    }


def fixture_admission_inputs(directory: pathlib.Path, action: str = "new_patch") -> dict[str, Any]:
    shared = PHP_ROOT / ".github/codex/autorelease/shared.md"
    phase = PHP_ROOT / ".github/codex/autorelease/investigation.md"
    event_path = directory / "event-contract.json"
    contract = fixture_contract()
    event_path.write_bytes(canonical_json(contract))
    digests = {
        "shared": instruction_digest(shared),
        "phaseTemplate": instruction_digest(phase),
        "eventContract": instruction_digest(event_path),
    }
    raw = directory / "raw"
    raw.mkdir()
    release_versions = {"new_patch": "8.5.9", "new_branch": "8.6.0"}
    release_version = release_versions.get(action, "8.5.9")
    body = canonical_json({"release": {"version": release_version, "stable": True}})
    (raw / "release.body").write_bytes(body)
    manifest_path = directory / "evidence-manifest.json"
    manifest = {
        "schemaVersion": 1,
        "captures": [
            {
                "captureId": "php_release_feed",
                "digest": sha256_bytes(body),
                "bodyPath": "raw/release.body",
                "status": 200,
            }
        ],
    }
    manifest_path.write_bytes(canonical_json(manifest))
    action_keys = {
        "new_patch": "new_patch:8.5.9",
        "new_branch": "new_branch:8.6",
        "branch_eol": "branch_eol:8.2:2026-12-31",
    }
    release_intent = (
        {"version": release_version, "sourceIdentifier": "php_release_feed"}
        if action in {"new_patch", "new_branch"}
        else None
    )
    plan = {
        "schemaVersion": 1,
        "actionKey": action_keys[action],
        "action": action,
        "agentContract": {"contractVersion": 1, "instructionDigests": digests},
        "evidence": [
            {
                "captureId": "php_release_feed",
                "digest": sha256_bytes(body),
                "claim": f"Fixture supports {action}",
                "locator": {"kind": "json_pointer", "value": "/release/version"},
            }
        ],
        "researchSources": [],
        "repositories": ["php-bin"],
        "preconditions": {
            "phpBinHead": "a" * 40,
            "misePhpHead": "b" * 40,
            "supportPolicyDigest": "sha256:" + "c" * 64,
        },
        "editsRequired": action != "new_patch",
        "allowedPaths": {"php-bin": ["expected-modules/*.txt"] if action != "new_patch" else []},
        "requiredChecks": ["Script checks"],
        "releaseIntent": release_intent,
        "agentOperations": [],
        "budgets": {"maxModelCalls": 1, "maxRetries": 1, "timeoutMinutes": 30},
        "notification": {"suggestedSeverity": "info", "summary": "fixture", "humanActionRequired": False},
        "risk": "routine" if action == "new_patch" else "lifecycle",
        "completionAssessment": assessment(contract, digests),
        "summary": "Evidence-bound fixture.",
    }
    return {
        "contract": contract,
        "eventPath": event_path,
        "digests": digests,
        "manifestPath": manifest_path,
        "manifest": manifest,
        "plan": plan,
        "shared": shared,
        "phase": phase,
    }


def admit_fixture(inputs: dict[str, Any]) -> dict[str, Any]:
    return validate_plan(
        inputs["plan"],
        inputs["manifestPath"],
        inputs["contract"],
        inputs["shared"],
        inputs["phase"],
        inputs["eventPath"],
        {"phpBinHead": "a" * 40, "misePhpHead": "b" * 40},
        "sha256:" + "c" * 64,
        set(),
    )


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
        contract = fixture_contract()
        digests = {"shared": "sha256:" + "a" * 64, "phaseTemplate": "sha256:" + "b" * 64, "eventContract": "sha256:" + "c" * 64}
        good = assessment(contract, digests)
        validate_completion_assessment(good, contract, digests)
        for mutation in ("failed", "unresolved", "changed-precondition", "protected-change", "out-of-scope"):
            bad = copy.deepcopy(good)
            if mutation == "failed":
                bad["criteria"][0] = {"id": "goal-correct", "status": "failed", "evidence": []}
            elif mutation == "unresolved":
                bad["unresolved"] = ["unresolved"]
            elif mutation == "changed-precondition":
                bad["instructionDigests"]["eventContract"] = "sha256:" + "d" * 64
            elif mutation == "protected-change":
                bad["goNoGo"] = "go"
                bad["phaseStatus"] = "blocked"
            else:
                bad["criteria"].append({"id": "extra", "status": "passed", "evidence": ["x"]})
            assert_reject(lambda bad=bad: validate_completion_assessment(bad, contract, digests))
        (directory / "contract.json").write_bytes(canonical_json(contract))
        (directory / "assessment.json").write_bytes(canonical_json(good))
        return ["contract.json", "assessment.json"]

    def a01(self, directory: pathlib.Path) -> list[str]:
        manifest = {"manifestDigest": "sha256:" + "a" * 64, "captures": [{"status": 200}]}
        result = watch_decision(manifest, manifest, [{"actionKey": "new_patch:8.5.8", "state": "complete"}], {"healthy": True})
        assert_true(result["trigger"] == "quiet" and result["modelCall"] is False, "quiet run woke a model")
        assert_true(notification_decision({"state": "complete"}, {"fingerprint": notification_decision({"state": "complete"}, None)["fingerprint"]})["action"] == "none", "quiet replay mutated notification")
        (directory / "decision.json").write_bytes(canonical_json(result))
        return ["decision.json"]

    def a02(self, directory: pathlib.Path) -> list[str]:
        inputs = fixture_admission_inputs(directory)
        result = admit_fixture(inputs)
        (directory / "admission.json").write_bytes(canonical_json(result))
        return ["evidence-manifest.json", "admission.json"]

    def a03(self, directory: pathlib.Path) -> list[str]:
        missing_dir = directory / "missing"
        missing_dir.mkdir()
        inputs = fixture_admission_inputs(missing_dir)
        (missing_dir / "raw/release.body").unlink()
        assert_reject(lambda: admit_fixture(inputs), "missing")
        altered_dir = directory / "altered"
        altered_dir.mkdir()
        inputs2 = fixture_admission_inputs(altered_dir)
        (altered_dir / "raw/release.body").write_text("altered")
        assert_reject(lambda: admit_fixture(inputs2), "digest mismatch")
        fingerprint = sha256_bytes(b"bad-evidence-rejection")
        (directory / "fingerprint.txt").write_text(fingerprint + "\n")
        return ["fingerprint.txt"]

    def a04(self, directory: pathlib.Path) -> list[str]:
        actions = {}
        for action in ("new_patch", "new_branch", "branch_eol"):
            target = directory / action
            target.mkdir()
            inputs = fixture_admission_inputs(target, action)
            admit_fixture(inputs)
            actions[action] = inputs["plan"]["actionKey"]
        source = (PHP_ROOT / "autorelease/control.py").read_text()
        forbidden_classifier_markers = ("BeautifulSoup", "support_table_to_events", "classify_php_release")
        assert_true(not any(item in source for item in forbidden_classifier_markers), "deterministic control contains lifecycle classifier")
        (directory / "classifications.json").write_bytes(canonical_json(actions))
        return ["classifications.json"]

    def a05(self, directory: pathlib.Path) -> list[str]:
        target = directory / "admission"
        target.mkdir()
        inputs = fixture_admission_inputs(target)
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
        event = {"attemptCount": 1, "failureFingerprint": "fp"}
        first = retry_decision(event, "fp", 2)
        exhausted = retry_decision({**event, "attemptCount": 2}, "fp", 2)
        repeated = retry_decision({**event, "lastRejectionRepeated": True}, "fp", 2)
        assert_true(first["recallAgent"], "bounded repair was not allowed")
        assert_true(not exhausted["recallAgent"] and not repeated["recallAgent"], "exhausted identical failure recalled agent")
        php_workflow = (PHP_ROOT / ".github/workflows/autorelease-implement.yml").read_text()
        mise_workflow = (self.mise_root / ".github/workflows/autorelease-consumer.yml").read_text()
        for name, workflow in {"php-bin": php_workflow, "mise-php": mise_workflow}.items():
            assert_true("authoritative-checks.log" in workflow, f"{name} does not retain deterministic failure logs")
            assert_true("Run one offline Codex repair" in workflow, f"{name} has no bounded repair invocation")
            assert_true("validate-repair:" in workflow, f"{name} does not cleanly validate repaired bytes")
        assert_true(
            'network_access = false' in (PHP_ROOT / ".codex/repair.config.toml").read_text()
            and 'network_access = false' in (self.mise_root / ".codex/repair.config.toml").read_text(),
            "repair network access is not disabled",
        )
        evidence = {
            "first": first,
            "exhausted": exhausted,
            "repeated": repeated,
            "phpWorkflowDigest": sha256_file(PHP_ROOT / ".github/workflows/autorelease-implement.yml"),
            "miseWorkflowDigest": sha256_file(self.mise_root / ".github/workflows/autorelease-consumer.yml"),
        }
        (directory / "retry.json").write_bytes(canonical_json(evidence))
        return ["retry.json"]

    def a07(self, directory: pathlib.Path) -> list[str]:
        watch = (PHP_ROOT / ".github/workflows/autorelease-watch.yml").read_text()
        implementation = (PHP_ROOT / ".github/workflows/autorelease-implement.yml").read_text()
        assert_true(
            "sandbox: read-only" in watch
            and 'cp .codex/investigation.config.toml "$RUNNER_TEMP/codex-home/config.toml"' in watch
            and '"--profile"' not in watch,
            "investigation sandbox or canonical config loading is missing",
        )
        assert_true(
            "sandbox: workspace-write" in implementation
            and 'cp ".codex/$phase.config.toml" "$RUNNER_TEMP/codex-home/config.toml"' in implementation
            and 'cp .codex/repair.config.toml "$RUNNER_TEMP/codex-home/config.toml"' in implementation
            and '"--profile"' not in implementation,
            "phase-bound implementation/repair canonical config loading is missing",
        )
        assert_true('network_access = false' in (PHP_ROOT / ".codex/implementation.config.toml").read_text(), "implementation network is not disabled")
        assert_true('allowed_domains = ["php.net", "github.com", "docs.github.com"]' in (PHP_ROOT / ".codex/investigation.config.toml").read_text(), "investigation allowlist changed")
        (directory / "boundary.txt").write_text("investigation=allowlisted-web-only\nimplementation=offline\nshell-network=disabled-by-sandbox\n")
        return ["boundary.txt"]

    def a08(self, directory: pathlib.Path) -> list[str]:
        protected_classes = [
            ".github/workflows/evil.yml",
            ".github/codex/autorelease/shared.md",
            "schemas/agent-task-contract.schema.json",
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
            contract = fixture_contract("implementation")
            contract_path = directory / f"contract-{index}.json"
            contract_path.write_bytes(canonical_json(contract))
            digests = {"shared": "sha256:" + "a" * 64, "phaseTemplate": "sha256:" + "b" * 64, "eventContract": sha256_file(contract_path)}
            plan = {
                "actionKey": "repair:8.5.9:deadbeef",
                "agentContract": {"instructionDigests": digests},
                "allowedPaths": {"php-bin": ["safe.txt"]},
            }
            result = assessment(contract, digests)
            expected = "unadmitted path" if path == "unadmitted.txt" else "protected path"
            assert_reject(
                lambda repo=repo, base=base, plan=plan, result=result, contract=contract, index=index: seal_patch(
                    repo, base, plan, result, contract, directory / f"sealed-{index}"
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
        (directory / "coordination.json").write_bytes(canonical_json(result))
        return ["coordination.json"]

    def a10(self, directory: pathlib.Path) -> list[str]:
        releases = (self.mise_root / "lib/releases.lua").read_text()
        available = (self.mise_root / "hooks/available.lua").read_text()
        install = (self.mise_root / "hooks/pre_install.lua").read_text()
        assert_true("M.is_supported_version" in releases and "8%.[2-5]" in releases, "active shorthand boundary missing")
        assert_true("is_supported_version" in available, "EOL versions can be discovered")
        assert_true("is_exact_stable_version" in install, "historical exact installation is blocked")
        (directory / "eol-policy.txt").write_text("discovery=maintained-only\ninstallation=exact-stable-history\npublication=maintained-only\n")
        return ["eol-policy.txt"]

    def a11(self, directory: pathlib.Path) -> list[str]:
        inputs = fixture_admission_inputs(directory)
        body_path = directory / "raw/release.body"
        body = b'{\n  "release": { "stable": true, "version": "8.5.9" }\n}\n'
        body_path.write_bytes(body)
        inputs["manifest"]["captures"][0]["digest"] = sha256_bytes(body)
        inputs["manifestPath"].write_bytes(canonical_json(inputs["manifest"]))
        inputs["plan"]["evidence"][0]["digest"] = sha256_bytes(body)
        admit_fixture(inputs)
        source = (PHP_ROOT / "autorelease/control.py").read_text()
        assert_true("supported-versions.php" in source and "BeautifulSoup" not in source, "source-format handling became a lifecycle parser")
        return ["evidence-manifest.json"]

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
        codex_contracts = {}
        for name, root in {"php-bin": PHP_ROOT, "mise-php": self.mise_root}.items():
            result = run("./scripts/validate-codex-action-inputs", "--json", cwd=root)
            codex_contracts[name] = json.loads(result.stdout)
        assert_true(
            codex_contracts["php-bin"]["commit"] == codex_contracts["mise-php"]["commit"]
            and codex_contracts["php-bin"]["metadataDigest"] == codex_contracts["mise-php"]["metadataDigest"],
            "repositories do not share the same reviewed Codex Action contract",
        )
        assert_true(
            codex_contracts["php-bin"]["codexVersion"] == codex_contracts["mise-php"]["codexVersion"],
            "repositories do not pin the same reviewed Codex CLI version",
        )
        (directory / "codex-action-inputs.json").write_bytes(canonical_json(codex_contracts))
        pins = json.loads((PHP_ROOT / ".github/autorelease-pins.json").read_text())
        assert_true(
            pins["actions"]["openai/codex-action"] == codex_contracts["php-bin"]["commit"],
            "Codex Action pin is not bound to the reviewed input contract",
        )
        e2e = PHP_ROOT / ".github/workflows/autorelease-e2e.yml"
        e2e_text = e2e.read_text()
        assert_true(
            'status:{type:"string",const:"passed"}' in e2e_text
            and 'nonce:{type:"string",const:$nonce}' in e2e_text,
            "credentialed agent canary schema does not declare string types",
        )
        assert_true(
            pins["workflows"][".github/workflows/autorelease-e2e.yml"] == sha256_file(e2e),
            "reviewed production-parity workflow digest changed",
        )
        watch_path = PHP_ROOT / ".github/workflows/autorelease-watch.yml"
        watch = watch_path.read_text()
        release = (PHP_ROOT / ".github/workflows/autorelease-publish.yml").read_text()
        watch_document = load_workflow(watch_path)
        workflow_permissions = watch_document.get("permissions", {})
        investigate = watch_document.get("jobs", {}).get("investigate", {})
        investigate_permissions = investigate.get("permissions", workflow_permissions)
        assert_true(
            isinstance(investigate_permissions, dict)
            and investigate_permissions.get("contents") == "read",
            "runtime investigation does not have resolved read-only contents permission",
        )
        assert_true("openai-api-key" not in release, "release job can read OpenAI credential")
        admin = PHP_ROOT / "docs/autorelease-admin-evidence.json"
        assert_true(admin.is_file(), "redacted administrator evidence is missing")
        evidence = json.loads(admin.read_text())
        assert_true(evidence.get("canary", {}).get("removed") is True, "admin canary was not removed")
        assert_true(evidence.get("protectionRestored") is True, "fixture bypass protection was not restored")
        assert_true(evidence.get("immutableReleasesEnabled") is True, "immutable releases were not enabled")
        agent_canary_environment = evidence.get("agentCanaryEnvironment", {})
        assert_true(
            agent_canary_environment.get("name") == "php-autorelease-canary"
            and agent_canary_environment.get("protectedBranchesOnly") is True
            and agent_canary_environment.get("administratorBypass") is False,
            "credentialed agent canary environment is not protected",
        )
        shutil.copy(admin, directory / admin.name)
        return [admin.name, "codex-action-inputs.json"]

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
        assert_true(not decision["modelCall"] and replay["action"] == "none", "completed replay caused side effect")
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
        watch_workflow = (PHP_ROOT / ".github/workflows/autorelease-watch.yml").read_text()
        release_workflow = (PHP_ROOT / ".github/workflows/autorelease-publish.yml").read_text()
        mise_workflow = (self.mise_root / ".github/workflows/autorelease-consumer.yml").read_text()
        assert_true(
            "Unattended mutation is paused" in watch_workflow,
            "watcher pause does not stop downstream mutation",
        )
        assert_true(
            release_workflow.count("current-operator.json") >= 3,
            "release effects are not gated by the live operator state",
        )
        assert_true(
            "phpBinOperatorCommit" in mise_workflow and "operatorState" in mise_workflow,
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
            ("A00", "Agent goal and completion contract", self.a00),
            ("A01", "Quiet run", self.a01),
            ("A02", "Evidence-bound plan", self.a02),
            ("A03", "Bad evidence rejection", self.a03),
            ("A04", "Agent classification fixtures", self.a04),
            ("A05", "No-edit release", self.a05),
            ("A06", "Bounded repair", self.a06),
            ("A07", "Network separation", self.a07),
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
        instruction_roots = {"php-bin": PHP_ROOT, "mise-php": self.mise_root}
        instruction_names = ("shared.md", "investigation.md", "implementation.md", "repair.md")
        instruction_digests = {
            f"{repo}/.github/codex/autorelease/{name}": sha256_file(
                root / ".github/codex/autorelease" / name
            )
            for repo, root in instruction_roots.items()
            for name in instruction_names
        }
        report = {
            "schemaVersion": 1,
            "verifierVersion": "1.0.0",
            "startedAt": self.started.isoformat(),
            "finishedAt": finished.isoformat(),
            "repositories": {"php-bin": self.php_sha, "mise-php": self.mise_sha},
            "actionPins": pins,
            "instructionDigests": instruction_digests,
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
