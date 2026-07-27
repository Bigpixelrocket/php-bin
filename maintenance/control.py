#!/usr/bin/env python3
"""Deterministic maintenance controls.

This module deliberately does not classify PHP releases or lifecycle state.
It validates authority, evidence, state transitions, and immutable effects
selected by Codex.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Iterable


ROOT = pathlib.Path(__file__).resolve().parents[1]
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ACTION_KEY_RE = re.compile(
    r"^(no_change:[0-9a-f]{8,64}|new_patch:\d+\.\d+\.\d+|new_branch:\d+\.\d+|"
    r"branch_eol:\d+\.\d+:\d{4}-\d{2}-\d{2}|"
    r"recipe_rebuild:\d+\.\d+\.\d+:[1-9]\d*|"
    r"repair:\d+\.\d+\.\d+:[0-9a-f]{8,64}|"
    r"(?:source_unhealthy|health_failed|policy_failure|auth_failure):[0-9a-f]{8,64})$"
)
STABLE_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[1-9]\d*)?$")
PROTECTED_PATTERNS = (
    ".github/codex/maintenance/*",
    ".github/maintenance-operator.json",
    ".github/maintenance-pins.json",
    ".github/workflows/*",
    ".codex/*",
    "schemas/*",
    "maintenance/*",
    "scripts/admit-maintenance-plan",
    "scripts/capture-maintenance-evidence",
    "scripts/configure-github-maintenance",
    "scripts/maintenance-event",
    "scripts/notify-maintenance",
    "scripts/prepare-agent-task",
    "scripts/seal-maintenance-patch",
    "scripts/snapshot-github-admin-state",
    "scripts/validate-maintenance-archive",
    "scripts/verify-merge-admission",
    "scripts/release-maintenance",
    "scripts/watch-maintenance-evidence",
    "maintenance-events/*",
    "maintenance-state/*",
    ".github/CODEOWNERS",
)
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bgh[opusr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
)
PROHIBITED_AGENT_AUTHORITY = {
    "merge",
    "push",
    "tag",
    "release",
    "publish",
    "delete_release",
    "overwrite_asset",
    "workflow_permissions",
    "secret_access",
}
LEGAL_EVENT_TRANSITIONS = {
    "detected": {"php_bin_ready", "blocked", "needs_human"},
    "php_bin_ready": {"mise_ready", "release_requested", "blocked", "needs_human"},
    "mise_ready": {"release_requested", "complete", "blocked", "needs_human"},
    "release_requested": {"released", "blocked", "needs_human"},
    "released": {"public_install_verified", "blocked", "needs_human"},
    "public_install_verified": {"complete", "blocked", "needs_human"},
    "blocked": {"detected", "php_bin_ready", "mise_ready", "release_requested", "needs_human"},
    "needs_human": {"detected", "php_bin_ready", "mise_ready", "release_requested", "blocked"},
    "complete": set(),
}
LEGAL_RELEASE_TRANSITIONS = {
    "requested": "built",
    "built": "draft_created",
    "draft_created": "draft_verified",
    "draft_verified": "published",
    "published": "public_verified",
    "public_verified": "complete",
}


class ControlError(RuntimeError):
    """A fail-closed deterministic-control rejection."""


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def load_json(path: pathlib.Path) -> Any:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ControlError(f"cannot load JSON {path}: {error}") from error


def write_json(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(canonical_json(value))
    temporary.replace(path)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ControlError(message)


def contained_path(root: pathlib.Path, value: Any, label: str) -> pathlib.Path:
    require(isinstance(value, str) and bool(value), f"{label} is missing")
    relative = pathlib.PurePosixPath(value)
    require(not relative.is_absolute() and ".." not in relative.parts, f"unsafe {label}: {value}")
    resolved_root = root.resolve()
    resolved = (resolved_root / pathlib.Path(*relative.parts)).resolve()
    require(resolved.is_relative_to(resolved_root), f"unsafe {label}: {value}")
    return resolved


def instruction_digest(path: pathlib.Path) -> str:
    require(path.is_file(), f"instruction file does not exist: {path}")
    return sha256_file(path)


def validate_task_contract(contract: dict[str, Any]) -> None:
    require(contract.get("contractVersion") == 1, "unsupported task contract version")
    require(
        contract.get("phase") in {"investigation", "implementation", "repair"},
        "invalid phase",
    )
    for field in (
        "goal",
        "actionKey",
        "preconditions",
        "allowedAuthority",
        "nonGoals",
        "completionCriteria",
        "stopConditions",
    ):
        require(field in contract, f"task contract is missing {field}")
    require(bool(contract["goal"]), "phase goal is empty")
    require(
        isinstance(contract["allowedAuthority"], list),
        "allowedAuthority must be an array",
    )
    require(
        all(isinstance(item, str) for item in contract["allowedAuthority"]),
        "allowedAuthority must contain only strings",
    )
    require(
        not (set(contract["allowedAuthority"]) & PROHIBITED_AGENT_AUTHORITY),
        "agent contract grants prohibited irreversible authority",
    )
    criteria = contract["completionCriteria"]
    require(isinstance(criteria, list) and criteria, "completion criteria are empty")
    require(all(isinstance(item, dict) for item in criteria), "completion criteria must be objects")
    ids = [criterion.get("id") for criterion in criteria]
    require(all(isinstance(item, str) and item for item in ids), "criterion id is missing")
    require(len(ids) == len(set(ids)), "criterion ids are not unique")
    for criterion in criteria:
        require(bool(criterion.get("requirement")), "criterion requirement is missing")
        require(
            bool(criterion.get("evidenceRequired")),
            "criterion evidence requirement is missing",
        )


def validate_completion_assessment(
    assessment: dict[str, Any],
    contract: dict[str, Any],
    expected_digests: dict[str, str] | None = None,
) -> None:
    validate_task_contract(contract)
    require(assessment.get("contractVersion") == 1, "unsupported assessment version")
    if expected_digests is not None:
        require(
            assessment.get("instructionDigests") == expected_digests,
            "assessment instruction digests do not match admitted inputs",
        )
    status = assessment.get("phaseStatus")
    require(status in {"complete", "blocked", "needs_human"}, "invalid phaseStatus")
    require(assessment.get("goNoGo") in {"go", "no_go"}, "invalid goNoGo")
    expected_ids = {
        criterion["id"] for criterion in contract["completionCriteria"]
    }
    results = assessment.get("criteria")
    require(isinstance(results, list), "assessment criteria must be an array")
    result_ids = [result.get("id") for result in results]
    require(len(result_ids) == len(set(result_ids)), "duplicate criterion result")
    require(set(result_ids) == expected_ids, "criterion results are missing or unexpected")
    for result in results:
        require(
            result.get("status") in {"passed", "failed", "unresolved"},
            f"invalid result for {result.get('id')}",
        )
        evidence = result.get("evidence")
        require(isinstance(evidence, list), "criterion evidence must be an array")
        if result["status"] == "passed":
            require(bool(evidence), f"passed criterion {result['id']} has no evidence")
    unresolved = assessment.get("unresolved")
    require(isinstance(unresolved, list), "unresolved must be an array")
    mechanically_go = (
        status == "complete"
        and all(result["status"] == "passed" for result in results)
        and not unresolved
    )
    require(
        (assessment["goNoGo"] == "go") == mechanically_go,
        "go/no-go is inconsistent with criterion results",
    )


def resolve_json_pointer(document: Any, pointer: str) -> Any:
    if pointer == "":
        return document
    require(pointer.startswith("/"), f"invalid JSON pointer: {pointer}")
    current = document
    for token in pointer[1:].split("/"):
        key = token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            require(key.isdigit(), f"non-numeric array index in pointer: {pointer}")
            index = int(key)
            require(index < len(current), f"array index does not resolve: {pointer}")
            current = current[index]
        else:
            require(isinstance(current, dict) and key in current, f"pointer does not resolve: {pointer}")
            current = current[key]
    return current


def load_capture(manifest_path: pathlib.Path, capture_id: str) -> tuple[dict[str, Any], bytes]:
    manifest = load_json(manifest_path)
    require(isinstance(manifest, dict), "capture manifest must be an object")
    captures = manifest.get("captures", [])
    require(isinstance(captures, list), "capture manifest captures must be an array")
    matches = [item for item in captures if isinstance(item, dict) and item.get("captureId") == capture_id]
    require(len(matches) == 1, f"capture {capture_id} does not resolve exactly once")
    capture = matches[0]
    body_path = contained_path(manifest_path.parent, capture.get("bodyPath"), "capture body path")
    require(body_path.is_file(), f"capture body is missing: {body_path}")
    body = body_path.read_bytes()
    require(sha256_bytes(body) == capture.get("digest"), f"capture digest mismatch: {capture_id}")
    return capture, body


def path_is_protected(path: str) -> bool:
    normalized = pathlib.PurePosixPath(path).as_posix()
    return any(fnmatch.fnmatch(normalized, pattern) for pattern in PROTECTED_PATTERNS)


def path_is_allowed(path: str, patterns: Iterable[str]) -> bool:
    normalized = pathlib.PurePosixPath(path).as_posix()
    return any(fnmatch.fnmatch(normalized, pattern) for pattern in patterns)


def _validate_support_policy_document(
    policy: Any,
    invariants_path: pathlib.Path,
) -> tuple[list[str], list[str]]:
    require(isinstance(policy, dict), "support policy must be an object")
    require(
        set(policy)
        == {
            "schemaVersion",
            "policyInvariantsDigest",
            "maintainedBranches",
            "sourceEvidenceDigests",
            "actionKey",
            "acceptedAt",
        },
        "support policy contains unknown or missing fields",
    )
    require(policy.get("schemaVersion") == 1, "unsupported support policy version")
    require(
        policy.get("policyInvariantsDigest") == sha256_file(invariants_path),
        "support policy is not bound to reviewed invariants",
    )
    branches = policy.get("maintainedBranches")
    require(
        isinstance(branches, list)
        and all(isinstance(value, str) and re.fullmatch(r"\d+\.\d+", value) for value in branches)
        and branches == sorted(set(branches), key=lambda value: tuple(map(int, value.split(".")))),
        "support policy branches are invalid or non-canonical",
    )
    evidence = policy.get("sourceEvidenceDigests")
    require(
        isinstance(evidence, list)
        and all(isinstance(value, str) and SHA256_RE.fullmatch(value) for value in evidence)
        and evidence == sorted(set(evidence)),
        "support policy contains invalid or non-canonical evidence digests",
    )
    try:
        accepted_at = dt.datetime.strptime(policy.get("acceptedAt", ""), "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        accepted_at = None
    require(accepted_at is not None, "support policy acceptance time is invalid")
    return branches, evidence


def validate_support_policy(root: pathlib.Path = ROOT) -> dict[str, Any]:
    invariants_path = root / "maintenance/policy-invariants.json"
    policy_path = root / "support-policy.json"
    invariants = load_json(invariants_path)
    policy = load_json(policy_path)
    require(isinstance(invariants, dict), "policy invariants must be an object")
    require(
        set(invariants)
        == {
            "schemaVersion",
            "target",
            "allowPrereleases",
            "historicalExactVersionsRemainInstallable",
            "immutablePublishedAssets",
        },
        "policy invariants contain unknown or missing fields",
    )
    require(invariants.get("schemaVersion") == 1, "unsupported policy invariants version")
    require(
        invariants.get("target")
        == {"os": "macOS", "minimumVersion": "26.0", "architecture": "arm64", "sapi": "cli"},
        "reviewed target invariant changed",
    )
    require(invariants.get("allowPrereleases") is False, "prereleases must remain forbidden")
    require(
        invariants.get("historicalExactVersionsRemainInstallable") is True,
        "historical exact installs must remain enabled",
    )
    require(invariants.get("immutablePublishedAssets") is True, "published assets must remain immutable")
    _branches, evidence = _validate_support_policy_document(policy, invariants_path)
    action_key = policy.get("actionKey")
    require(
        action_key == "bootstrap"
        or bool(re.fullmatch(r"(?:new_branch:\d+\.\d+|branch_eol:\d+\.\d+:\d{4}-\d{2}-\d{2})", action_key or "")),
        "invalid support policy action key",
    )
    require(action_key == "bootstrap" or bool(evidence), "accepted support policy lacks evidence")
    return {
        "valid": True,
        "policyDigest": sha256_file(policy_path),
        "invariantsDigest": sha256_file(invariants_path),
    }


def validate_plan(
    plan: dict[str, Any],
    manifest_path: pathlib.Path,
    contract: dict[str, Any],
    shared_path: pathlib.Path,
    phase_path: pathlib.Path,
    event_contract_path: pathlib.Path,
    repo_heads: dict[str, str] | None = None,
    policy_digest: str | None = None,
    completed_actions: set[str] | None = None,
) -> dict[str, Any]:
    require(plan.get("schemaVersion") == 1, "unsupported maintenance plan version")
    require(
        plan.get("action")
        in {
            "no_change",
            "new_patch",
            "new_branch",
            "branch_eol",
            "repair",
            "reconcile_partial",
            "blocked",
            "needs_human",
        },
        "invalid maintenance action",
    )
    action_key = plan.get("actionKey", "")
    require(bool(ACTION_KEY_RE.fullmatch(action_key)), "invalid action key")
    if plan.get("action") == "no_change":
        manifest_digest = load_json(manifest_path).get("manifestDigest", "")
        require(
            action_key == f"no_change:{manifest_digest.removeprefix('sha256:')[:16]}",
            "no-change action key is not bound to the evidence manifest",
        )
        require(plan.get("editsRequired") is False, "no-change plan cannot require edits")
        require(not plan.get("releaseIntent"), "no-change plan cannot request a release")
    elif plan.get("action") not in {"blocked", "needs_human"}:
        require(plan.get("editsRequired") in {True, False}, "plan must declare whether edits are required")
    require(
        action_key not in (completed_actions or set()),
        "action key already completed",
    )
    expected_digests = {
        "shared": instruction_digest(shared_path),
        "phaseTemplate": instruction_digest(phase_path),
        "eventContract": instruction_digest(event_contract_path),
    }
    agent_contract = plan.get("agentContract", {})
    require(agent_contract.get("contractVersion") == 1, "invalid agent contract version")
    require(
        agent_contract.get("instructionDigests") == expected_digests,
        "plan instruction digests do not match supplied instructions",
    )
    validate_completion_assessment(
        {
            **plan.get("completionAssessment", {}),
            "contractVersion": 1,
            "instructionDigests": expected_digests,
        },
        contract,
        expected_digests,
    )
    if plan["action"] in {"blocked", "needs_human"}:
        require(
            plan["completionAssessment"]["goNoGo"] == "no_go",
            "blocked plans cannot advance",
        )
    else:
        require(
            plan["completionAssessment"]["goNoGo"] == "go",
            "only an internally complete agent plan can advance",
        )
    declared_heads = plan.get("preconditions", {})
    require(isinstance(declared_heads, dict), "preconditions must be an object")
    if repo_heads:
        for key, value in repo_heads.items():
            require(declared_heads.get(key) == value, f"stale repository precondition: {key}")
    if policy_digest is not None:
        require(
            declared_heads.get("supportPolicyDigest") == policy_digest,
            "stale support policy precondition",
        )
    evidence_refs = {}
    for index, evidence in enumerate(plan.get("evidence", [])):
        capture, body = load_capture(manifest_path, evidence.get("captureId", ""))
        require(evidence.get("digest") == capture["digest"], "plan evidence digest mismatch")
        locator = evidence.get("locator", {})
        if locator.get("kind") == "json_pointer":
            try:
                document = json.loads(body)
            except json.JSONDecodeError as error:
                raise ControlError("JSON locator targets a non-JSON capture") from error
            resolve_json_pointer(document, locator.get("value", ""))
        elif locator.get("kind") == "text_fragment":
            fragment = locator.get("value", "")
            require(bool(fragment) and fragment.encode() in body, "text locator does not resolve")
        else:
            raise ControlError("unsupported evidence locator")
        evidence_refs[f"evidence[{index}]"] = evidence
    research_sources = plan.get("researchSources", [])
    require(isinstance(research_sources, list), "researchSources must be an array")
    precondition_refs = {f"preconditions.{key}" for key in declared_heads}
    source_refs = {f"researchSources[{index}]" for index in range(len(research_sources))}
    for result in plan["completionAssessment"]["criteria"]:
        for reference in result["evidence"]:
            require(
                reference in evidence_refs
                or reference in precondition_refs
                or reference in source_refs,
                f"criterion evidence reference does not resolve: {reference}",
            )
    allowed_paths = plan.get("allowedPaths", {})
    require(isinstance(allowed_paths, dict), "allowedPaths must be an object")
    for patterns in allowed_paths.values():
        require(isinstance(patterns, list), "allowed path set must be an array")
        for pattern in patterns:
            pure = pathlib.PurePosixPath(pattern)
            require(not pure.is_absolute() and ".." not in pure.parts, f"unsafe allowed path: {pattern}")
            require(
                not path_is_protected(pattern),
                f"protected path cannot be admitted for runtime editing: {pattern}",
            )
            if fnmatch.fnmatch("support-policy.json", pattern):
                require(plan.get("risk") == "lifecycle", "support state requires lifecycle risk")
                require(plan.get("action") in {"new_branch", "branch_eol"}, "support state requires a lifecycle action")
    repositories = plan.get("repositories")
    require(
        isinstance(repositories, list)
        and "php-bin" in repositories
        and all(value in {"php-bin", "mise-php"} for value in repositories),
        "plan repository authority is invalid",
    )
    require(plan.get("requiredChecks") == ["Script checks"], "required deterministic checks changed")
    release_intent = plan.get("releaseIntent")
    if release_intent is not None:
        require(isinstance(release_intent, dict), "releaseIntent must be an object or null")
        version = release_intent.get("version", "")
        require(bool(STABLE_VERSION_RE.fullmatch(version)), "release version is not stable")
        require(
            not re.search(r"(?:alpha|beta|rc|dev)", version, re.I),
            "prerelease intent is forbidden",
        )
    operations = plan.get("agentOperations")
    require(isinstance(operations, list), "agentOperations must be an array")
    require(all(isinstance(operation, str) for operation in operations), "agentOperations must contain strings")
    for operation in operations:
        require(operation not in PROHIBITED_AGENT_AUTHORITY, f"prohibited agent operation: {operation}")
    budgets = plan.get("budgets")
    require(isinstance(budgets, dict) and bool(budgets), "plan must declare reviewed budgets")
    for field, upper, label in (
        ("maxModelCalls", 5, "model-call"),
        ("maxRetries", 3, "retry"),
        ("timeoutMinutes", 60, "time"),
    ):
        value = budgets.get(field)
        require(isinstance(value, int) and not isinstance(value, bool), f"{field} must be an integer")
        require(0 < value <= upper, f"{label} budget is outside reviewed bound")
    return {
        "admitted": True,
        "admittedAt": utc_now(),
        "actionKey": action_key,
        "planDigest": sha256_bytes(canonical_json(plan)),
        "instructionDigests": expected_digests,
    }


def git(repo: pathlib.Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=repo,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def changed_paths(repo: pathlib.Path, base: str) -> list[str]:
    result = git(repo, "diff", "--name-only", "--diff-filter=ACDMRTUXB", base, "--")
    paths = [line for line in result.stdout.splitlines() if line]
    untracked = git(repo, "ls-files", "--others", "--exclude-standard").stdout.splitlines()
    return sorted(set(paths + untracked))


def seal_patch(
    repo: pathlib.Path,
    base: str,
    plan: dict[str, Any],
    result: dict[str, Any],
    contract: dict[str, Any],
    output_dir: pathlib.Path,
) -> dict[str, Any]:
    expected_digests = plan["agentContract"]["instructionDigests"]
    validate_completion_assessment(result, contract, expected_digests)
    require(result["goNoGo"] == "go", "implementation result is no-go")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", base or "")), "base is not an exact commit SHA")
    require(git(repo, "rev-parse", f"{base}^{{commit}}").stdout.strip() == base, "base is not an exact commit")
    paths = changed_paths(repo, base)
    require(bool(paths), "implementation produced no patch")
    admitted = [
        item
        for patterns in plan.get("allowedPaths", {}).values()
        for item in patterns
    ]
    for path in paths:
        require(not path_is_protected(path), f"patch changes protected path: {path}")
        require(path_is_allowed(path, admitted), f"patch changes unadmitted path: {path}")
        candidate = repo / path
        if candidate.exists():
            require(not candidate.is_symlink(), f"patch contains symlink: {path}")
            require(candidate.is_file(), f"patch contains unsupported entry: {path}")
            require(candidate.stat().st_size <= 2 * 1024 * 1024, f"patch file too large: {path}")
            mode = candidate.stat().st_mode & 0o777
            require(mode in {0o644, 0o755}, f"patch contains unexpected mode: {path}")
            require(mode != 0o755 or path.startswith("scripts/"), f"unexpected executable path: {path}")
            body = candidate.read_bytes()
            require(b"\0" not in body, f"patch contains binary file: {path}")
            try:
                decoded = body.decode("utf-8")
            except UnicodeDecodeError as error:
                raise ControlError(f"patch file is not valid UTF-8: {path}") from error
            for pattern in SECRET_PATTERNS:
                require(not pattern.search(decoded), f"patch contains secret-like material: {path}")
            if path == "support-policy.json":
                try:
                    policy = json.loads(decoded)
                except json.JSONDecodeError as error:
                    raise ControlError("support policy is not valid JSON") from error
                _branches, policy_evidence = _validate_support_policy_document(
                    policy,
                    repo / "maintenance/policy-invariants.json",
                )
                evidence_digests = sorted(
                    {item.get("digest") for item in plan.get("evidence", []) if item.get("digest")}
                )
                require(
                    policy_evidence == evidence_digests and bool(evidence_digests),
                    "support policy is not bound to admitted captured evidence",
                )
                require(policy.get("actionKey") == plan.get("actionKey"), "support policy action key changed")
    output_dir.mkdir(parents=True, exist_ok=True)
    patch_path = output_dir / "sealed.patch"
    tracked_patch = git(repo, "diff", "--binary", "--full-index", base, "--").stdout
    untracked_patch_parts = []
    for path in git(repo, "ls-files", "--others", "--exclude-standard").stdout.splitlines():
        proc = subprocess.run(
            ["git", "diff", "--binary", "--no-index", "--", "/dev/null", path],
            cwd=repo,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        require(proc.returncode in {0, 1}, f"failed to serialize untracked path: {path}")
        untracked_patch_parts.append(proc.stdout)
    patch_path.write_text(tracked_patch + "".join(untracked_patch_parts))
    require(patch_path.stat().st_size <= 4 * 1024 * 1024, "sealed patch exceeds size limit")
    files = []
    for path in paths:
        candidate = repo / path
        files.append(
            {
                "path": path,
                "digest": sha256_file(candidate) if candidate.is_file() else None,
                "mode": oct(candidate.stat().st_mode & 0o777) if candidate.exists() else None,
            }
        )
    manifest = {
        "schemaVersion": 1,
        "baseSha": base,
        "actionKey": plan["actionKey"],
        "planDigest": sha256_bytes(canonical_json(plan)),
        "patchDigest": sha256_file(patch_path),
        "files": files,
        "sealedAt": utc_now(),
    }
    write_json(output_dir / "patch-manifest.json", manifest)
    return manifest


def verify_merge(
    repo: pathlib.Path,
    expected_head: str,
    manifest: dict[str, Any],
    checks: dict[str, Any],
    preconditions: dict[str, str],
    current: dict[str, str],
    readiness: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    require(bool(re.fullmatch(r"[0-9a-f]{40}", expected_head or "")), "expected head is not an exact commit SHA")
    actual_head = git(repo, "rev-parse", "HEAD").stdout.strip()
    require(actual_head == expected_head, "PR head does not equal validated SHA")
    require(checks and all(value == "success" for value in checks.values()), "required checks did not succeed")
    require(preconditions == current, "merge preconditions changed")
    base_sha = manifest.get("baseSha")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", base_sha or "")), "sealed manifest has no exact base SHA")
    require(
        git(repo, "rev-list", "--parents", "-n", "1", expected_head).stdout.split()
        == [expected_head, base_sha],
        "validated commit is not a single commit on the sealed base",
    )
    actual_paths = set(
        git(
            repo,
            "diff",
            "--name-only",
            "--diff-filter=ACDMRTUXB",
            base_sha,
            expected_head,
            "--",
        ).stdout.splitlines()
    )
    file_records = manifest.get("files", [])
    require(isinstance(file_records, list), "sealed manifest files are invalid")
    manifest_paths = {item.get("path") for item in file_records if isinstance(item, dict)}
    require(len(manifest_paths) == len(file_records) and None not in manifest_paths, "sealed manifest paths are invalid")
    require(actual_paths == manifest_paths, "final diff does not equal the sealed manifest")
    for file_record in file_records:
        path = file_record["path"]
        require(not path_is_protected(path), f"sealed manifest contains protected path: {path}")
        candidate = repo / path
        expected = file_record.get("digest")
        require(candidate.is_file() if expected else not candidate.exists(), f"manifest path mismatch: {path}")
        if expected:
            require(sha256_file(candidate) == expected, f"validated file changed: {path}")
            require(
                oct(candidate.stat().st_mode & 0o777) == file_record.get("mode"),
                f"validated file mode changed: {path}",
            )
    for record in readiness or []:
        require(record.get("ready") is True, "cross-repository readiness is missing")
        require(bool(record.get("commit")), "readiness record has no exact commit")
    return {"admitted": True, "headSha": actual_head, "verifiedAt": utc_now()}


def transition_event(event: dict[str, Any], target: str, evidence: list[dict[str, Any]]) -> dict[str, Any]:
    current = event.get("state", "detected")
    require(target in LEGAL_EVENT_TRANSITIONS.get(current, set()), f"illegal event transition: {current} -> {target}")
    require(bool(evidence), "event transition requires evidence")
    updated = json.loads(json.dumps(event))
    updated["state"] = target
    updated.setdefault("history", []).append(
        {"from": current, "to": target, "at": utc_now(), "evidence": evidence}
    )
    return updated


def release_transition(
    transaction: dict[str, Any],
    target: str,
    assets_dir: pathlib.Path,
    expected_assets: dict[str, str],
) -> dict[str, Any]:
    current = transaction.get("state", "requested")
    require(LEGAL_RELEASE_TRANSITIONS.get(current) == target, f"illegal release transition: {current} -> {target}")
    published = transaction.get("publishedAssets", {})
    if published:
        require(published == expected_assets, "published asset inconsistency")
    if target in {"draft_verified", "published", "public_verified", "complete"}:
        for name, digest in expected_assets.items():
            path = assets_dir / name
            require(path.is_file(), f"release asset is missing: {name}")
            require(sha256_file(path) == digest, f"release asset digest mismatch: {name}")
    updated = json.loads(json.dumps(transaction))
    updated["state"] = target
    updated["assetDigests"] = expected_assets
    if target == "published":
        updated["publishedAssets"] = expected_assets
    updated.setdefault("history", []).append({"from": current, "to": target, "at": utc_now()})
    return updated


def notification_decision(event: dict[str, Any], prior: dict[str, Any] | None) -> dict[str, Any]:
    fingerprint_fields = {
        "state": event.get("state"),
        "evidenceDigest": event.get("evidenceDigest"),
        "failureFingerprint": event.get("failureFingerprint"),
        "humanActionRequired": bool(event.get("humanActionRequired")),
        "finalResult": event.get("finalResult"),
    }
    fingerprint = sha256_bytes(canonical_json(fingerprint_fields))
    if prior and prior.get("fingerprint") == fingerprint:
        return {"action": "none", "fingerprint": fingerprint}
    if prior is None:
        action = "create_and_close" if event.get("state") == "complete" else "create"
    elif event.get("state") == "complete":
        action = "comment_and_close"
    else:
        action = "comment"
    severity = event.get("severity", "info")
    critical = severity == "critical"
    return {
        "action": action,
        "fingerprint": fingerprint,
        "critical": critical,
        "labels": ["maintenance", *(["attention-required"] if critical or event.get("humanActionRequired") else [])],
    }


def retained_notification_issue(prior: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return a usable retained issue identity without relying on search indexing."""
    issue = (prior or {}).get("issue")
    number = issue.get("number") if isinstance(issue, dict) else None
    if not isinstance(number, bool) and isinstance(number, int) and number > 0:
        return issue
    return None


def watch_decision(
    manifest: dict[str, Any],
    previous: dict[str, Any],
    events: Iterable[dict[str, Any]],
    health: dict[str, Any],
) -> dict[str, Any]:
    incomplete = sorted(
        event.get("actionKey")
        for event in events
        if event.get("state") != "complete"
    )
    if not health.get("healthy", False):
        trigger = "health_failed"
    elif any(capture.get("status") != 200 for capture in manifest.get("captures", [])):
        trigger = "source_unhealthy"
    elif incomplete:
        trigger = "event_incomplete"
    elif previous.get("manifestDigest") != manifest.get("manifestDigest"):
        trigger = "evidence_changed"
    else:
        trigger = "quiet"
    return {
        "schemaVersion": 1,
        "trigger": trigger,
        "manifestDigest": manifest.get("manifestDigest"),
        "incompleteActions": incomplete,
        "modelCall": trigger != "quiet",
    }


def retry_decision(
    event: dict[str, Any],
    failure_fingerprint: str,
    max_attempts: int,
) -> dict[str, Any]:
    require(0 < max_attempts <= 5, "retry budget is outside the reviewed bound")
    attempts = int(event.get("attemptCount", 0))
    previous = event.get("failureFingerprint")
    if previous == failure_fingerprint and attempts >= max_attempts:
        return {"recallAgent": False, "reason": "identical_failure_exhausted", "attemptCount": attempts}
    if previous == failure_fingerprint and event.get("lastRejectionRepeated", False):
        return {"recallAgent": False, "reason": "identical_rejection", "attemptCount": attempts}
    return {"recallAgent": attempts < max_attempts, "reason": "bounded_retry", "attemptCount": attempts + 1}


def mutation_allowed(operator_state: dict[str, Any]) -> bool:
    return operator_state.get("unattendedMutation") == "enabled"


def audit_reconstruction(event: dict[str, Any], root: pathlib.Path) -> dict[str, Any]:
    required = event.get("auditEvidence", [])
    require(isinstance(required, list) and bool(required), "event has no audit evidence")
    verified = []
    for item in required:
        require(isinstance(item, dict), "audit evidence entry must be an object")
        item_path = item.get("path")
        item_digest = item.get("digest")
        require(isinstance(item_digest, str) and SHA256_RE.fullmatch(item_digest), "audit evidence digest is missing")
        path = contained_path(root, item_path, "audit evidence path")
        require(path.is_file(), f"audit evidence is unavailable: {item_path}")
        require(sha256_file(path) == item_digest, f"audit evidence digest mismatch: {item_path}")
        verified.append(item_path)
    require(bool(event.get("actionKey")), "audit event has no action key")
    require(bool(event.get("history")), "audit event has no transition history")
    return {"reconstructed": True, "actionKey": event["actionKey"], "evidence": verified}


class RestrictedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        old = urllib.parse.urlparse(req.full_url)
        new = urllib.parse.urlparse(newurl)
        if new.scheme != "https" or new.hostname != old.hostname:
            raise urllib.error.HTTPError(newurl, code, "cross-host redirect rejected", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@dataclass(frozen=True)
class EvidenceSource:
    capture_id: str
    url: str
    max_bytes: int


EVIDENCE_SOURCES = (
    EvidenceSource("php_supported_versions", "https://www.php.net/supported-versions.php", 2_000_000),
    EvidenceSource("php_release_feed", "https://www.php.net/releases/index.php?json", 5_000_000),
    EvidenceSource("php_source_tags", "https://api.github.com/repos/php/php-src/tags?per_page=100", 5_000_000),
    EvidenceSource("php_bin_releases", "https://api.github.com/repos/bigpixelrocket/php-bin/releases?per_page=100", 10_000_000),
    EvidenceSource("php_bin_state", "https://api.github.com/repos/bigpixelrocket/php-bin/commits/main", 2_000_000),
    EvidenceSource("mise_php_releases", "https://api.github.com/repos/bigpixelrocket/mise-php/releases?per_page=100", 10_000_000),
    EvidenceSource("mise_php_state", "https://api.github.com/repos/bigpixelrocket/mise-php/commits/main", 2_000_000),
)


def capture_evidence(
    output_dir: pathlib.Path,
    sources: Iterable[EvidenceSource] = EVIDENCE_SOURCES,
    token: str | None = None,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    opener = urllib.request.build_opener(RestrictedRedirect)
    captures = []
    for source in sources:
        headers = {
            "Accept": "application/vnd.github+json, application/json, text/html",
            "User-Agent": "bigpixelrocket-maintenance/1",
        }
        if token and urllib.parse.urlparse(source.url).hostname == "api.github.com":
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(
            source.url,
            headers=headers,
        )
        last_error: Exception | None = None
        for attempt in range(3):
            if attempt:
                time.sleep(2**attempt)
            try:
                with opener.open(request, timeout=30) as response:
                    body = response.read(source.max_bytes + 1)
                    require(len(body) <= source.max_bytes, f"capture too large: {source.capture_id}")
                    body_path = pathlib.Path("raw") / f"{source.capture_id}.body"
                    destination = output_dir / body_path
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(body)
                    captures.append(
                        {
                            "captureId": source.capture_id,
                            "url": source.url,
                            "retrievedAt": utc_now(),
                            "status": response.status,
                            "contentType": response.headers.get("Content-Type"),
                            "etag": response.headers.get("ETag"),
                            "lastModified": response.headers.get("Last-Modified"),
                            "digest": sha256_bytes(body),
                            "bodyPath": body_path.as_posix(),
                        }
                    )
                    last_error = None
                    break
            except ControlError as error:
                last_error = error
                break
            except urllib.error.HTTPError as error:
                last_error = error
                if error.code not in {408, 429} and not 500 <= error.code < 600:
                    break
            except (OSError, urllib.error.URLError) as error:
                last_error = error
        if last_error is not None:
            body_path = pathlib.Path("raw") / f"{source.capture_id}.body"
            destination = output_dir / body_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(b"")
            captures.append(
                {
                    "captureId": source.capture_id,
                    "url": source.url,
                    "retrievedAt": utc_now(),
                    "status": 0,
                    "contentType": None,
                    "etag": None,
                    "lastModified": None,
                    "digest": sha256_bytes(b""),
                    "bodyPath": body_path.as_posix(),
                    "error": type(last_error).__name__,
                }
            )
    manifest = {
        "schemaVersion": 1,
        "capturedAt": utc_now(),
        "captures": captures,
        "manifestDigest": "",
    }
    comparable = [
        {
            "captureId": item["captureId"],
            "status": item["status"],
            "digest": item["digest"],
        }
        for item in captures
    ]
    manifest["manifestDigest"] = sha256_bytes(canonical_json(comparable))
    write_json(output_dir / "evidence-manifest.json", manifest)
    return manifest


def _archive_member_name(name: str) -> str:
    return name[2:] if name.startswith("./") else name


def validate_archive(archive: pathlib.Path, version: str) -> None:
    require(archive.name == f"php-{version}-cli-macos-aarch64.tar.gz", "unexpected archive name")
    try:
        with tarfile.open(archive, "r:gz") as handle:
            members = handle.getmembers()
    except tarfile.TarError as error:
        raise ControlError(f"cannot read archive {archive}: {error}") from error
    names = set()
    for member in members:
        normalized = pathlib.PurePosixPath(_archive_member_name(member.name))
        require(
            ".." not in normalized.parts
            and not normalized.is_absolute()
            and not member.name.startswith("/"),
            f"unsafe archive path: {member.name}",
        )
        require(not member.issym() and not member.islnk(), "archive contains a link")
        names.add(normalized.as_posix())
    require("bin/php" in names, "archive does not contain bin/php")


def cli_error(error: Exception) -> int:
    print(f"maintenance control rejected input: {error}", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    digest_parser = subparsers.add_parser("digest")
    digest_parser.add_argument("path", type=pathlib.Path)

    contract_parser = subparsers.add_parser("validate-contract")
    contract_parser.add_argument("--contract", required=True, type=pathlib.Path)
    contract_parser.add_argument("--assessment", required=True, type=pathlib.Path)

    capture_parser = subparsers.add_parser("capture-evidence")
    capture_parser.add_argument("--output", required=True, type=pathlib.Path)

    event_parser = subparsers.add_parser("transition-event")
    event_parser.add_argument("--event", required=True, type=pathlib.Path)
    event_parser.add_argument("--target", required=True)
    event_parser.add_argument("--evidence", required=True, type=pathlib.Path)
    event_parser.add_argument("--output", required=True, type=pathlib.Path)

    archive_parser = subparsers.add_parser("validate-archive")
    archive_parser.add_argument("--archive", required=True, type=pathlib.Path)
    archive_parser.add_argument("--version", required=True)

    subparsers.add_parser("validate-policy")

    args = parser.parse_args(argv)
    try:
        if args.command == "digest":
            print(sha256_file(args.path))
        elif args.command == "validate-contract":
            contract = load_json(args.contract)
            assessment = load_json(args.assessment)
            validate_completion_assessment(assessment, contract, assessment.get("instructionDigests"))
            print(json.dumps({"valid": True}))
        elif args.command == "capture-evidence":
            print(json.dumps(capture_evidence(args.output, token=os.environ.get("GITHUB_TOKEN"))))
        elif args.command == "transition-event":
            updated = transition_event(load_json(args.event), args.target, load_json(args.evidence))
            write_json(args.output, updated)
            print(json.dumps(updated))
        elif args.command == "validate-archive":
            validate_archive(args.archive, args.version)
            print(json.dumps({"valid": True}))
        elif args.command == "validate-policy":
            print(json.dumps(validate_support_policy(ROOT)))
        return 0
    except (ControlError, OSError, subprocess.CalledProcessError) as error:
        return cli_error(error)


if __name__ == "__main__":
    raise SystemExit(main())
