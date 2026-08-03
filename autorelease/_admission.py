"""Admission of agent work: the plan, the sealed patch, and the merge.

These are the three gates a model-authored change passes before it can reach a
protected branch. Each one re-asserts the reviewed bounds from the artefacts in
front of it rather than trusting the phase that produced them.
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import json
import pathlib
import re
import subprocess
from typing import Any

from ._evidence import load_plan_evidence
from ._validation import (
    ACTION_KEY_RE,
    COMMIT_SHA_RE,
    COMPLETION_EVIDENCE_REF_RE,
    ROOT,
    SECRET_PATTERNS,
    SHA256_RE,
    STABLE_VERSION_RE,
    ControlError,
    canonical_json,
    instruction_digest,
    load_json,
    path_is_allowed,
    path_is_protected,
    require,
    resolve_json_pointer,
    sha256_bytes,
    sha256_file,
    utc_now,
    write_json,
)


REQUIRED_PLAN_CHECKS = ["Script checks"]
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


def validate_stable_release_evidence(
    action: str,
    release_intent: dict[str, Any] | None,
    resolved_evidence: list[dict[str, Any]],
) -> None:
    if action not in {"new_patch", "new_branch"}:
        return
    require(isinstance(release_intent, dict), "stable release action has no release intent")
    version = release_intent.get("version")
    require(
        any(
            item.get("captureId") == "php_release_feed" and item.get("value") == version
            for item in resolved_evidence
        ),
        "stable release version is not exact evidence in the official PHP release feed",
    )


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
    invariants_path = root / "autorelease/policy-invariants.json"
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


def _validate_plan_shape(
    plan: dict[str, Any],
    manifest_path: pathlib.Path,
    completed_actions: set[str] | None,
) -> str:
    """Reject a plan whose identity is wrong, and return the action key it claims.

    Nothing later in admission means anything until the plan names one reviewed
    action and one well-formed key that no completed event already owns.
    """
    require(plan.get("schemaVersion") == 1, "unsupported autorelease plan version")
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
        "invalid autorelease action",
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
    return action_key


def _validate_plan_preconditions(
    plan: dict[str, Any],
    contract: dict[str, Any],
    shared_path: pathlib.Path,
    phase_path: pathlib.Path,
    event_contract_path: pathlib.Path,
    repo_heads: dict[str, str] | None,
    policy_digest: str | None,
) -> tuple[dict[str, str], dict[str, Any]]:
    """Bind the plan to the instructions it was written against and the state it saw.

    Returns the instruction digests the admission record carries and the declared
    preconditions, which the plan's own evidence references are resolved against.
    """
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
    return expected_digests, declared_heads


def _validate_plan_actions(
    plan: dict[str, Any],
    manifest_path: pathlib.Path,
    declared_heads: dict[str, Any],
) -> None:
    """Reject the effects the plan asks for: evidence, paths, release, and budgets.

    Every claim is re-derived from the captured bodies and the reviewed bounds
    rather than trusted from the plan that asserts it.
    """
    evidence_refs = {}
    resolved_evidence = []
    for index, evidence in enumerate(plan.get("evidence", [])):
        capture, body = load_plan_evidence(manifest_path, evidence.get("captureId", ""))
        require(evidence.get("digest") == capture["digest"], "plan evidence digest mismatch")
        locator = evidence.get("locator", {})
        if locator.get("kind") == "json_pointer":
            try:
                document = json.loads(body)
            except json.JSONDecodeError as error:
                raise ControlError("JSON locator targets a non-JSON capture") from error
            resolved_value = resolve_json_pointer(document, locator.get("value", ""))
        elif locator.get("kind") == "text_fragment":
            fragment = locator.get("value", "")
            require(bool(fragment) and fragment.encode() in body, "text locator does not resolve")
            resolved_value = fragment
        else:
            raise ControlError("unsupported evidence locator")
        evidence_refs[f"evidence[{index}]"] = evidence
        resolved_evidence.append(
            {"captureId": evidence.get("captureId"), "value": resolved_value}
        )
    research_sources = plan.get("researchSources", [])
    require(isinstance(research_sources, list), "researchSources must be an array")
    precondition_refs = {f"preconditions.{key}" for key in declared_heads}
    source_refs = {f"researchSources[{index}]" for index in range(len(research_sources))}
    for result in plan["completionAssessment"]["criteria"]:
        for reference in result["evidence"]:
            require(
                bool(COMPLETION_EVIDENCE_REF_RE.fullmatch(reference)),
                f"invalid criterion evidence reference: {reference}",
            )
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
    require(plan.get("requiredChecks") == REQUIRED_PLAN_CHECKS, "required deterministic checks changed")
    release_intent = plan.get("releaseIntent")
    if release_intent is not None:
        require(isinstance(release_intent, dict), "releaseIntent must be an object or null")
        version = release_intent.get("version", "")
        require(bool(STABLE_VERSION_RE.fullmatch(version)), "release version is not stable")
        require(
            not re.search(r"(?:alpha|beta|rc|dev)", version, re.I),
            "prerelease intent is forbidden",
        )
    validate_stable_release_evidence(plan.get("action", ""), release_intent, resolved_evidence)
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
    """Admit one agent plan, or reject it.

    The three gates run in a fixed order: what the plan is, what it was written
    against, and what it asks for. A later gate reads values the earlier one
    proved, so none of them is safe to reorder.
    """
    action_key = _validate_plan_shape(plan, manifest_path, completed_actions)
    expected_digests, declared_heads = _validate_plan_preconditions(
        plan,
        contract,
        shared_path,
        phase_path,
        event_contract_path,
        repo_heads,
        policy_digest,
    )
    _validate_plan_actions(plan, manifest_path, declared_heads)
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
    require(bool(COMMIT_SHA_RE.fullmatch(base or "")), "base is not an exact commit SHA")
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
                    repo / "autorelease/policy-invariants.json",
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
    require(bool(COMMIT_SHA_RE.fullmatch(expected_head or "")), "expected head is not an exact commit SHA")
    actual_head = git(repo, "rev-parse", "HEAD").stdout.strip()
    require(actual_head == expected_head, "PR head does not equal validated SHA")
    require(checks and all(value == "success" for value in checks.values()), "required checks did not succeed")
    require(preconditions == current, "merge preconditions changed")
    base_sha = manifest.get("baseSha")
    require(bool(COMMIT_SHA_RE.fullmatch(base_sha or "")), "sealed manifest has no exact base SHA")
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
