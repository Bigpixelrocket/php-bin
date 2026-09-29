"""Admission of autorelease work: the plan, the sealed patch, and the merge.

These are the three gates a classified plan and its repository change pass before
they can reach a protected branch or a release. Each one re-asserts the reviewed
bounds from the artefacts in front of it rather than trusting the code that produced
them, so admission stays an independent check on the deterministic classifier
(`_classifier`) and the lifecycle edits (`_implementation`).
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import json
import pathlib
import re
import subprocess
from typing import Any

from ._evidence import (
    STABLE_RELEASE_ACTIONS,
    branch_feed_capture_id,
    load_capture,
    load_plan_evidence,
    release_feed_capture_ids,
)
from ._validation import (
    ACTION_KEY_RE,
    COMMIT_SHA_RE,
    ROOT,
    SECRET_PATTERNS,
    SHA256_RE,
    STABLE_VERSION_RE,
    ControlError,
    canonical_json,
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
# Every committed path whose bytes decide what a release archive contains: the
# toolchain pin, the build and packaging scripts the publish job runs, the extension
# sets, and the files copied into every archive. Their identity at the commit a release
# was built from is recorded in its notes, so a later run can tell whether the current
# recipe would build different bytes and a rebuild is due. Each branch also covers its
# own `expected-modules/<branch>.txt` (see `recipe_identity`). Inputs outside the
# repository (the runner image, unpinned Homebrew packages) and the workflow definition
# are deliberately not covered: they change without a reviewed recipe change, and
# covering them would rebuild every release on an unrelated workflow edit.
RECIPE_INPUT_PATHS = (
    ".spc-sha256",
    ".spc-version",
    "LICENSE",
    "NOTICE",
    "patches",
    "scripts/build.sh",
    "scripts/install-build-deps.sh",
    "scripts/install-spc.sh",
    "scripts/lib.sh",
    "scripts/package.sh",
    "stages",
)
def validate_stable_release_evidence(
    action: str,
    release_intent: dict[str, Any] | None,
    resolved_evidence: list[dict[str, Any]],
) -> None:
    """Require a stable release to resolve exactly in an official PHP release feed.

    The aggregate feed names only the newest release of each major, so a patch on an
    older maintained branch is proven by that branch's own feed capture. A branch
    capture proves only its own branch: `8.4.26` never resolves from the 8.3 feed.
    """
    if action not in STABLE_RELEASE_ACTIONS:
        return
    require(isinstance(release_intent, dict), "stable release action has no release intent")
    version = release_intent.get("version")
    feeds = release_feed_capture_ids(version)
    require(
        any(
            item.get("captureId") in feeds and item.get("value") == version
            for item in resolved_evidence
        ),
        "stable release version is not exact evidence in the official PHP release feed",
    )


def validate_release_is_newest_patch(
    action: str,
    release_intent: dict[str, Any] | None,
    manifest_path: pathlib.Path,
) -> None:
    """Reject a stable release that a captured release feed already supersedes.

    The version's branch feed names the newest release of that branch and the
    aggregate feed the newest of its major, so either naming a later patch on the
    same branch makes the proposed version an intermediate one that would publish
    after its successor. Both feeds are read from the capture whether or not the
    plan cites them, so a plan cannot skip the check by citing less: the watcher's
    capture at admission, and the publish recapture again before building. Only
    official feeds count: a php-src tag can exist before its release and never
    supersedes one. The check rejects only on contrary evidence; a feed that is
    missing, unhealthy, unreadable, or names another branch leaves the decision to
    the proof requirement in `validate_stable_release_evidence`.
    """
    if action not in STABLE_RELEASE_ACTIONS:
        return
    require(isinstance(release_intent, dict), "stable release action has no release intent")
    version = release_intent.get("version")
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version) if isinstance(version, str) else None
    require(bool(match), f"stable release version is invalid: {version}")
    major, minor, patch = match.groups()
    manifest = load_json(manifest_path)
    captures = manifest.get("captures") if isinstance(manifest, dict) else None
    require(isinstance(captures, list), "evidence manifest captures must be an array")
    healthy = {
        capture.get("captureId")
        for capture in captures
        if isinstance(capture, dict) and capture.get("status") == 200
    }
    for capture_id, pointer in (
        (branch_feed_capture_id(f"{major}.{minor}"), "/version"),
        ("php_release_feed", f"/{major}/version"),
    ):
        if capture_id not in healthy:
            continue
        _capture, body = load_capture(manifest_path, capture_id)
        try:
            newest = resolve_json_pointer(json.loads(body), pointer)
        except (UnicodeDecodeError, json.JSONDecodeError, ControlError):
            continue
        same_branch = re.fullmatch(rf"{major}\.{minor}\.(\d+)", newest) if isinstance(newest, str) else None
        require(
            not same_branch or int(same_branch.group(1)) <= int(patch),
            f"stable release {version} is superseded by {newest} in {capture_id}",
        )


def validate_patch_extends_shipped_branch(
    action: str,
    release_intent: dict[str, Any] | None,
    manifest_path: pathlib.Path,
    completed_actions: set[str],
) -> None:
    """Reject a `new_patch` that would be the first release on its branch.

    A branch's first release is a `new_branch`, which publishes only after exact
    `php_bin_ready` and `mise_ready` records, so a plain patch must never stand in for
    it. A branch has shipped when the captured php-bin releases hold a published
    release on it, or a completed event record names a release on it.
    """
    if action != "new_patch":
        return
    require(isinstance(release_intent, dict), "stable release action has no release intent")
    match = re.fullmatch(r"(\d+\.\d+)\.\d+", str(release_intent.get("version", "")))
    require(bool(match), f"stable release version is invalid: {release_intent.get('version')}")
    branch = match.group(1)
    require(
        branch_has_shipped(manifest_path, branch, completed_actions),
        f"new_patch would be the first PHP {branch} release; only new_branch may publish it",
    )


def branch_has_shipped(manifest_path: pathlib.Path, branch: str, completed_actions: set[str]) -> bool:
    """Tell whether a PHP branch already has a release.

    A branch has shipped when the captured php-bin releases hold a published release
    on it, or a completed event record names a release on it.
    """
    _capture, body = load_capture(manifest_path, "php_bin_releases")
    try:
        releases = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ControlError("php-bin releases capture is not valid JSON") from error
    require(isinstance(releases, list), "php-bin releases capture is not a release array")
    return any(
        isinstance(release, dict)
        and not release.get("draft")
        and not release.get("prerelease")
        and bool(STABLE_VERSION_RE.fullmatch(str(release.get("tag_name", ""))))
        and str(release.get("tag_name")).startswith(f"{branch}.")
        for release in releases
    ) or any(
        key == f"new_branch:{branch}"
        or bool(re.fullmatch(rf"(?:new_patch|recipe_rebuild):{re.escape(branch)}\.\d+(?::\d+)?", key))
        for key in completed_actions
    )


def validate_recipe_rebuild_evidence(
    action: str,
    action_key: str,
    resolved_evidence: list[dict[str, Any]],
) -> None:
    """Require a rebuild to cite the published release it supersedes.

    `recipe_rebuild:<version>:<n>` rebuilds the newest published revision of that
    version: `<version>` itself for the first rebuild, `<version>-<n-1>` after that.
    """
    if action != "recipe_rebuild":
        return
    _prefix, version, revision = action_key.split(":")
    rebuilt = version if revision == "1" else f"{version}-{int(revision) - 1}"
    require(
        any(
            item.get("captureId") == "php_bin_releases" and item.get("value") == rebuilt
            for item in resolved_evidence
        ),
        "recipe rebuild does not cite the published release it supersedes",
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
    branches, evidence = _validate_support_policy_document(policy, invariants_path)
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
        "maintainedBranches": branches,
    }


LIFECYCLE_ACTION_KEY_RE = re.compile(r"new_branch:(\d+\.\d+)|branch_eol:(\d+\.\d+):\d{4}-\d{2}-\d{2}")


def is_lifecycle_resume(plan: dict[str, Any]) -> bool:
    """Tell whether a plan resumes a lifecycle edit that already merged.

    A lifecycle plan that requires the implementation run but allows no path can change
    nothing: its edit is already on the base, and only the clean validation, a new
    branch's real build, and the `php_bin_ready` record are still owed. Admission, the
    implementation, and sealing each re-check that the edit is really there
    (`validate_lifecycle_on_base`) before anything runs on it.
    """
    allowed = plan.get("allowedPaths")
    return (
        plan.get("action") in {"new_branch", "branch_eol"}
        and plan.get("editsRequired") is True
        and isinstance(allowed, dict)
        and not any(allowed.values())
    )


def recorded_action_keys(directory: pathlib.Path) -> set[str]:
    """Return the action key of every durable event record in `directory`, failing closed."""
    require(directory.is_dir(), f"events directory is missing: {directory}")
    keys = set()
    for path in sorted(directory.glob("*.json")):
        record = load_json(path)
        key = record.get("actionKey") if isinstance(record, dict) else None
        require(
            isinstance(key, str) and bool(ACTION_KEY_RE.fullmatch(key)),
            f"event record carries no valid action key: {path.name}",
        )
        keys.add(key)
    return keys


def validate_lifecycle_on_base(
    repo: pathlib.Path,
    plan: dict[str, Any],
    recorded_keys: set[str] | None,
) -> str:
    """Require a resumed lifecycle edit to be fully present in `repo`, and return its branch.

    `repo` is a clean tree of the plan's base. The deterministic edit binds the policy
    it writes to its own action key, so an accepted policy carrying the plan's key is
    that edit's output. A `new_branch` must then maintain the branch and carry its
    module list, which the edit never overwrites once present, so a list corrected by
    reviewed pull request still counts. A `branch_eol` must no longer maintain the
    branch. The policy's evidence digests and acceptance time belong to the capture
    that first admitted the edit and are only validated for shape here.

    No event record may exist for the key: an incomplete one resumes through its own
    next transition instead, and a complete one means the action already finished.
    `recorded_keys` is None when the records could not be read, which rejects.
    """
    key = str(plan.get("actionKey", ""))
    match = LIFECYCLE_ACTION_KEY_RE.fullmatch(key)
    require(
        bool(match) and key.startswith(f"{plan.get('action')}:"),
        f"lifecycle action key is invalid: {key}",
    )
    branch = match.group(1) or match.group(2)
    maintained = validate_support_policy(repo)["maintainedBranches"]
    policy = load_json(repo / "support-policy.json")
    require(policy.get("actionKey") == key, f"the accepted support policy was not written by {key}")
    if plan.get("action") == "new_branch":
        require(branch in maintained, f"the accepted support policy does not maintain PHP {branch}")
        modules = repo / f"expected-modules/{branch}.txt"
        require(
            modules.is_file() and not modules.is_symlink(),
            f"the module list of PHP {branch} is missing",
        )
    else:
        require(branch not in maintained, f"the accepted support policy still maintains PHP {branch}")
    require(recorded_keys is not None, f"the event records needed to resume {key} were not supplied")
    require(key not in recorded_keys, f"an event record for {key} already exists")
    return branch


PLAN_FIELDS = frozenset(
    {
        "schemaVersion",
        "actionKey",
        "action",
        "evidence",
        "repositories",
        "preconditions",
        "editsRequired",
        "allowedPaths",
        "requiredChecks",
        "releaseIntent",
        "notification",
        "risk",
        "summary",
    }
)
PLAN_ACTIONS = frozenset(
    {"no_change", "new_patch", "new_branch", "branch_eol", "recipe_rebuild", "blocked", "needs_human"}
)
# A plan that stops the run, or records evidence as reviewed, authorizes no work at all.
NO_WORK_ACTIONS = frozenset({"no_change", "blocked", "needs_human"})


def _require_no_work(plan: dict[str, Any], label: str) -> None:
    require(plan.get("editsRequired") is False, f"{label} plan cannot require edits")
    allowed_paths = plan.get("allowedPaths")
    require(
        isinstance(allowed_paths, dict) and not any(allowed_paths.values()),
        f"{label} plan cannot allow paths",
    )
    require(plan.get("releaseIntent") is None, f"{label} plan cannot request a release")


def _validate_plan_shape(
    plan: dict[str, Any],
    manifest_path: pathlib.Path,
    completed_actions: set[str] | None,
    pending_rebuild: str | None = None,
) -> str:
    """Reject a plan whose identity is wrong, and return the action key it claims.

    Nothing later in admission means anything until the plan has exactly the reviewed
    fields, names one reviewed action and one well-formed key that no completed event
    already owns.

    `pending_rebuild` is the rebuild the watcher selected deterministically from the
    same capture and recipe, or None when none is due. A rebuild plan must name exactly
    that key, and no plan may record the evidence as unchanged while one is due, so a
    pending rebuild can neither be invented nor silenced by the classifier.
    """
    require(isinstance(plan, dict), "autorelease plan must be an object")
    require(set(plan) == PLAN_FIELDS, "autorelease plan fields are unknown or missing")
    require(plan.get("schemaVersion") == 1, "unsupported autorelease plan version")
    action = plan.get("action")
    require(action in PLAN_ACTIONS, "invalid autorelease action")
    action_key = plan.get("actionKey", "")
    require(isinstance(action_key, str) and bool(ACTION_KEY_RE.fullmatch(action_key)), "invalid action key")
    require(plan.get("editsRequired") in {True, False}, "plan must declare whether edits are required")
    if action in {"new_patch", "new_branch", "branch_eol"}:
        require(action_key.startswith(f"{action}:"), "action key does not match its action")
    if action in NO_WORK_ACTIONS:
        _require_no_work(plan, action.replace("_", "-"))
    if action == "no_change":
        manifest_digest = load_json(manifest_path).get("manifestDigest", "")
        require(
            action_key == f"no_change:{manifest_digest.removeprefix('sha256:')[:16]}",
            "no-change action key is not bound to the evidence manifest",
        )
        require(not pending_rebuild, f"no-change plan cannot leave a due rebuild pending: {pending_rebuild}")
    elif action == "recipe_rebuild":
        require(
            bool(pending_rebuild) and action_key == pending_rebuild,
            f"recipe rebuild is not the selected rebuild: {pending_rebuild or 'none is due'}",
        )
        _prefix, version, revision = action_key.split(":")
        require(plan.get("editsRequired") is False, "recipe rebuild plan cannot require edits")
        allowed_paths = plan.get("allowedPaths")
        require(
            isinstance(allowed_paths, dict) and not any(allowed_paths.values()),
            "recipe rebuild plan cannot allow paths",
        )
        release_intent = plan.get("releaseIntent")
        require(
            isinstance(release_intent, dict) and release_intent.get("version") == f"{version}-{revision}",
            "recipe rebuild release intent is not the selected revision",
        )
    require(
        action_key not in (completed_actions or set()),
        "action key already completed",
    )
    return action_key


def _validate_plan_preconditions(
    plan: dict[str, Any],
    repo_heads: dict[str, str] | None,
    policy_digest: str | None,
) -> dict[str, Any]:
    """Bind the plan to the exact repository and policy state it was classified against."""
    declared_heads = plan.get("preconditions")
    require(isinstance(declared_heads, dict), "preconditions must be an object")
    require(
        set(declared_heads) == {"phpBinHead", "misePhpHead", "supportPolicyDigest"},
        "plan preconditions are unknown or missing",
    )
    if repo_heads:
        for key, value in repo_heads.items():
            require(declared_heads.get(key) == value, f"stale repository precondition: {key}")
    if policy_digest is not None:
        require(
            declared_heads.get("supportPolicyDigest") == policy_digest,
            "stale support policy precondition",
        )
    return declared_heads


def _validate_plan_actions(
    plan: dict[str, Any],
    manifest_path: pathlib.Path,
) -> None:
    """Reject the effects the plan asks for: evidence, paths, checks, and release.

    Every claim is re-derived from the captured bodies and the reviewed bounds
    rather than trusted from the plan that asserts it.
    """
    evidence = plan.get("evidence")
    require(isinstance(evidence, list) and bool(evidence), "plan cites no evidence")
    resolved_evidence = []
    for item in evidence:
        require(isinstance(item, dict), "plan evidence entry must be an object")
        capture, body = load_plan_evidence(manifest_path, item.get("captureId", ""))
        require(item.get("digest") == capture["digest"], "plan evidence digest mismatch")
        locator = item.get("locator", {})
        require(isinstance(locator, dict), "plan evidence locator must be an object")
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
        resolved_evidence.append({"captureId": item.get("captureId"), "value": resolved_value})
    allowed_paths = plan.get("allowedPaths", {})
    require(isinstance(allowed_paths, dict), "allowedPaths must be an object")
    require(set(allowed_paths) == {"php-bin", "mise-php"}, "allowedPaths repositories changed")
    for patterns in allowed_paths.values():
        require(isinstance(patterns, list), "allowed path set must be an array")
        for pattern in patterns:
            require(isinstance(pattern, str) and bool(pattern), "allowed path must be a non-empty string")
            pure = pathlib.PurePosixPath(pattern)
            require(not pure.is_absolute() and ".." not in pure.parts, f"unsafe allowed path: {pattern}")
            require(
                not path_is_protected(pattern),
                f"protected path cannot be admitted for runtime editing: {pattern}",
            )
            if fnmatch.fnmatch("support-policy.json", pattern):
                require(plan.get("risk") == "lifecycle", "support state requires lifecycle risk")
                require(plan.get("action") in {"new_branch", "branch_eol"}, "support state requires a lifecycle action")
    require(
        plan.get("editsRequired") is False or plan.get("action") in {"new_branch", "branch_eol"},
        "only a lifecycle plan may require repository edits",
    )
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
    validate_release_is_newest_patch(plan.get("action", ""), release_intent, manifest_path)
    validate_recipe_rebuild_evidence(plan.get("action", ""), plan.get("actionKey", ""), resolved_evidence)


def validate_plan(
    plan: dict[str, Any],
    manifest_path: pathlib.Path,
    repo_heads: dict[str, str] | None = None,
    policy_digest: str | None = None,
    completed_actions: set[str] | None = None,
    pending_rebuild: str | None = None,
    repo: pathlib.Path | None = None,
    recorded_keys: set[str] | None = None,
) -> dict[str, Any]:
    """Admit one classified plan, or reject it.

    Admission is the independent second check on the deterministic classifier: it
    shares no decision logic with it and re-derives every claim from the capture. The
    three gates run in a fixed order: what the plan is, what state it was classified
    against, and what it asks for. A later gate reads values the earlier one proved,
    so none of them is safe to reorder. A `new_patch` must finally extend a branch that
    already shipped, which needs the completed records the watcher supplied.

    A lifecycle resume (`is_lifecycle_resume`) is also checked against `repo`, the
    checked-out base, and `recorded_keys`, the action keys of its event records: the
    policy there must be the one the plan was classified against and already hold the
    lifecycle edit, no record may exist for the key, and a resumed new branch must not
    have shipped. Without both inputs a resume is rejected.
    """
    action_key = _validate_plan_shape(plan, manifest_path, completed_actions, pending_rebuild)
    declared = _validate_plan_preconditions(plan, repo_heads, policy_digest)
    _validate_plan_actions(plan, manifest_path)
    validate_patch_extends_shipped_branch(
        plan.get("action", ""), plan.get("releaseIntent"), manifest_path, completed_actions or set()
    )
    if is_lifecycle_resume(plan):
        require(repo is not None, "a lifecycle resume is admitted only against the checked-out base")
        require(
            sha256_file(repo / "support-policy.json") == declared.get("supportPolicyDigest"),
            "the checked-out support policy is not the one the plan was classified against",
        )
        branch = validate_lifecycle_on_base(repo, plan, recorded_keys)
        require(
            plan.get("action") != "new_branch"
            or not branch_has_shipped(manifest_path, branch, completed_actions or set()),
            f"PHP {branch} already shipped, so its new_branch lifecycle cannot resume",
        )
    return {
        "admitted": True,
        "admittedAt": utc_now(),
        "actionKey": action_key,
        "planDigest": sha256_bytes(canonical_json(plan)),
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


def recipe_identity(repo: pathlib.Path, commit: str, branch: str) -> str:
    """Digest the recipe inputs one PHP branch is built from at one exact commit.

    The digest covers the committed tree entries (path, mode, and blob) under
    `RECIPE_INPUT_PATHS` plus that branch's `expected-modules/<branch>.txt`, never the
    working tree, so the watcher, admission, and the publish transaction agree for the
    same commit even after a build has written beside them. Only the branch's own
    module list is covered, so adding a new branch, or changing another branch's list,
    rebuilds nothing already published on this one.
    """
    require(bool(COMMIT_SHA_RE.fullmatch(commit or "")), "recipe commit is not an exact commit SHA")
    require(bool(re.fullmatch(r"\d+\.\d+", branch or "")), f"recipe branch is invalid: {branch}")
    listing = git(
        repo,
        "ls-tree",
        "-r",
        "--full-tree",
        commit,
        "--",
        *RECIPE_INPUT_PATHS,
        f"expected-modules/{branch}.txt",
    ).stdout
    require(bool(listing.strip()), "recipe inputs are missing at the commit")
    return sha256_bytes(listing.encode())


def changed_paths(repo: pathlib.Path, base: str) -> list[str]:
    result = git(repo, "diff", "--name-only", "--diff-filter=ACDMRTUXB", base, "--")
    paths = [line for line in result.stdout.splitlines() if line]
    untracked = git(repo, "ls-files", "--others", "--exclude-standard").stdout.splitlines()
    return sorted(set(paths + untracked))


def seal_patch(
    repo: pathlib.Path,
    base: str,
    plan: dict[str, Any],
    output_dir: pathlib.Path,
) -> dict[str, Any]:
    """Seal the working-tree diff of one admitted plan against its exact base.

    Only admitted, unprotected, small UTF-8 text files may change, and a regenerated
    `support-policy.json` must validate against the reviewed invariants and be bound
    to the plan's own evidence digests and action key. The sealed patch and its file
    digests are what clean validation applies and what the exact-SHA merge gate
    compares, so nothing written after sealing can reach main.

    The one legal empty patch is a lifecycle resume whose edit is verifiably already
    on the base: the manifest then says `alreadyApplied` and seals no file, and the
    base itself is what gets validated, built, and recorded.
    """
    require(bool(COMMIT_SHA_RE.fullmatch(base or "")), "base is not an exact commit SHA")
    require(git(repo, "rev-parse", f"{base}^{{commit}}").stdout.strip() == base, "base is not an exact commit")
    paths = changed_paths(repo, base)
    already_applied = not paths and is_lifecycle_resume(plan)
    if already_applied:
        validate_lifecycle_on_base(repo, plan, recorded_action_keys(repo / "autorelease-events"))
    else:
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
    # The patch is sealed as the exact bytes git wrote. Decoding it as text would
    # translate line endings and re-encode content, so `git apply` would receive a
    # patch other than the one whose digest the manifest records.
    tracked = subprocess.run(
        ["git", "diff", "--binary", "--full-index", base, "--"],
        cwd=repo,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    patch_parts = [tracked.stdout]
    for path in git(repo, "ls-files", "--others", "--exclude-standard").stdout.splitlines():
        proc = subprocess.run(
            ["git", "diff", "--binary", "--no-index", "--", "/dev/null", path],
            cwd=repo,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        require(proc.returncode in {0, 1}, f"failed to serialize untracked path: {path}")
        patch_parts.append(proc.stdout)
    patch_path.write_bytes(b"".join(patch_parts))
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
        "alreadyApplied": already_applied,
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
    """Admit the merge of one validated commit, or raise.

    The checked-out head must be the validated SHA, a single commit on the sealed
    base whose diff is exactly the sealed file set, byte for byte and mode for mode.
    Every check in `REQUIRED_PLAN_CHECKS` must be reported as successful, the
    recorded preconditions must still hold, and any readiness record must be ready.

    An `alreadyApplied` manifest seals no file, so there is nothing to merge: the
    validated head must be the sealed base itself and still be main, which the
    unchanged preconditions prove.
    """
    require(bool(COMMIT_SHA_RE.fullmatch(expected_head or "")), "expected head is not an exact commit SHA")
    actual_head = git(repo, "rev-parse", "HEAD").stdout.strip()
    require(actual_head == expected_head, "PR head does not equal validated SHA")
    require(checks and all(value == "success" for value in checks.values()), "required checks did not succeed")
    # Every reported check passing proves nothing when a required one was never reported.
    require(
        all(checks.get(name) == "success" for name in REQUIRED_PLAN_CHECKS),
        "a required check was not reported as successful",
    )
    require(preconditions == current, "merge preconditions changed")
    base_sha = manifest.get("baseSha")
    require(bool(COMMIT_SHA_RE.fullmatch(base_sha or "")), "sealed manifest has no exact base SHA")
    file_records = manifest.get("files", [])
    require(isinstance(file_records, list), "sealed manifest files are invalid")
    if manifest.get("alreadyApplied") is True:
        require(not file_records, "an already-applied manifest cannot seal file changes")
        require(expected_head == base_sha, "an already-applied lifecycle must validate its sealed base itself")
        require(current.get("phpBinHead") == expected_head, "main is not the validated commit")
    else:
        require(bool(file_records), "a sealed manifest without files must be an already-applied lifecycle")
        _verify_sealed_commit(repo, expected_head, base_sha, file_records)
    for record in readiness or []:
        require(record.get("ready") is True, "cross-repository readiness is missing")
        require(bool(record.get("commit")), "readiness record has no exact commit")
    return {"admitted": True, "headSha": actual_head, "verifiedAt": utc_now()}


def _verify_sealed_commit(
    repo: pathlib.Path,
    expected_head: str,
    base_sha: str,
    file_records: list[Any],
) -> None:
    """Require `expected_head` to be one commit on `base_sha` changing exactly the sealed files."""
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
