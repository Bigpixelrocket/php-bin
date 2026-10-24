"""Deterministic repository edits for admitted lifecycle plans.

A `new_branch` plan adds `expected-modules/<branch>.txt` and regenerates
`support-policy.json` with the branch added. The module list is the one the branch's
discovery build produced (`DISCOVER_MODULE_LIST` in `scripts/build.sh`): what actually
built, plus a `!<extension>` line for each extension that did not compile and was left
out. Without a discovered list it is copied byte for byte from the newest branch the
accepted policy already maintains. A `branch_eol` plan regenerates the policy
with the branch removed and leaves its module list in place, so historical rebuild
inputs stay reviewable. The new policy is bound to the plan's own evidence digests and
action key, and accepted at the capture time, so the same admitted plan always
produces the same bytes.

A lifecycle resume (`_admission.is_lifecycle_resume`) allows no path at all: its edit
merged in an earlier run that stopped before recording readiness. The edit is then
verified present on the base and nothing is written, so the run validates, builds, and
records the exact commit already on main.

These edits are proposals, not authority. `_admission.seal_patch` re-checks every path
against the plan, the policy against its invariants and evidence, and the clean
validation and exact-SHA merge gates run after it. A module list that does not match
the new branch's real build fails the exact module comparison of that build and stops
with an owner issue. A list already on the base, such as one a human corrected by pull
request, is never overwritten.
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import re
from typing import Any

from ._admission import (
    is_lifecycle_resume,
    recorded_action_keys,
    validate_lifecycle_on_base,
    validate_support_policy,
)
from ._validation import ControlError, contained_path, require, sha256_file


LIFECYCLE_ACTIONS = frozenset({"new_branch", "branch_eol"})
MODULE_LINE_RE = re.compile(r"!?[a-z][a-z0-9_]*")


def canonical_module_list(text: str) -> str:
    """Validate a discovered module list and return it in its one canonical form.

    Every line is a normalized module name or `!<extension>`; at least one module is
    listed, nothing repeats, and no name is both built and left out. The canonical form
    lists the modules sorted, then the left-out extensions sorted, so the same build
    always yields the same bytes.
    """
    lines = text.splitlines()
    require(all(MODULE_LINE_RE.fullmatch(line) for line in lines), "module list has an invalid line")
    require(len(lines) == len(set(lines)), "module list repeats a line")
    modules = sorted(line for line in lines if not line.startswith("!"))
    unbuilt = sorted(line[1:] for line in lines if line.startswith("!"))
    require(bool(modules), "module list names no module")
    require(not set(modules) & set(unbuilt), "module list both builds and leaves out the same name")
    return "".join(f"{name}\n" for name in modules) + "".join(f"!{name}\n" for name in unbuilt)


def _branch_key(branch: str) -> tuple[int, ...]:
    return tuple(int(part) for part in branch.split("."))


def render_support_policy(policy: dict[str, Any]) -> str:
    """Render a support policy in the repository's reviewed layout.

    Keys keep their reviewed order and every list stays on one line, which is how
    `support-policy.json` has always been written, so a regenerated policy diffs as
    exactly the fields that changed.
    """
    lines = []
    for key in (
        "schemaVersion",
        "policyInvariantsDigest",
        "maintainedBranches",
        "sourceEvidenceDigests",
        "actionKey",
        "acceptedAt",
    ):
        value = policy[key]
        rendered = (
            "[" + ", ".join(json.dumps(item) for item in value) + "]"
            if isinstance(value, list)
            else json.dumps(value)
        )
        lines.append(f"  {json.dumps(key)}: {rendered}")
    return "{\n" + ",\n".join(lines) + "\n}\n"


def apply_lifecycle_plan(
    repo: pathlib.Path,
    plan: dict[str, Any],
    manifest: dict[str, Any],
    module_list: str | None = None,
) -> list[str]:
    """Write the edits one admitted lifecycle plan requires, and return the changed paths.

    `repo` is a checkout of the plan's exact base commit and `manifest` the evidence
    manifest the plan was admitted against. The accepted policy in `repo` must still
    validate, and a plan for any other action is rejected: only lifecycle work edits the
    repository. A lifecycle resume writes nothing and returns no path, once its edit is
    verified present and no event record exists for it. `module_list` is the new
    branch's discovered list; only a `new_branch` edit that writes a list accepts one.
    """
    action = plan.get("action")
    require(action in LIFECYCLE_ACTIONS, f"no deterministic repository edit exists for action: {action}")
    require(plan.get("editsRequired") is True, "lifecycle plan does not require edits")
    if is_lifecycle_resume(plan):
        require(module_list is None, "a lifecycle resume writes no module list")
        validate_lifecycle_on_base(repo, plan, recorded_action_keys(repo / "autorelease-events"))
        return []
    require(module_list is None or action == "new_branch", "only a new branch takes a module list")
    key = plan.get("actionKey", "")
    match = re.fullmatch(r"(?:new_branch:(\d+\.\d+)|branch_eol:(\d+\.\d+):\d{4}-\d{2}-\d{2})", key)
    require(bool(match), f"lifecycle action key is invalid: {key}")
    branch = match.group(1) or match.group(2)
    maintained = list(validate_support_policy(repo)["maintainedBranches"])
    captured_at = manifest.get("capturedAt") if isinstance(manifest, dict) else None
    try:
        dt.datetime.strptime(captured_at or "", "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ControlError("evidence manifest capture time is invalid") from error
    changed = []
    if action == "new_branch":
        require(branch not in maintained, f"PHP {branch} is already maintained")
        older = [item for item in maintained if _branch_key(item) < _branch_key(branch)]
        require(bool(older), f"no maintained branch precedes PHP {branch} to copy its module list from")
        target = contained_path(repo, f"expected-modules/{branch}.txt", "module list path")
        require(
            module_list is None or not target.exists(),
            f"PHP {branch} already has a module list, which a discovered one never replaces",
        )
        if not target.exists():
            if module_list is not None:
                target.write_text(canonical_module_list(module_list))
            else:
                source = contained_path(repo, f"expected-modules/{older[-1]}.txt", "module list path")
                require(source.is_file(), f"module list of PHP {older[-1]} is missing")
                target.write_bytes(source.read_bytes())
            changed.append(f"expected-modules/{branch}.txt")
        branches = sorted({*maintained, branch}, key=_branch_key)
    else:
        require(branch in maintained, f"PHP {branch} is not maintained")
        branches = [item for item in maintained if item != branch]
    evidence = plan.get("evidence")
    require(isinstance(evidence, list) and bool(evidence), "lifecycle plan cites no evidence")
    policy = {
        "schemaVersion": 1,
        "policyInvariantsDigest": sha256_file(repo / "autorelease/policy-invariants.json"),
        "maintainedBranches": branches,
        "sourceEvidenceDigests": sorted({item["digest"] for item in evidence}),
        "actionKey": key,
        "acceptedAt": captured_at,
    }
    (repo / "support-policy.json").write_text(render_support_policy(policy))
    changed.append("support-policy.json")
    return sorted(changed)
