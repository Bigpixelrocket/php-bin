"""Event, release, and watcher state machines.

Every legal transition, the one name an action key may occupy, and the single
routing table the watcher follows live here. These functions decide what happens
next from recorded state alone; they never fetch evidence or admit a plan.
"""

from __future__ import annotations

import json
import pathlib
import re
from typing import Any, Iterable

from ._validation import (
    ACTION_KEY_RE,
    SHA256_RE,
    ControlError,
    canonical_json,
    contained_path,
    require,
    sha256_bytes,
    sha256_file,
    utc_now,
)


# A zero patch component is deliberately excluded: `8.6.0` is equally the tag of a
# `new_branch:8.6` action, so its action key is not derivable from the tag alone.
RECOVERABLE_RELEASE_TAG_RE = re.compile(r"^(\d+\.\d+\.[1-9]\d*)(?:-([1-9]\d*))?$")
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


def validate_completed_event_record(record: dict[str, Any]) -> None:
    """Validate a durable event as a complete, contiguous legal transition history."""

    require(isinstance(record, dict), "autorelease event must be an object")
    require(record.get("schemaVersion") == 1, "autorelease event version is invalid")
    require(bool(ACTION_KEY_RE.fullmatch(record.get("actionKey", ""))), "autorelease event action key is invalid")
    require(record.get("state") == "complete", "autorelease event is not complete")
    history = record.get("history")
    require(isinstance(history, list) and bool(history), "autorelease event has no transition history")
    current = history[0].get("from") if isinstance(history[0], dict) else None
    for transition in history:
        require(isinstance(transition, dict), "autorelease event transition must be an object")
        require(
            set(transition) == {"from", "to", "at", "evidence"},
            "autorelease event transition fields changed",
        )
        require(transition.get("from") == current, "autorelease event history is not contiguous")
        target = transition.get("to")
        require(target in LEGAL_EVENT_TRANSITIONS.get(current, set()), "autorelease event transition is illegal")
        timestamp = transition.get("at")
        require(
            isinstance(timestamp, str) and timestamp.endswith("Z"),
            "autorelease event transition timestamp is invalid",
        )
        evidence = transition.get("evidence")
        require(
            isinstance(evidence, list)
            and bool(evidence)
            and all(isinstance(item, dict) and bool(item) for item in evidence),
            "autorelease event transition evidence is invalid",
        )
        current = target
    require(current == record["state"], "autorelease event state does not match its history")


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
        "labels": ["autorelease", *(["attention-required"] if critical or event.get("humanActionRequired") else [])],
    }


def retained_notification_issue(prior: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return a usable retained issue identity without relying on search indexing."""
    issue = (prior or {}).get("issue")
    number = issue.get("number") if isinstance(issue, dict) else None
    if not isinstance(number, bool) and isinstance(number, int) and number > 0:
        return issue
    return None


ACTION_FILENAME_MAP = str.maketrans({":": "-", "/": "-"})


def action_filename(action_key: str, suffix: str = ".json") -> str:
    """Return the single file or branch name an action key may occupy.

    Every event record, readiness record, and automation branch in both repositories is
    named from its action key by this one mapping, so the name is only ever derived here.
    The key is model-authored and reaches shell arguments and repository paths, so its
    alphabet is re-asserted at this boundary rather than trusted from the caller.
    """
    require(bool(ACTION_KEY_RE.fullmatch(action_key)), f"invalid action key: {action_key}")
    return action_key.translate(ACTION_FILENAME_MAP) + suffix


def unrecorded_published_release(
    releases: Iterable[dict[str, Any]],
    events: Iterable[dict[str, Any]],
    record_files: Iterable[str] = (),
) -> str | None:
    """Return the action key of one published release that has no event record at all.

    A live release with no record silently corrupts every later decision, because the
    completed-action ledger is what admission uses to tell finished work from new work.
    Recovery is fail-closed: a release is only claimed when immutability proves it came
    from the guarded publish transaction and its action key is derivable from the tag
    alone. Any existing record, complete or not, is left to its own path, and so is a
    key whose record filename is already occupied by an unrelated document, because the
    filer refuses to overwrite a file and would otherwise fail on every later run. One
    key is returned per run; a further backlog is repaired by later runs.
    """
    recorded = {event.get("actionKey") for event in events}
    occupied = set(record_files)
    keys = set()
    for release in releases:
        if not isinstance(release, dict):
            continue
        if release.get("draft") or release.get("prerelease") or release.get("immutable") is not True:
            continue
        tag = RECOVERABLE_RELEASE_TAG_RE.fullmatch(str(release.get("tag_name", "")))
        if tag is None:
            continue
        key = f"recipe_rebuild:{tag.group(1)}:{tag.group(2)}" if tag.group(2) else f"new_patch:{tag.group(1)}"
        if key not in recorded and action_filename(key) not in occupied:
            keys.add(key)
    return min(keys, default=None)


def watch_decision(
    manifest: dict[str, Any],
    previous: dict[str, Any],
    events: Iterable[dict[str, Any]],
    health: dict[str, Any],
    *,
    self_evidence_update: bool = False,
    releases: Iterable[dict[str, Any]] = (),
    record_files: Iterable[str] = (),
) -> dict[str, Any]:
    events = list(events)
    incomplete = sorted(
        event.get("actionKey")
        for event in events
        if event.get("state") != "complete"
    )
    unrecorded = unrecorded_published_release(releases, events, record_files)
    if not health.get("healthy", False):
        trigger = "health_failed"
    elif any(capture.get("status") != 200 for capture in manifest.get("captures", [])):
        trigger = "source_unhealthy"
    elif incomplete:
        trigger = "event_incomplete"
    elif previous.get("manifestDigest") != manifest.get("manifestDigest"):
        current_captures = {
            item.get("captureId"): (item.get("status"), item.get("digest"))
            for item in manifest.get("captures", [])
            if isinstance(item, dict)
        }
        previous_captures = {
            item.get("captureId"): (item.get("status"), item.get("digest"))
            for item in previous.get("captures", [])
            if isinstance(item, dict)
        }
        changed_captures = {
            capture_id
            for capture_id in set(current_captures) | set(previous_captures)
            if current_captures.get(capture_id) != previous_captures.get(capture_id)
        }
        trigger = (
            "quiet"
            if self_evidence_update and changed_captures == {"php_bin_state"}
            else "evidence_changed"
        )
    else:
        trigger = "quiet"
    # A missing record outranks every trigger that a trustworthy snapshot can raise, so
    # it is repaired before new work starts. It never changes whether the model is
    # called: the repair is deterministic, but suppressing the investigation would let a
    # blocked repair starve reconciliation and selection on every later run.
    model_call = trigger != "quiet"
    if unrecorded and trigger not in {"health_failed", "source_unhealthy"}:
        trigger = "record_missing"
    return {
        "schemaVersion": 1,
        "trigger": trigger,
        "manifestDigest": manifest.get("manifestDigest"),
        "incompleteActions": incomplete,
        "action": "record_completed_event" if trigger == "record_missing" else "none",
        "actionKey": unrecorded if trigger == "record_missing" else "",
        "modelCall": model_call,
    }


# Only these two admitted actions announce themselves before their route runs, and only
# these three select a release for the publish transaction.
WATCH_LIFECYCLE_NOTIFICATION_ACTIONS = frozenset({"new_branch", "branch_eol"})
# `watch_decision` names a missing event record as its own action. The recovery overlay
# owns that repair, so it is a route the plan never takes rather than an unrouted one.
WATCH_RECOVERY_ACTION = "record_completed_event"
WATCH_PUBLISH_ACTIONS = frozenset({"new_patch", "new_branch", "reconcile_partial"})


def route_watch_action(decision: dict[str, Any]) -> dict[str, Any]:
    """Return the one route a coordinated watcher decision takes, or raise.

    The watcher runs two independent routes in the same job: `route` dispatches the
    admitted plan, and `recoveryRoute` repairs a published release that has no event
    record. Recovery is an overlay rather than an exclusive branch, so it carries its own
    field and never competes with the plan for one.

    Every legal combination is enumerated, including the ones that legitimately do
    nothing — those return `route: "none"` with the reason, so an idle run stays green.
    Anything else raises instead of falling through to a silent success, which is what an
    unrouted combination used to do.

    Invariant: `recoveryRoute` must depend on `recordActionKey` alone. The watch workflow
    calls this function twice in one run — the recover step reads `recoveryRoute` from a
    call that supplies only the record key, then the dispatch step reads `route` from a
    call that supplies the whole decision. Both agree today only because the recovery
    overlay ignores every other field. A field added to the recovery decision would make
    the first call answer from an incomplete decision and silently disagree with the
    second, so it must be passed to both callers in the same change.
    """
    action = str(decision.get("action") or "")
    action_key = str(decision.get("actionKey") or "")
    record_action_key = str(decision.get("recordActionKey") or "")
    edits_required = bool(decision.get("editsRequired"))
    recovery_merged = bool(decision.get("recoveryMerged"))
    evidence_recorded = bool(decision.get("evidenceAlreadyRecorded"))

    # The workflow passes the recovery key separately, but a caller handing this function
    # a raw `watch_decision` carries it as that decision's own key, so both are accepted.
    recovery_key = record_action_key or (action_key if action == WATCH_RECOVERY_ACTION else "")

    def routed(route: str, reason: str, notify: str = "none") -> dict[str, Any]:
        return {
            "schemaVersion": 1,
            "route": route,
            "reason": reason,
            "notify": notify,
            "action": action,
            "actionKey": action_key,
            "recordActionKey": recovery_key,
            "recoveryRoute": "recover_record" if recovery_key else "none",
        }

    if action in {"", "none"}:
        return routed("none", "no_admitted_plan")
    if action == WATCH_RECOVERY_ACTION:
        return routed("none", "recovery_routed_by_recovery_route")
    if recovery_merged and action == "branch_eol":
        # The completion asserts an untouched base, which the recovered record just moved.
        return routed("none", "eol_completion_deferred_by_recovery")
    if action == "no_change" and evidence_recorded:
        return routed("none", "evidence_state_already_recorded")
    if action in {"blocked", "needs_human"}:
        return routed("notify_blocked", "operator_attention_required")
    notify = "lifecycle" if action in WATCH_LIFECYCLE_NOTIFICATION_ACTIONS else "none"
    if action == "no_change":
        return routed("no_change_evidence", "record_reviewed_evidence", notify)
    if edits_required:
        return routed("dispatch_implementation", "admitted_plan_requires_edits", notify)
    if action in WATCH_PUBLISH_ACTIONS:
        if record_action_key and action_key == record_action_key:
            # The ledger this plan was admitted against is the one missing this record,
            # so the release it selects is already public.
            return routed("none", "release_published_pending_record", notify)
        return routed("dispatch_publish", "publish_admitted_release", notify)
    if action == "branch_eol":
        return routed("complete_branch_eol", "complete_admitted_eol", notify)
    raise ControlError(f"watcher action is unrouted: {action} with editsRequired={edits_required}")


def retry_decision(
    event: dict[str, Any],
    failure_fingerprint: str,
    max_attempts: int,
) -> dict[str, Any]:
    """Decide whether a failed agent phase may be recalled.

    No workflow calls this: the retry budget is an acceptance property, asserted
    by autorelease/verify.py check A06, which proves an identical repeated
    failure can never spend an unbounded number of agent runs.
    """
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
    """Replay a completed event from its retained evidence alone.

    No workflow calls this: auditability is an acceptance property, asserted by
    autorelease/verify.py check A19, which proves a finished action can be
    reconstructed from the record and rejects it once any cited file is missing
    or altered.
    """
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
