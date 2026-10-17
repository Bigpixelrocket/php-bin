"""Event, release, and watcher state machines.

Every legal transition, the one name an action key may occupy, and the single
routing table the watcher follows live here. These functions decide what happens
next from recorded state alone; they never fetch evidence or admit a plan.

The fixed email templates live here too, with the validator and plain-text
rendering of the branch status document they carry, since both read retained run
state as untrusted input.
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import re
from typing import Any, Iterable, Mapping

from ._evidence import BRANCH_FEED_CAPTURE_RE, EVIDENCE_CAPTURE_IDS
from ._validation import (
    ACTION_KEY_RE,
    COMMIT_SHA_RE,
    SHA256_RE,
    STABLE_VERSION_RE,
    ControlError,
    canonical_json,
    contained_path,
    require,
    sha256_bytes,
    sha256_file,
    utc_now,
)


# A plain zero patch is deliberately excluded: `8.6.0` is equally the tag of a
# `new_branch:8.6` action, so its action key is not derivable from the tag alone. A
# revision makes it unambiguous: `8.6.0-1` can only be `recipe_rebuild:8.6.0:1`.
RECOVERABLE_RELEASE_TAG_RE = re.compile(r"^(\d+\.\d+\.(?:[1-9]\d*|0(?=-)))(?:-([1-9]\d*))?$")
# A published release tag: a PHP version, plus a rebuild revision when the recipe
# changed after that version was first published.
PUBLISHED_RELEASE_TAG_RE = re.compile(r"^((\d+\.\d+)\.\d+)(?:-([1-9]\d*))?$")
# The publish transaction writes this line into every release's notes, naming the
# recipe the release was built from. Release notes reach the watcher inside the
# `php_bin_releases` capture, so the identity survives across runs with no extra state.
RECIPE_IDENTITY_NOTE_PREFIX = "Recipe identity: "
# Notes edited in the GitHub web interface come back with CRLF line endings.
RECIPE_IDENTITY_NOTE_RE = re.compile(r"^Recipe identity: (sha256:[0-9a-f]{64})\r?$", re.MULTILINE)
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
# `publishing` is recorded after the draft bytes are verified once more and before the
# release is made public, so a run that stops between the publication and the record
# of `published` is still known to have possibly gone live.
LEGAL_RELEASE_TRANSITIONS = {
    "requested": "built",
    "built": "draft_created",
    "draft_created": "draft_verified",
    "draft_verified": "publishing",
    "publishing": "published",
    "published": "public_verified",
    "public_verified": "complete",
}


def validate_completed_event_record(record: dict[str, Any]) -> None:
    """Validate a durable event as a complete, contiguous legal transition history."""

    require(isinstance(record, dict), "autorelease event must be an object")
    require(record.get("state") == "complete", "autorelease event is not complete")
    _validate_event_history(record)


# The exact field set the implementation run writes for a lifecycle readiness record.
READINESS_RECORD_FIELDS = {
    "schemaVersion",
    "actionKey",
    "classification",
    "state",
    "history",
    "phpBinCommit",
    "planDigest",
    "supportPolicyDigest",
    "policyInvariantsDigest",
    "evidenceManifestDigest",
    "evidenceDigests",
}


def validate_readiness_event_record(record: dict[str, Any]) -> str:
    """Validate an implementation run's `php_bin_ready` record and return its merged commit.

    The implementation run writes exactly one transition, `detected` to
    `php_bin_ready`, whose only evidence is the validated merge of the admitted
    lifecycle patch. That merge commit is what the record vouches for, so the trusted
    automation exemption binds it to the pull request's base: the record can only be
    accepted directly on top of the commit it names.
    """
    require(isinstance(record, dict), "autorelease event must be an object")
    require(set(record) == READINESS_RECORD_FIELDS, "readiness record fields changed")
    require(record.get("state") == "php_bin_ready", "readiness record is not at php_bin_ready")
    _validate_event_history(record)
    classification = record.get("classification")
    require(classification in {"new_branch", "branch_eol"}, "readiness record is not a lifecycle action")
    require(
        record["actionKey"].split(":", 1)[0] == classification,
        "readiness record action key does not match its classification",
    )
    history = record["history"]
    require(
        len(history) == 1 and history[0]["from"] == "detected" and history[0]["to"] == "php_bin_ready",
        "readiness record history is not a single detected to php_bin_ready transition",
    )
    evidence = history[0]["evidence"]
    require(
        len(evidence) == 1
        and set(evidence[0]) == {"kind", "commit", "planDigest"}
        and evidence[0]["kind"] == "validated_merge",
        "readiness record evidence is not one validated merge",
    )
    commit = evidence[0]["commit"]
    require(isinstance(commit, str) and bool(COMMIT_SHA_RE.fullmatch(commit)), "readiness merge commit is invalid")
    require(record.get("phpBinCommit") == commit, "readiness record names a different php-bin commit")
    require(evidence[0]["planDigest"] == record.get("planDigest"), "readiness record plan digest differs")
    for field in ("planDigest", "supportPolicyDigest", "policyInvariantsDigest", "evidenceManifestDigest"):
        value = record.get(field)
        require(isinstance(value, str) and bool(SHA256_RE.fullmatch(value)), f"readiness record {field} is invalid")
    digests = record.get("evidenceDigests")
    require(
        isinstance(digests, list)
        and bool(digests)
        and all(isinstance(item, str) and SHA256_RE.fullmatch(item) for item in digests),
        "readiness record evidence digests are invalid",
    )
    return commit


def _validate_event_history(record: dict[str, Any]) -> None:
    """Require a versioned event whose history is a contiguous chain of legal transitions."""
    require(record.get("schemaVersion") == 1, "autorelease event version is invalid")
    action_key = record.get("actionKey")
    require(
        isinstance(action_key, str) and bool(ACTION_KEY_RE.fullmatch(action_key)),
        "autorelease event action key is invalid",
    )
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


# Evidence kinds that name the published release a completed record describes: the
# publish transaction's own record, and the watcher's recovery of a missing one.
RELEASE_RECORD_EVIDENCE_KINDS = {"published_release", "published_immutable_release"}


def release_event_recorded(
    record: dict[str, Any] | None,
    action_key: str,
    version: str,
    asset_digests: dict[str, str] | None = None,
) -> bool:
    """Return whether `record`, main's copy of an event record, completes this release.

    A rerun of the publish run's final job must not file a second record, and must not
    report a record as missing that an earlier attempt, or the watcher's recovery,
    already merged. No record, or one still short of `complete` (a new branch's record
    waiting for its release), means this release is not recorded yet. A complete record
    counts only when it is a valid completed history for exactly this action key whose
    release evidence names this version and, when the transaction is known, exactly its
    asset digests. A complete record naming anything else contradicts the release and
    is rejected rather than read as either answer.
    """
    require(bool(STABLE_VERSION_RE.fullmatch(version or "")), f"release version is invalid: {version}")
    if record is None:
        return False
    require(isinstance(record, dict), "autorelease event must be an object")
    if record.get("state") != "complete":
        return False
    validate_completed_event_record(record)
    require(record.get("actionKey") == action_key, "the completed record belongs to another action key")
    named = [
        item
        for transition in record["history"]
        for item in transition["evidence"]
        if item.get("kind") in RELEASE_RECORD_EVIDENCE_KINDS and item.get("version") == version
    ]
    require(bool(named), f"the completed record for {action_key} does not name release {version}")
    if asset_digests is not None:
        require(
            all(item.get("assetDigests") == asset_digests for item in named),
            f"the completed record for {action_key} names other assets than release {version}",
        )
    return True


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
    """Advance a release transaction by its single legal next state.

    The asset set is fixed by the first transition: every later one must present the
    same digests, so a transaction handed from one job to the next can never continue
    with different bytes. Every state from `draft_verified` on also re-reads the local
    assets against those digests.
    """
    current = transaction.get("state", "requested")
    require(LEGAL_RELEASE_TRANSITIONS.get(current) == target, f"illegal release transition: {current} -> {target}")
    published = transaction.get("publishedAssets", {})
    if published:
        require(published == expected_assets, "published asset inconsistency")
    recorded = transaction.get("assetDigests")
    if recorded:
        require(recorded == expected_assets, "release asset set changed during the transaction")
    if target in {"draft_verified", "publishing", "published", "public_verified", "complete"}:
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


EMAIL_SUBJECT_PREFIX = "[php-bin autorelease]"
# A publish run only succeeds once it has dispatched the next watcher run.
EMAIL_NEXT_WATCHER_SENTENCE = "The next watcher run was started to take the next due release, if any."
# The admitted actions whose route moves main or starts work, all of which wait while a
# publish run has not recorded its release (WATCH_ROUTES_HELD_FOR_PUBLISH).
EMAIL_HELD_FOR_PUBLISH_ACTIONS = frozenset({"no_change", "new_patch", "new_branch", "branch_eol", "recipe_rebuild"})
# Repository slugs reach the digest from `github.repository`, never from run state.
EMAIL_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
# ACTION_KEY_RE fixes key syntax only, so each version-deriving action also pins
# the key family it may carry. blocked/needs_human carry whatever key stopped, so
# they accept any.
EMAIL_ACTION_KEY_PREFIXES = {
    "no_change": {"no_change"},
    "new_patch": {"new_patch"},
    "new_branch": {"new_branch"},
    "branch_eol": {"branch_eol"},
    "recipe_rebuild": {"recipe_rebuild"},
}


# The branch status document (`schemas/autorelease-status.schema.json`). `_status`
# derives it from one retained watcher capture; it is read back here because the
# email digest and the published page render it, and a retained copy is untrusted
# input like any other run state. Rejection messages name fields, never values, so a
# rejection reason is safe to interpolate into an email.
STATUS_SCHEMA_VERSION = 1
STATUS_FIELDS = frozenset(
    {
        "schemaVersion",
        "checkedAt",
        "runUrl",
        "summary",
        "badges",
        "trigger",
        "action",
        "actionKey",
        "inProgressActionKeys",
        "rebuildDueActionKey",
        "changedCaptures",
        "captureHealth",
        "branches",
    }
)
STATUS_BRANCH_FIELDS = frozenset(
    {
        "branch",
        "status",
        "upstream",
        "phpBin",
        "rebuildDue",
        "supportState",
        "securitySupportUntil",
        "securitySupportDaysLeft",
    }
)
# Every trigger `watch_decision` can report, and every action a plan can carry.
STATUS_TRIGGERS = frozenset(
    {
        "quiet",
        "evidence_changed",
        "event_incomplete",
        "source_unhealthy",
        "health_failed",
        "rebuild_due",
        "record_missing",
    }
)
STATUS_ACTIONS = frozenset(
    {"no_change", "new_patch", "new_branch", "branch_eol", "recipe_rebuild", "blocked", "needs_human"}
)
# Ordered as the summary lists them. `releasing` means an admitted or incomplete
# release action names the branch; `unknown` means a capture it needs was unhealthy
# or unreadable, so no version comparison is claimed.
STATUS_BRANCH_STATES = ("current", "behind", "releasing", "unknown")
# The row classes the reviewed supported-versions reader accepts.
STATUS_SUPPORT_STATES = frozenset({"stable", "security", "eol", "future"})
STATUS_RUN_URL_RE = re.compile(r"^https://github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/actions/runs/[1-9]\d*$")
STATUS_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
STATUS_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
STATUS_BRANCH_RE = re.compile(r"^\d+\.\d+$")
# A security support end at most this many days away also shows its countdown.
STATUS_EOL_COUNTDOWN_DAYS = 180
# Month names are fixed here rather than taken from the locale, so a runner's
# locale cannot change a rendered byte.
STATUS_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _status_timestamp(value: Any, label: str) -> dt.datetime:
    require(isinstance(value, str) and bool(STATUS_TIMESTAMP_RE.fullmatch(value)), f"{label} is not a UTC timestamp")
    try:
        return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ControlError(f"{label} is not a UTC timestamp") from error


def _status_date(value: Any, label: str) -> dt.date:
    require(isinstance(value, str) and bool(STATUS_DATE_RE.fullmatch(value)), f"{label} is not a date")
    try:
        return dt.date.fromisoformat(value)
    except ValueError as error:
        raise ControlError(f"{label} is not a date") from error


def _status_member(value: Any, allowed: Iterable[str]) -> bool:
    """Test membership without hashing, so an unhashable value is rejected, not raised."""
    return isinstance(value, str) and value in allowed


def _status_capture_ids(value: Any, label: str) -> list[str]:
    require(isinstance(value, list), f"{label} is not a list")
    require(
        all(
            isinstance(item, str) and (item in EVIDENCE_CAPTURE_IDS or bool(BRANCH_FEED_CAPTURE_RE.fullmatch(item)))
            for item in value
        ),
        f"{label} names an unknown capture",
    )
    require(value == sorted(set(value)), f"{label} is not sorted and unique")
    return value


def _patch_order(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def status_summary(branches: list[dict[str, Any]]) -> str:
    """Return the one-line summary of branch states, such as `All 4 branches current`.

    The summary is computed, never stored free-form: the validator recomputes it, so a
    retained document cannot carry text of its own into a subject line or a badge.
    """
    total = len(branches)
    noun = "branch" if total == 1 else "branches"
    counts = {state: sum(1 for item in branches if item.get("status") == state) for state in STATUS_BRANCH_STATES}
    if counts["current"] == total:
        text = f"All {total} {noun} current" if total > 1 else "1 branch current"
    else:
        text = f"{counts['current']} of {total} {noun} current" + "".join(
            f", {counts[state]} {state}" for state in STATUS_BRANCH_STATES[1:] if counts[state]
        )
    rebuilds = sum(1 for item in branches if item.get("rebuildDue") is True)
    if rebuilds:
        text += f", {rebuilds} {'rebuild' if rebuilds == 1 else 'rebuilds'} due"
    return text


def _status_php_bin_cell(item: dict[str, Any], health: dict[str, Any]) -> str:
    """Return the php-bin cell of one branch: its tag, `none`, or `unknown`."""
    if item["phpBin"]:
        return item["phpBin"]["tag"]
    missing = set(health["unhealthyCaptures"]) | set(health["unreadableCaptures"])
    return "unknown" if "php_bin_releases" in missing else "none"


def status_badges(branches: list[dict[str, Any]], health: dict[str, Any]) -> dict[str, str]:
    """Return one badge message per branch, such as `8.5.11-3, current`.

    shields.io dynamic badges cannot filter a list, so the published document keys
    these by branch (`$.badges['8.5']`). Like the summary, they are recomputed by the
    validator rather than trusted.
    """
    badges = {}
    for item in branches:
        php_bin = _status_php_bin_cell(item, health)
        badges[item["branch"]] = "unknown" if php_bin == item["status"] == "unknown" else f"{php_bin}, {item['status']}"
    return badges


def _validate_status_branch(item: Any, checked: dt.date) -> None:
    require(isinstance(item, dict) and set(item) == STATUS_BRANCH_FIELDS, "status branch fields changed")
    branch = item["branch"]
    require(isinstance(branch, str) and bool(STATUS_BRANCH_RE.fullmatch(branch)), "status branch is invalid")
    status = item["status"]
    require(_status_member(status, STATUS_BRANCH_STATES), "status branch state is unknown")
    upstream = item["upstream"]
    if upstream is not None:
        require(
            isinstance(upstream, dict) and set(upstream) == {"version", "releaseDate"},
            "status upstream fields changed",
        )
        require(
            isinstance(upstream["version"], str)
            and bool(re.fullmatch(rf"{re.escape(branch)}\.\d+", upstream["version"])),
            "status upstream version is not a patch of its branch",
        )
        _status_date(upstream["releaseDate"], "status upstream release date")
    php_bin = item["phpBin"]
    if php_bin is not None:
        require(
            isinstance(php_bin, dict) and set(php_bin) == {"tag", "version", "revision", "publishedAt"},
            "status php-bin fields changed",
        )
        tag = PUBLISHED_RELEASE_TAG_RE.fullmatch(php_bin["tag"]) if isinstance(php_bin["tag"], str) else None
        require(tag is not None and tag.group(2) == branch, "status php-bin tag is not a release of its branch")
        require(php_bin["version"] == tag.group(1), "status php-bin version does not match its tag")
        revision = php_bin["revision"]
        require(
            isinstance(revision, int) and not isinstance(revision, bool) and revision == int(tag.group(3) or 0),
            "status php-bin revision does not match its tag",
        )
        _status_timestamp(php_bin["publishedAt"], "status php-bin publication time")
    # The two comparison states are claims about the versions, so they must hold.
    if status == "current":
        require(
            upstream is not None
            and php_bin is not None
            and _patch_order(php_bin["version"]) >= _patch_order(upstream["version"]),
            "a current branch does not ship its upstream release",
        )
    if status == "behind":
        require(
            upstream is not None
            and (php_bin is None or _patch_order(php_bin["version"]) < _patch_order(upstream["version"])),
            "a behind branch already ships its upstream release",
        )
    require(item["rebuildDue"] is None or isinstance(item["rebuildDue"], bool), "status rebuild flag is invalid")
    until = item["securitySupportUntil"]
    days_left = item["securitySupportDaysLeft"]
    if until is None:
        require(
            item["supportState"] is None and days_left is None,
            "status support fields are only partly known",
        )
    else:
        require(_status_member(item["supportState"], STATUS_SUPPORT_STATES), "status support state is unknown")
        require(
            isinstance(days_left, int)
            and not isinstance(days_left, bool)
            and days_left == (_status_date(until, "status security support end") - checked).days,
            "status security support countdown does not match its date",
        )


def validate_status_document(document: Any) -> dict[str, Any]:
    """Validate a branch status document against its exact reviewed shape, or raise.

    Every value the email digest, the published page, or a badge renders is checked
    here: versions and tags by the release grammar, dates and times by format, keys by
    the action-key grammar, capture IDs by the fixed source set, and the summary by
    recomputation. Cross-field claims are checked too, so `current` always means the
    branch ships its upstream release and a countdown always matches its date.
    """
    require(isinstance(document, dict) and set(document) == STATUS_FIELDS, "status document fields changed")
    require(type(document["schemaVersion"]) is int and document["schemaVersion"] == STATUS_SCHEMA_VERSION, "status document version is unsupported")
    checked = _status_timestamp(document["checkedAt"], "status capture time").date()
    require(
        isinstance(document["runUrl"], str) and bool(STATUS_RUN_URL_RE.fullmatch(document["runUrl"])),
        "status run url is invalid",
    )
    require(document["trigger"] is None or _status_member(document["trigger"], STATUS_TRIGGERS), "status trigger is unknown")
    action = document["action"]
    action_key = document["actionKey"]
    require((action is None) == (action_key is None), "status action and action key disagree")
    if action is not None:
        require(_status_member(action, STATUS_ACTIONS), "status action is unknown")
        require(
            isinstance(action_key, str) and bool(ACTION_KEY_RE.fullmatch(action_key)),
            "status action key is invalid",
        )
        allowed_prefixes = EMAIL_ACTION_KEY_PREFIXES.get(action)
        require(
            allowed_prefixes is None or action_key.split(":")[0] in allowed_prefixes,
            "status action key does not match its action",
        )
    in_progress = document["inProgressActionKeys"]
    require(
        isinstance(in_progress, list)
        and all(isinstance(key, str) and bool(ACTION_KEY_RE.fullmatch(key)) for key in in_progress)
        and in_progress == sorted(set(in_progress)),
        "status in-progress action keys are invalid",
    )
    rebuild = document["rebuildDueActionKey"]
    require(
        rebuild is None
        or (isinstance(rebuild, str) and rebuild.startswith("recipe_rebuild:") and bool(ACTION_KEY_RE.fullmatch(rebuild))),
        "status rebuild action key is invalid",
    )
    if document["changedCaptures"] is not None:
        _status_capture_ids(document["changedCaptures"], "status changed captures")
    health = document["captureHealth"]
    require(
        isinstance(health, dict) and set(health) == {"healthy", "unhealthyCaptures", "unreadableCaptures"},
        "status capture health fields changed",
    )
    unhealthy = _status_capture_ids(health["unhealthyCaptures"], "status unhealthy captures")
    unreadable = _status_capture_ids(health["unreadableCaptures"], "status unreadable captures")
    require(health["healthy"] is (not unhealthy and not unreadable), "status capture health disagrees with its lists")
    branches = document["branches"]
    require(isinstance(branches, list) and bool(branches), "status lists no branch")
    for item in branches:
        _validate_status_branch(item, checked)
    names = [item["branch"] for item in branches]
    require(
        names == sorted(set(names), key=_patch_order, reverse=True),
        "status branches are not unique and newest first",
    )
    require(document["summary"] == status_summary(branches), "status summary does not match its branches")
    require(document["badges"] == status_badges(branches, health), "status badges do not match its branches")
    return document


def _status_day(value: dt.date, *, year: bool = True) -> str:
    return f"{value.day:02d} {STATUS_MONTHS[value.month - 1]}" + (f" {value.year}" if year else "")


def status_checked_label(document: dict[str, Any]) -> str:
    """Return the capture time of a validated status document as `2026-10-17 09:25 UTC`."""
    return _status_timestamp(document["checkedAt"], "status capture time").strftime("%Y-%m-%d %H:%M UTC")


def status_block(document: dict[str, Any]) -> str:
    """Render a validated status document as the fixed-format plain-text table.

    The email digest and the published page show exactly this block: one row per
    maintained branch, then one line naming in-progress work, the selected rebuild,
    and the captures whose digest changed, then capture health when it failed. A
    value the capture could not establish reads `unknown`; a branch with no php-bin
    release yet reads `none`.
    """
    checked = _status_timestamp(document["checkedAt"], "status capture time")
    health = document["captureHealth"]
    rows = [("Branch", "php.net", "php-bin", "Status", "Security EOL")]
    for item in document["branches"]:
        upstream = item["upstream"]
        upstream_cell = (
            f"{upstream['version']} ({_status_day(dt.date.fromisoformat(upstream['releaseDate']))})"
            if upstream
            else "unknown"
        )
        php_bin = item["phpBin"]
        php_bin_cell = _status_php_bin_cell(item, health)
        if php_bin:
            published = _status_timestamp(php_bin["publishedAt"], "status php-bin publication time").date()
            php_bin_cell += f" ({_status_day(published, year=published.year != checked.year)})"
        status_cell = item["status"] + (", rebuild due" if item["rebuildDue"] else "")
        until = item["securitySupportUntil"]
        if until is None:
            eol_cell = "unknown"
        else:
            days = item["securitySupportDaysLeft"]
            eol_cell = _status_day(dt.date.fromisoformat(until))
            if days < 0:
                eol_cell += " (ended)"
            elif days <= STATUS_EOL_COUNTDOWN_DAYS:
                eol_cell += f" ({days} {'day' if days == 1 else 'days'})"
        rows.append((item["branch"], upstream_cell, php_bin_cell, status_cell, eol_cell))
    widths = [max(len(row[column]) for row in rows) for column in range(len(rows[0]) - 1)]
    table = [
        "  ".join(cell.ljust(width) for cell, width in zip(row, widths)) + "  " + row[-1]
        for row in rows
    ]
    changed = document["changedCaptures"]
    lines = [
        f"Branch status at {checked:%Y-%m-%d %H:%M} UTC:",
        "",
        *table,
        "",
        f"In progress: {', '.join(document['inProgressActionKeys']) or 'none'}   "
        f"Rebuilds due: {document['rebuildDueActionKey'] or 'none'}   "
        f"Changed inputs: {'unknown' if changed is None else ', '.join(changed) or 'none'}",
    ]
    if health["unhealthyCaptures"]:
        lines.append(f"Unhealthy captures: {', '.join(health['unhealthyCaptures'])}")
    if health["unreadableCaptures"]:
        lines.append(f"Unreadable captures: {', '.join(health['unreadableCaptures'])}")
    return "\n".join(lines)


def _email_status(report: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    """Return the status paragraph for a watcher digest, and the document if it validated.

    A missing or rejected document never stops the digest: the template is still sent
    with a fixed line saying why the table is absent, since the run outcome the
    template reports does not depend on it.
    """
    if report.get("statusUnreadable"):
        return "Branch status: unavailable; the retained status document is not valid JSON.", None
    document = report.get("status")
    if document is None:
        return "Branch status: unavailable; this run retained no status document.", None
    try:
        validate_status_document(document)
    except ControlError as error:
        return f"Branch status: unavailable; the retained status document was rejected ({error}).", None
    return status_block(document), document


def _email(template: str, subject: str, *paragraphs: str, run_url: str) -> dict[str, Any]:
    return {
        "template": template,
        "subject": f"{EMAIL_SUBJECT_PREFIX} {subject}",
        "body": "\n\n".join([*paragraphs, f"Run: {run_url}"]),
    }


def email_digest(report: dict[str, Any]) -> dict[str, Any]:
    """Select and fill the one fixed email template for a completed pipeline run.

    Every value interpolated into a subject or body is validated against the
    same shape rules admission enforces, so free-form plan prose never reaches
    the outbound channel — a plan only ever picks which fixed sentence is sent.
    An outcome with no template is rejected instead of guessed at.

    Every watcher template also carries the branch status table from the run's
    retained status document (`report["status"]`), or a fixed line saying why it
    is absent. A quiet day's subject is that document's summary and capture time.
    Publish digests carry no table: the only status document a publish run can
    reach is the one its dispatching watcher captured before the release, so the
    next watcher digest reports the published state instead.
    """
    workflow = report.get("workflow")
    require(workflow in {"watcher", "publish"}, "email digest workflow is unknown")
    conclusion = report.get("conclusion")
    require(isinstance(conclusion, str) and bool(conclusion), "email digest conclusion is missing")
    run_url = report.get("runUrl", "")
    require(run_url.startswith("https://github.com/"), "email digest run url is invalid")
    repository = report.get("repository", "")
    require(bool(EMAIL_REPOSITORY_RE.fullmatch(repository)), "email digest repository is invalid")

    if workflow == "publish":
        transaction = report.get("transaction")
        version = ""
        released = False
        recorded = False
        if transaction is not None:
            require(isinstance(transaction, dict), "release transaction state must be an object")
            version = transaction.get("version")
            require(
                isinstance(version, str) and bool(STABLE_VERSION_RE.fullmatch(version)),
                "release transaction version is invalid",
            )
            released = transaction.get("released")
            require(isinstance(released, bool), "release transaction released flag is invalid")
            # State retained before the record flag existed carries none, which reads as
            # a record that was not written.
            recorded = transaction.get("recorded", False)
            require(isinstance(recorded, bool), "release transaction recorded flag is invalid")
            require(released or not recorded, "an unreleased transaction cannot have a recorded event")
        # A publish job only succeeds after recording a released transaction, so a
        # green run without one is inconsistent state, not a failed release.
        require(
            conclusion != "success" or released is True,
            "a successful publish run must retain released transaction state",
        )
        if released and conclusion == "success" and "-" in version:
            base = version.split("-")[0]
            return _email(
                "rebuild_published",
                f"PHP {version} rebuild published",
                f"The rebuild revision PHP {version} for macOS arm64 is live and fresh public "
                f"installs of it were verified: https://github.com/{repository}/releases/tag/{version}. "
                f"Earlier PHP {base} releases stay published unchanged, and installs of the plain "
                f"version {base} now resolve to this revision. {EMAIL_NEXT_WATCHER_SENTENCE}",
                run_url=run_url,
            )
        if released and conclusion == "success":
            return _email(
                "release_published",
                f"PHP {version} published",
                f"The immutable PHP {version} release for macOS arm64 is live and fresh public "
                f"installs of it were verified: https://github.com/{repository}/releases/tag/{version}. "
                f"{EMAIL_NEXT_WATCHER_SENTENCE}",
                run_url=run_url,
            )
        if released and recorded:
            # The release job reconciles an existing release even when the fresh build
            # fails, and the next watcher run is dispatched after the record merged, so a
            # run can finish the release and its record and still fail.
            return _email(
                "release_complete_run_failed",
                f"PHP {version} published and recorded; run failed",
                f"The PHP {version} release is live and its durable event record was completed, "
                f"but the publish run still finished with conclusion '{conclusion}'. That happens "
                "when another job failed around the finished release: the fresh build that "
                "reconciling an existing release did not need, or starting the next watcher run, "
                "which leaves any further due release to the daily schedule. The release itself "
                "needs nothing; check the run if the failure recurs.",
                run_url=run_url,
            )
        if released:
            return _email(
                "release_record_pending",
                f"PHP {version} published; record recovery pending",
                f"The PHP {version} release went live, but the publish run failed after publication, "
                "so its durable event record is missing and no next watcher run was started. The next "
                "scheduled watcher run recovers the record automatically; nothing needs doing unless "
                "that recovery also fails.",
                run_url=run_url,
            )
        return _email(
            "publish_failed",
            f"Publish failed{f' for PHP {version}' if version else ''}",
            "The publish transaction stopped before any release went live, so nothing was "
            "published and nothing needs rolling back. A critical GitHub issue has been filed "
            "with the failing run; after the cause is fixed, the release re-runs through the "
            "normal admitted path.",
            run_url=run_url,
        )

    status_paragraph, status = _email_status(report)
    if conclusion != "success":
        return _email(
            "watcher_failed",
            f"Watcher run failed ({conclusion})",
            f"The autorelease watcher run finished with conclusion '{conclusion}'. If the "
            "failure was actionable, a critical GitHub issue has been filed and assigned. The "
            "watcher is idempotent, so re-dispatching it after the cause is fixed is safe.",
            status_paragraph,
            run_url=run_url,
        )
    decision = report.get("decision")
    require(isinstance(decision, dict), "a successful watcher run must supply its watch decision")
    digest = decision.get("manifestDigest")
    require(
        isinstance(digest, str) and bool(SHA256_RE.fullmatch(digest)),
        "watch decision manifest digest is invalid",
    )
    classified = decision.get("classify")
    require(isinstance(classified, bool), "watch decision classify flag is invalid")
    if not classified:
        return _email(
            "quiet_day",
            f"{status['summary']} (checked {status_checked_label(status)})"
            if status
            else "Watcher: no upstream changes",
            "The watcher captured fresh upstream evidence and it matches the last reviewed "
            "capture, so nothing needed classifying and nothing was changed."
            + (
                " The php_bin_state change below is the commit that recorded that capture."
                if status and status["changedCaptures"] == ["php_bin_state"]
                else ""
            ),
            status_paragraph,
            f"Evidence manifest: {digest}",
            run_url=run_url,
        )
    plan = report.get("plan")
    require(isinstance(plan, dict), "a successful classified watcher run must supply its admitted plan")
    action = plan.get("action")
    action_key = plan.get("actionKey")
    require(
        isinstance(action_key, str) and bool(ACTION_KEY_RE.fullmatch(action_key)),
        "admitted plan action key is invalid",
    )
    allowed_prefixes = EMAIL_ACTION_KEY_PREFIXES.get(action)
    require(
        allowed_prefixes is None or action_key.split(":")[0] in allowed_prefixes,
        "admitted plan action key does not match its action",
    )
    version = action_key.split(":")[1] if ":" in action_key else ""
    publish_in_flight = report.get("publishInFlight", False)
    require(isinstance(publish_in_flight, bool), "publish in flight flag is invalid")
    if publish_in_flight and action in EMAIL_HELD_FOR_PUBLISH_ACTIONS:
        return _email(
            "held_for_publish",
            f"Watcher: {action_key} waits for the publish in flight",
            f"A publish run had not recorded its release when this run started, so the watcher "
            f"admitted {action_key} but changed nothing on main and dispatched nothing. That "
            "publish run starts the next watcher run once its release is recorded, and that run "
            "takes whatever is due then; if the publish fails, the daily schedule does.",
            status_paragraph,
            run_url=run_url,
        )
    if action == "recipe_rebuild":
        revision = f"{version}-{action_key.split(':')[2]}"
        return _email(
            "recipe_rebuild_started",
            f"Watcher: PHP {revision} rebuild started",
            f"The build recipe changed since PHP {version} was last published, so the watcher "
            f"admitted rebuild revision {revision} ({action_key}). The publish phase was "
            "dispatched; a separate email confirms publication or reports the failure. Every "
            f"existing PHP {version} release stays published and unchanged.",
            status_paragraph,
            run_url=run_url,
        )
    if action == "no_change":
        return _email(
            "no_change_reviewed",
            "Watcher: evidence changed, no release needed"
            + (f" ({status['summary'][0].lower()}{status['summary'][1:]})" if status else ""),
            f"Upstream evidence changed and the classifier found it requires no "
            f"release work ({action_key}). The reviewed evidence snapshot was recorded on main, "
            "so tomorrow's run compares against today's state. The changed inputs are listed "
            "below the table.",
            status_paragraph,
            f"Evidence manifest: {digest}",
            run_url=run_url,
        )
    if action == "new_patch":
        return _email(
            "new_patch_started",
            f"Watcher: PHP {version} release started",
            f"Upstream published PHP {version} and the watcher admitted a release plan for it "
            f"({action_key}). The implementation and publish phases were dispatched; a separate "
            "email confirms publication or reports the failure.",
            status_paragraph,
            run_url=run_url,
        )
    if action == "new_branch":
        return _email(
            "new_branch_detected",
            f"Watcher: new PHP branch {version} detected",
            f"A new PHP branch was detected and admitted as {action_key}. Its first publication "
            "proceeds automatically once mise-php records matching exact-commit readiness; until "
            "then the watcher re-checks daily and mutates nothing.",
            status_paragraph,
            run_url=run_url,
        )
    if action == "branch_eol":
        return _email(
            "branch_eol_started",
            f"Watcher: PHP {version} reached end of life",
            f"The support policy retired PHP {version} ({action_key}). Support cleanup completes "
            "automatically once mise-php records matching EOL readiness; published releases for "
            "the branch stay immutable and installable.",
            status_paragraph,
            run_url=run_url,
        )
    if action in {"blocked", "needs_human"}:
        return _email(
            "watcher_attention",
            f"Watcher needs attention ({action})",
            f"The classifier stopped at '{action}' for {action_key} and mutated nothing. A "
            "GitHub issue has been filed or updated with the exact evidence and the required "
            "next step.",
            status_paragraph,
            run_url=run_url,
        )
    raise ControlError(f"no email template exists for action: {action}")


def email_fallback(report: dict[str, Any], reason: str) -> dict[str, Any]:
    """Render the last-resort digest for run state no template accepts.

    The daily email must not go silent exactly when the pipeline does something
    novel, so rejection by `email_digest` still produces a message. Only values
    that revalidate here are interpolated; everything else is replaced with
    'unknown', and the stated reason is this module's own rejection text. A
    watcher fallback still carries the branch status table, or the fixed line
    saying why it is absent, exactly as the templates do.
    """
    workflow = report.get("workflow")
    if workflow not in {"watcher", "publish"}:
        workflow = "unknown"
    conclusion = report.get("conclusion")
    if not isinstance(conclusion, str) or not re.fullmatch(r"[a-z_]{1,32}", conclusion):
        conclusion = "unknown"
    run_url = report.get("runUrl", "")
    if not isinstance(run_url, str) or not run_url.startswith("https://github.com/"):
        run_url = "unknown (see the Actions history)"
    return _email(
        "unexpected_state",
        f"Pipeline outcome needs a look ({workflow}, {conclusion})",
        f"A {workflow} run finished with conclusion '{conclusion}', but its retained state "
        "matched no known outcome, so this summary is a fallback rather than a classification. "
        f"The digest was rejected because: {reason}",
        "Check the run and its retained artifacts directly. If this recurs for a legitimate "
        "outcome, the digest template table needs a new case.",
        *([_email_status(report)[0]] if workflow == "watcher" else []),
        run_url=run_url,
    )


ACTION_FILENAME_MAP = str.maketrans({":": "-", "/": "-"})


def action_filename(action_key: str, suffix: str = ".json") -> str:
    """Return the single file or branch name an action key may occupy.

    Every event record, readiness record, and automation branch in both repositories is
    named from its action key by this one mapping, so the name is only ever derived here.
    The key comes from a retained plan or record and reaches shell arguments and repository paths, so its
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


def release_is_newest(version: str, releases: Iterable[dict[str, Any]]) -> bool:
    """Return whether `version` sorts above every other published release.

    GitHub moves the "Latest" badge to whichever release was published last unless the
    publication says otherwise, so a rebuild of an older branch would take it from the
    newest PHP version. Versions compare numerically as (major, minor, patch, revision),
    a plain patch counting as revision 0, so `8.5.11-2` sorts above `8.5.11` and
    `8.10.0` above `8.9.9`. Drafts, prereleases, tags that are not release versions,
    and `version` itself are ignored; with nothing else published the version is newest.
    """
    tag = PUBLISHED_RELEASE_TAG_RE.fullmatch(version)
    require(tag is not None, f"release version is not a PHP version: {version}")

    def order(match: re.Match[str]) -> tuple[int, ...]:
        return (*(int(part) for part in match.group(1).split(".")), int(match.group(3) or 0))

    candidate = order(tag)
    for release in releases:
        if not isinstance(release, dict) or release.get("draft") or release.get("prerelease"):
            continue
        other = PUBLISHED_RELEASE_TAG_RE.fullmatch(str(release.get("tag_name", "")))
        if other is None or other.group(0) == version:
            continue
        if order(other) > candidate:
            return False
    return True


def recipe_identity_note(identity: str) -> str:
    """Return the release-notes line that records the recipe a release was built from."""
    require(bool(SHA256_RE.fullmatch(identity or "")), "recipe identity is not a sha256 digest")
    return RECIPE_IDENTITY_NOTE_PREFIX + identity


def release_recipe_identity(release: dict[str, Any]) -> str | None:
    """Return the recipe identity a published release records, or None if it records none.

    Releases published before identities were recorded carry none, and neither does a
    release whose notes were written by hand; both read as built from an unknown recipe.
    """
    body = release.get("body")
    match = RECIPE_IDENTITY_NOTE_RE.search(body) if isinstance(body, str) else None
    return match.group(1) if match else None


def pending_recipe_rebuild(
    releases: Iterable[dict[str, Any]],
    recipe_identities: Mapping[str, str],
) -> str | None:
    """Return the action key of the one rebuild revision that is due, or None.

    `recipe_identities` maps every maintained branch to the identity of the recipe it
    would be built from now. A published version is due when its newest revision was
    built from a recipe other than its branch's identity, or records no identity at all.
    The revision is one past the highest published revision of that version, so the key
    names a tag that cannot exist yet. Only maintained branches are rebuilt: an EOL
    branch keeps its releases exactly as published. Drafts and prereleases are ignored,
    so a rebuild whose draft was left by a failed transaction is selected again and
    resumes that draft.

    Selection is deterministic so the classifier confirms rather than invents it:
    the newest version of each branch goes first, because that is what branch
    shorthand installs resolve to, then older versions, newest first. One key is
    returned per run; later runs rebuild the rest.
    """
    require(
        all(SHA256_RE.fullmatch(identity or "") for identity in recipe_identities.values()),
        "recipe identity is not a sha256 digest",
    )
    maintained = set(recipe_identities)
    newest: dict[str, tuple[int, dict[str, Any]]] = {}
    for release in releases:
        if not isinstance(release, dict) or release.get("draft") or release.get("prerelease"):
            continue
        tag = PUBLISHED_RELEASE_TAG_RE.fullmatch(str(release.get("tag_name", "")))
        if tag is None or tag.group(2) not in maintained:
            continue
        revision = int(tag.group(3) or 0)
        if tag.group(1) not in newest or revision > newest[tag.group(1)][0]:
            newest[tag.group(1)] = (revision, release)

    def version_key(version: str) -> tuple[int, ...]:
        return tuple(int(part) for part in version.split("."))

    latest_of_branch: dict[str, str] = {}
    for version in newest:
        branch = version.rsplit(".", 1)[0]
        if branch not in latest_of_branch or version_key(version) > version_key(latest_of_branch[branch]):
            latest_of_branch[branch] = version
    due = [
        version
        for version, (_revision, release) in newest.items()
        if release_recipe_identity(release) != recipe_identities[version.rsplit(".", 1)[0]]
    ]
    if not due:
        return None
    selected = min(
        due,
        key=lambda version: (
            latest_of_branch[version.rsplit(".", 1)[0]] != version,
            tuple(-part for part in version_key(version)),
        ),
    )
    return f"recipe_rebuild:{selected}:{newest[selected][0] + 1}"


def watch_decision(
    manifest: dict[str, Any],
    previous: dict[str, Any],
    events: Iterable[dict[str, Any]],
    health: dict[str, Any],
    *,
    self_evidence_update: bool = False,
    releases: Iterable[dict[str, Any]] = (),
    record_files: Iterable[str] = (),
    recipe_identities: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Choose the wake trigger, and name any deterministic repair or rebuild that is due.

    `recipe_identities` maps each maintained branch to the identity of the checked-out
    recipe for it. When it is supplied, a published release built from any other recipe
    keeps the watcher awake: the `rebuild_due` trigger runs the classifier even on a day
    whose evidence matches the last reviewed snapshot, so a recorded `no_change` can
    never leave a rebuild pending quietly. The selected key is reported as
    `rebuildActionKey`, and admission accepts no other rebuild.
    """
    releases = list(releases)
    events = list(events)
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
    # An untrustworthy snapshot cannot prove which releases exist, so a rebuild is only
    # selected once the health guards have passed, exactly like a missing record.
    rebuild = (
        pending_recipe_rebuild(releases, recipe_identities)
        if recipe_identities is not None and trigger not in {"health_failed", "source_unhealthy"}
        else None
    )
    if rebuild and trigger == "quiet":
        trigger = "rebuild_due"
    # A missing record outranks every trigger that a trustworthy snapshot can raise, so
    # it is repaired before new work starts. It never changes whether the classifier
    # runs: the repair is deterministic, but suppressing classification would let a
    # blocked repair starve reconciliation and selection on every later run.
    classify = trigger != "quiet"
    # An untrustworthy snapshot cannot be read for a missing record either, so the
    # repair is only looked for once the health guards above have passed.
    unrecorded = (
        None
        if trigger in {"health_failed", "source_unhealthy"}
        else unrecorded_published_release(releases, events, record_files)
    )
    if unrecorded:
        trigger = "record_missing"
    return {
        "schemaVersion": 1,
        "trigger": trigger,
        "manifestDigest": manifest.get("manifestDigest"),
        "incompleteActions": incomplete,
        "action": "record_completed_event" if trigger == "record_missing" else "none",
        "actionKey": unrecorded if trigger == "record_missing" else "",
        "rebuildActionKey": rebuild or "",
        "classify": classify,
    }


# Only these two admitted actions announce themselves before their route runs, and only
# these three select a release for the publish transaction.
WATCH_LIFECYCLE_NOTIFICATION_ACTIONS = frozenset({"new_branch", "branch_eol"})
# `watch_decision` names a missing event record as its own action. The recovery overlay
# owns that repair, so it is a route the plan never takes rather than an unrouted one.
WATCH_RECOVERY_ACTION = "record_completed_event"
WATCH_PUBLISH_ACTIONS = frozenset({"new_patch", "new_branch", "recipe_rebuild"})
# The plan routes that move main or start work that does. A publish run still in flight
# recaptures `php_bin_state` before publication, and a plan admitted meanwhile was
# classified before that run's record existed, so each of these waits for the watcher
# run the publish starts once its record is on main. The recovery overlay, which also
# moves main, waits under the same flag in `route_watch_action`.
WATCH_ROUTES_HELD_FOR_PUBLISH = frozenset(
    {"no_change_evidence", "dispatch_implementation", "dispatch_publish", "complete_branch_eol"}
)


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

    Invariant: `recoveryRoute` must depend on `recordActionKey` and `publishInFlight`
    alone. The watch workflow calls this function twice in one run — the recover step
    reads `recoveryRoute` from a call that supplies only those two fields, then the
    dispatch step reads `route` from a call that supplies the whole decision. Both agree
    only because the recovery overlay ignores every other field. A field added to the
    recovery decision would make the first call answer from an incomplete decision and
    silently disagree with the second, so it must be passed to both callers in the same
    change.

    `publishInFlight` says a publish run had not yet recorded its release when this run
    started. Each successful publish starts the next watcher run once its record is on
    main, so every route that moves main or starts work waits for that run instead of
    re-admitting the release in flight from evidence captured before its record; a
    publish that fails starts nothing, which leaves the work to the daily schedule. The
    record recovery waits too: that publish files the record itself, and a recovered
    record merged first would move main under its record pull request. The deferral
    replaces only the routes; validation and notification are unchanged.
    """
    action = str(decision.get("action") or "")
    action_key = str(decision.get("actionKey") or "")
    record_action_key = str(decision.get("recordActionKey") or "")
    edits_required = bool(decision.get("editsRequired"))
    recovery_merged = bool(decision.get("recoveryMerged"))
    evidence_recorded = bool(decision.get("evidenceAlreadyRecorded"))
    publish_in_flight = bool(decision.get("publishInFlight"))

    # The workflow passes the recovery key separately, but a caller handing this function
    # a raw `watch_decision` carries it as that decision's own key, so both are accepted.
    recovery_key = record_action_key or (action_key if action == WATCH_RECOVERY_ACTION else "")

    def routed(route: str, reason: str, notify: str = "none") -> dict[str, Any]:
        if publish_in_flight and route in WATCH_ROUTES_HELD_FOR_PUBLISH:
            route, reason = "none", "deferred_to_publish_in_flight"
        return {
            "schemaVersion": 1,
            "route": route,
            "reason": reason,
            "notify": notify,
            "action": action,
            "actionKey": action_key,
            "recordActionKey": recovery_key,
            "recoveryRoute": "recover_record" if recovery_key and not publish_in_flight else "none",
        }

    if action in {"", "none"}:
        return routed("none", "no_admitted_plan")
    if action == WATCH_RECOVERY_ACTION:
        return routed("none", "recovery_routed_by_recovery_route")
    if action in WATCH_PUBLISH_ACTIONS and record_action_key and action_key == record_action_key:
        # The ledger this plan was admitted against is the one missing this record,
        # so the release it selects is already public.
        notify = "lifecycle" if action in WATCH_LIFECYCLE_NOTIFICATION_ACTIONS else "none"
        return routed("none", "release_published_pending_record", notify)
    if recovery_merged and action in {"branch_eol", "no_change"}:
        # Both routes commit against an untouched base, which the recovered record just moved.
        return routed("none", "record_write_deferred_by_recovery")
    if recovery_merged and (
        action in WATCH_PUBLISH_ACTIONS or (edits_required and action in WATCH_LIFECYCLE_NOTIFICATION_ACTIONS)
    ):
        # The plan was admitted against the main the recovered record just moved. The
        # publish recapture binds `php_bin_state`, and an implementation seals against
        # the admitted base, so either would fail this run. The next run re-admits the
        # same work against the moved main.
        return routed("none", "dispatch_deferred_by_recovery")
    if action == "no_change" and evidence_recorded:
        return routed("none", "evidence_state_already_recorded")
    if action in {"blocked", "needs_human"}:
        return routed("notify_blocked", "operator_attention_required")
    notify = "lifecycle" if action in WATCH_LIFECYCLE_NOTIFICATION_ACTIONS else "none"
    if action == "no_change":
        return routed("no_change_evidence", "record_reviewed_evidence", notify)
    if edits_required:
        # Only lifecycle work has a deterministic repository edit to implement.
        if action in WATCH_LIFECYCLE_NOTIFICATION_ACTIONS:
            return routed("dispatch_implementation", "admitted_plan_requires_edits", notify)
        raise ControlError(f"no deterministic implementation exists for action: {action}")
    if action in WATCH_PUBLISH_ACTIONS:
        return routed("dispatch_publish", "publish_admitted_release", notify)
    if action == "branch_eol":
        return routed("complete_branch_eol", "complete_admitted_eol", notify)
    raise ControlError(f"watcher action is unrouted: {action} with editsRequired={edits_required}")


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
