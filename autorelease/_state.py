"""Event, release, and watcher state machines.

Every legal transition, the one name an action key may occupy, and the single
routing table the watcher follows live here. These functions decide what happens
next from recorded state alone; they never fetch evidence or admit a plan.
"""

from __future__ import annotations

import json
import pathlib
import re
from typing import Any, Iterable, Mapping

from ._validation import (
    ACTION_KEY_RE,
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
                f"version {base} now resolve to this revision.",
                run_url=run_url,
            )
        if released and conclusion == "success":
            return _email(
                "release_published",
                f"PHP {version} published",
                f"The immutable PHP {version} release for macOS arm64 is live and fresh public "
                f"installs of it were verified: https://github.com/{repository}/releases/tag/{version}.",
                run_url=run_url,
            )
        if released and recorded:
            # The release job reconciles an existing release even when the fresh build
            # fails, so a run can finish the release and its record and still fail.
            return _email(
                "release_complete_run_failed",
                f"PHP {version} published and recorded; run failed",
                f"The PHP {version} release is live and its durable event record was completed, "
                f"but the publish run still finished with conclusion '{conclusion}'. That happens "
                "when the release was reconciled from its existing assets while another job, such "
                "as the fresh build that reconciliation did not need, failed. The release itself "
                "needs nothing; check the run if the failure recurs.",
                run_url=run_url,
            )
        if released:
            return _email(
                "release_record_pending",
                f"PHP {version} published; record recovery pending",
                f"The PHP {version} release went live, but the publish run failed after publication, "
                "so its durable event record is missing. Tomorrow's watcher recovers the record "
                "automatically; nothing needs doing unless that recovery also fails.",
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

    if conclusion != "success":
        return _email(
            "watcher_failed",
            f"Watcher run failed ({conclusion})",
            f"The daily autorelease watcher finished with conclusion '{conclusion}'. If the "
            "failure was actionable, a critical GitHub issue has been filed and assigned. The "
            "watcher is idempotent, so re-dispatching it after the cause is fixed is safe.",
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
            "Watcher: no upstream changes",
            "The watcher captured fresh upstream evidence and it matches the last reviewed "
            "capture, so nothing needed classifying and nothing was changed.",
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
    if action == "recipe_rebuild":
        revision = f"{version}-{action_key.split(':')[2]}"
        return _email(
            "recipe_rebuild_started",
            f"Watcher: PHP {revision} rebuild started",
            f"The build recipe changed since PHP {version} was last published, so the watcher "
            f"admitted rebuild revision {revision} ({action_key}). The publish phase was "
            "dispatched; a separate email confirms publication or reports the failure. Every "
            f"existing PHP {version} release stays published and unchanged.",
            run_url=run_url,
        )
    if action == "no_change":
        return _email(
            "no_change_reviewed",
            "Watcher: evidence changed, no release needed",
            f"Upstream evidence changed and the classifier found it requires no "
            f"release work ({action_key}). The reviewed evidence snapshot was recorded on main, "
            "so tomorrow's run compares against today's state.",
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
            run_url=run_url,
        )
    if action == "new_branch":
        return _email(
            "new_branch_detected",
            f"Watcher: new PHP branch {version} detected",
            f"A new PHP branch was detected and admitted as {action_key}. Its first publication "
            "proceeds automatically once mise-php records matching exact-commit readiness; until "
            "then the watcher re-checks daily and mutates nothing.",
            run_url=run_url,
        )
    if action == "branch_eol":
        return _email(
            "branch_eol_started",
            f"Watcher: PHP {version} reached end of life",
            f"The support policy retired PHP {version} ({action_key}). Support cleanup completes "
            "automatically once mise-php records matching EOL readiness; published releases for "
            "the branch stay immutable and installable.",
            run_url=run_url,
        )
    if action in {"blocked", "needs_human"}:
        return _email(
            "watcher_attention",
            f"Watcher needs attention ({action})",
            f"The classifier stopped at '{action}' for {action_key} and mutated nothing. A "
            "GitHub issue has been filed or updated with the exact evidence and the required "
            "next step.",
            run_url=run_url,
        )
    raise ControlError(f"no email template exists for action: {action}")


def email_fallback(report: dict[str, Any], reason: str) -> dict[str, Any]:
    """Render the last-resort digest for run state no template accepts.

    The daily email must not go silent exactly when the pipeline does something
    novel, so rejection by `email_digest` still produces a message. Only values
    that revalidate here are interpolated; everything else is replaced with
    'unknown', and the stated reason is this module's own rejection text.
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
