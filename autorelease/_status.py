"""Branch status derived from one retained watcher capture.

The status document answers, per maintained branch, what php.net released last and
what php-bin published last, in a fixed shape a dashboard or badge can parse
(`schemas/autorelease-status.schema.json`). It is derived only from what the watcher
already retained: the evidence manifest and its captured bodies, the watch decision,
the admitted plan, and the reviewed evidence snapshot the decision compared against.
Nothing is fetched and nothing is decided here; the classifier and admission never
read this document.

A capture that is unhealthy or does not have its reviewed shape is never guessed
from: the values it would supply are null, the branch reads `unknown`, and the
capture is named in `captureHealth`. The document is validated against its exact
shape before it is returned, so the email digest and the published page only ever
render values that passed the same rules.
"""

from __future__ import annotations

import datetime as dt
import html
import json
import pathlib
import re
from typing import Any, Mapping

from ._classifier import parse_supported_versions, version_key
from ._evidence import (
    BRANCH_FEED_CAPTURE_RE,
    branch_feed_capture_id,
    load_capture,
    validate_capture_id_set,
    validate_evidence_state_record,
)
from ._state import (
    PUBLISHED_RELEASE_TAG_RE,
    STATUS_SCHEMA_VERSION,
    STATUS_TIMESTAMP_RE,
    pending_recipe_rebuild,
    status_badges,
    status_block,
    status_summary,
    validate_status_document,
)
from ._validation import ACTION_KEY_RE, ControlError, canonical_json, load_json, require, sha256_bytes


# An admitted plan with one of these actions is release or lifecycle work in flight,
# and the first three of them release the branch their key names.
STATUS_WORK_ACTIONS = frozenset({"new_patch", "new_branch", "branch_eol", "recipe_rebuild"})
STATUS_RELEASING_FAMILIES = frozenset({"new_patch", "new_branch", "recipe_rebuild"})


def _released_branch(action_key: str) -> str | None:
    """Return the branch a release action key publishes on, or None for any other key."""
    family, _, rest = action_key.partition(":")
    if family not in STATUS_RELEASING_FAMILIES:
        return None
    version = rest.split(":")[0]
    return ".".join(version.split(".")[:2])


def _admitted_plan(run_dir: pathlib.Path) -> dict[str, Any] | None:
    """Return the run's plan only when its admission record admits exactly those bytes.

    A plan that failed admission authorized nothing, so it names no action here.
    """
    plan_path = run_dir / "autorelease-plan.json"
    admission_path = run_dir / "admission.json"
    if not plan_path.is_file() or not admission_path.is_file():
        return None
    plan = load_json(plan_path)
    admission = load_json(admission_path)
    if not (isinstance(plan, dict) and isinstance(admission, dict)):
        return None
    if admission.get("admitted") is not True or admission.get("actionKey") != plan.get("actionKey"):
        return None
    if admission.get("planDigest") != sha256_bytes(canonical_json(plan)):
        return None
    return plan


def _decision(run_dir: pathlib.Path, manifest: dict[str, Any]) -> dict[str, Any] | None:
    """Return the run's watch decision, which must have been taken on this manifest."""
    path = run_dir / "watch-decision.json"
    if not path.is_file():
        return None
    decision = load_json(path)
    require(isinstance(decision, dict), "watch decision must be an object")
    require(
        decision.get("manifestDigest") == manifest.get("manifestDigest"),
        "watch decision was not taken on this evidence manifest",
    )
    incomplete = decision.get("incompleteActions", [])
    require(
        isinstance(incomplete, list)
        and all(isinstance(key, str) and bool(ACTION_KEY_RE.fullmatch(key)) for key in incomplete),
        "watch decision incomplete actions are invalid",
    )
    rebuild = decision.get("rebuildActionKey", "")
    require(
        rebuild == "" or (isinstance(rebuild, str) and bool(ACTION_KEY_RE.fullmatch(rebuild))),
        "watch decision rebuild action key is invalid",
    )
    return decision


def _changed_captures(manifest: dict[str, Any], previous_path: pathlib.Path) -> list[str] | None:
    """Return the capture IDs whose status or digest differs from the reviewed snapshot.

    This is the comparison `watch_decision` makes. A snapshot that is missing or no
    longer has its reviewed shape compares against nothing, so the answer is unknown.
    """
    if not previous_path.is_file():
        return None
    try:
        previous = load_json(previous_path)
        validate_evidence_state_record(previous)
    except ControlError:
        return None
    current = {item["captureId"]: (item.get("status"), item.get("digest")) for item in manifest["captures"]}
    prior = {item["captureId"]: (item["status"], item["digest"]) for item in previous["captures"]}
    return sorted(capture_id for capture_id in set(current) | set(prior) if current.get(capture_id) != prior.get(capture_id))


class _Reader:
    """Read access to the healthy captures of one manifest, recording what failed."""

    def __init__(self, manifest_path: pathlib.Path, manifest: dict[str, Any]):
        self.manifest_path = manifest_path
        self.status = {item["captureId"]: item.get("status") for item in manifest["captures"]}
        self.unreadable: set[str] = set()

    def body(self, capture_id: str) -> bytes | None:
        """Return a healthy capture's verified bytes, or None when it cannot be trusted."""
        if self.status.get(capture_id) != 200:
            return None
        try:
            _capture, body = load_capture(self.manifest_path, capture_id)
        except ControlError:
            self.unreadable.add(capture_id)
            return None
        return body

    def json_body(self, capture_id: str) -> Any:
        body = self.body(capture_id)
        if body is None:
            return None
        try:
            return json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.unreadable.add(capture_id)
            return None


def _upstream(reader: _Reader, branch: str) -> dict[str, str] | None:
    """Return the version and release date the branch's own feed names, or None."""
    capture_id = branch_feed_capture_id(branch)
    document = reader.json_body(capture_id)
    if document is None:
        return None
    version = document.get("version") if isinstance(document, dict) else None
    date = document.get("date") if isinstance(document, dict) else None
    try:
        require(isinstance(version, str) and bool(re.fullmatch(rf"{re.escape(branch)}\.\d+", version)), "version")
        require(isinstance(date, str) and bool(re.fullmatch(r"\d{1,2} [A-Z][a-z]{2} \d{4}", date)), "date")
        released = dt.datetime.strptime(date, "%d %b %Y").date()
    except (ControlError, ValueError):
        reader.unreadable.add(capture_id)
        return None
    return {"version": version, "releaseDate": released.isoformat()}


def _published(reader: _Reader) -> list[dict[str, Any]] | None:
    """Return the published, non-prerelease php-bin releases, or None when unknown."""
    releases = reader.json_body("php_bin_releases")
    if releases is None:
        return None
    if not isinstance(releases, list):
        reader.unreadable.add("php_bin_releases")
        return None
    return [item for item in releases if isinstance(item, dict) and not item.get("draft") and not item.get("prerelease")]


def _newest_release(releases: list[dict[str, Any]], branch: str) -> dict[str, Any] | None:
    """Return the newest published tag on a branch, ordering patch first, then revision.

    A release whose publication time does not have GitHub's UTC form is skipped rather
    than rendered.
    """
    newest: tuple[tuple[int, ...], dict[str, Any]] | None = None
    for release in releases:
        tag = PUBLISHED_RELEASE_TAG_RE.fullmatch(str(release.get("tag_name", "")))
        published_at = release.get("published_at")
        if tag is None or tag.group(2) != branch:
            continue
        if not (isinstance(published_at, str) and STATUS_TIMESTAMP_RE.fullmatch(published_at)):
            continue
        revision = int(tag.group(3) or 0)
        order = (*version_key(tag.group(1)), revision)
        if newest is None or order > newest[0]:
            newest = (
                order,
                {"tag": tag.group(0), "version": tag.group(1), "revision": revision, "publishedAt": published_at},
            )
    return newest[1] if newest else None


def status_document(
    run_dir: pathlib.Path,
    previous_path: pathlib.Path,
    run_url: str,
    recipe_identities: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Derive the branch status document from one retained watcher run directory.

    `run_dir` is the watcher's `autorelease-run` directory, or a downloaded
    investigation artifact: `evidence/evidence-manifest.json` is required, while the
    watch decision, plan, and admission record are read when the run got that far.
    `previous_path` is the reviewed evidence snapshot the decision compared against.
    `recipe_identities` maps maintained branches to the recipe identity of the
    watcher's checked-out commit; a branch it does not cover reports its rebuild as
    unknown. Branches are the ones whose feeds the manifest captured, which is the
    accepted policy at capture time.
    """
    manifest_path = run_dir / "evidence/evidence-manifest.json"
    manifest = load_json(manifest_path)
    require(isinstance(manifest, dict), "evidence manifest must be an object")
    captures = manifest.get("captures")
    require(
        isinstance(captures, list) and all(isinstance(item, dict) for item in captures),
        "evidence manifest captures must be objects",
    )
    validate_capture_id_set([item.get("captureId") for item in captures], "status ")
    decision = _decision(run_dir, manifest)
    plan = _admitted_plan(run_dir)
    reader = _Reader(manifest_path, manifest)
    captured_at = manifest.get("capturedAt")
    require(
        isinstance(captured_at, str) and bool(STATUS_TIMESTAMP_RE.fullmatch(captured_at)),
        "evidence manifest capture time is invalid",
    )
    try:
        checked = dt.datetime.strptime(captured_at, "%Y-%m-%dT%H:%M:%SZ").date()
    except ValueError as error:
        raise ControlError("evidence manifest capture time is invalid") from error

    in_progress = set(decision.get("incompleteActions", [])) if decision else set()
    if plan and plan.get("action") in STATUS_WORK_ACTIONS:
        in_progress.add(plan["actionKey"])
    releasing = {branch for branch in map(_released_branch, in_progress) if branch}

    support = None
    page = reader.body("php_supported_versions")
    if page is not None:
        try:
            support = parse_supported_versions(page)
        except ControlError:
            reader.unreadable.add("php_supported_versions")
    releases = _published(reader)
    branches = sorted(
        (match.group(1) for match in map(BRANCH_FEED_CAPTURE_RE.fullmatch, reader.status) if match),
        key=version_key,
        reverse=True,
    )
    rows = []
    for branch in branches:
        upstream = _upstream(reader, branch)
        php_bin = _newest_release(releases, branch) if releases is not None else None
        if branch in releasing:
            state = "releasing"
        elif upstream is None or releases is None:
            state = "unknown"
        elif php_bin is not None and version_key(php_bin["version"]) >= version_key(upstream["version"]):
            state = "current"
        else:
            state = "behind"
        rebuild_due = None
        if releases is not None and recipe_identities is not None and branch in recipe_identities:
            rebuild_due = pending_recipe_rebuild(releases, {branch: recipe_identities[branch]}) is not None
        row = support.get(branch) if support is not None else None
        rows.append(
            {
                "branch": branch,
                "status": state,
                "upstream": upstream,
                "phpBin": php_bin,
                "rebuildDue": rebuild_due,
                "supportState": row.state if row else None,
                "securitySupportUntil": row.security_until.isoformat() if row else None,
                "securitySupportDaysLeft": (row.security_until - checked).days if row else None,
            }
        )
    unhealthy = sorted(capture_id for capture_id, status in reader.status.items() if status != 200)
    unreadable = sorted(reader.unreadable)
    health = {
        "healthy": not unhealthy and not unreadable,
        "unhealthyCaptures": unhealthy,
        "unreadableCaptures": unreadable,
    }
    action = plan.get("action") if plan else None
    document = {
        "schemaVersion": STATUS_SCHEMA_VERSION,
        "checkedAt": captured_at,
        "runUrl": run_url,
        "summary": status_summary(rows),
        "badges": status_badges(rows, health),
        "trigger": decision.get("trigger") if decision else None,
        "action": action,
        "actionKey": plan.get("actionKey") if plan else None,
        "inProgressActionKeys": sorted(in_progress),
        "rebuildDueActionKey": (decision.get("rebuildActionKey") or None) if decision else None,
        "changedCaptures": _changed_captures(manifest, previous_path),
        "captureHealth": health,
        "branches": rows,
    }
    return validate_status_document(document)


def status_page(document: dict[str, Any]) -> str:
    """Render the human-readable page published beside `status.json`.

    It shows the same fixed-format table as the email digest. Every value has already
    passed `validate_status_document`, and is escaped as HTML regardless.
    """
    validate_status_document(document)
    run_url = html.escape(document["runUrl"])
    return (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<title>php-bin release status</title>\n"
        "</head>\n"
        "<body>\n"
        "<h1>php-bin release status</h1>\n"
        f"<p>{html.escape(document['summary'])}.</p>\n"
        f"<pre>{html.escape(status_block(document))}</pre>\n"
        '<p>Machine-readable: <a href="status.json">status.json</a>. '
        f'Watcher run: <a href="{run_url}">{run_url}</a>.</p>\n'
        "</body>\n"
        "</html>\n"
    )
