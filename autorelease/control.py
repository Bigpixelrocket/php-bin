#!/usr/bin/env python3
"""Deterministic autorelease controls.

No model takes part in any decision. Captured evidence is classified by fixed
rules, every classified plan is admitted by an independent check, and lifecycle
edits, state transitions, and immutable release effects are all computed here.

It is the stable import surface for the package behind it, so every name the
workflows, scripts, verifier, and tests already use stays importable from here:

- `_validation`: digests, canonical JSON, path containment, and the regular
  expressions that fix the shape of every identifier.
- `_evidence`: the opaque capture client and the readers that re-derive a
  cited capture's identity.
- `_state`: the event, release, and watcher state machines, including the one
  routing table the watcher follows.
- `_classifier`: the priority rules that turn one capture into exactly one
  plan, and the reviewed reader of the supported-versions page.
- `_admission`: the three independent gates a plan and its repository change
  pass: the plan, the sealed patch, and the merge.
- `_implementation`: the deterministic repository edits of an admitted
  lifecycle plan.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys
from typing import Any

# Workflows run this file directly (`./autorelease/control.py <command>`), where only
# the autorelease directory is on the import path, while the scripts, verify.py, and
# the tests import it as `autorelease.control`. Direct execution therefore borrows the
# same repository-root shim the scripts use, so the absolute imports below resolve in
# both contexts and no consumer has to know which one it is in.
if __package__ in {None, ""}:
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from autorelease._admission import (  # noqa: E402
    PLAN_ACTIONS,
    PLAN_FIELDS,
    RECIPE_INPUT_PATHS,
    REQUIRED_PLAN_CHECKS,
    _validate_plan_shape,
    _validate_support_policy_document,
    changed_paths,
    git,
    recipe_identity,
    seal_patch,
    validate_plan,
    validate_recipe_rebuild_evidence,
    validate_release_is_newest_patch,
    validate_stable_release_evidence,
    validate_support_policy,
    verify_merge,
)
from autorelease._classifier import (  # noqa: E402
    SourceFormatError,
    SupportRow,
    branch_of,
    classify_evidence,
    parse_supported_versions,
    version_key,
)
from autorelease._implementation import (  # noqa: E402
    apply_lifecycle_plan,
    render_support_policy,
)
from autorelease._evidence import (  # noqa: E402
    BRANCH_FEED_CAPTURE_RE,
    EDGE_CACHE_BYPASS_PARAMETER,
    EVIDENCE_CAPTURE_IDS,
    RUNTIME_PLAN_EVIDENCE_IDS,
    EvidenceSource,
    RestrictedRedirect,
    branch_feed_capture_id,
    capture_evidence,
    fetch_url,
    load_capture,
    load_plan_evidence,
    manifest_digest,
    validate_capture_id_set,
    validate_evidence_attestation_predicate,
    validate_evidence_state_record,
    validate_recaptured_evidence,
)
from autorelease._state import (  # noqa: E402
    ACTION_FILENAME_MAP,
    LEGAL_EVENT_TRANSITIONS,
    LEGAL_RELEASE_TRANSITIONS,
    PUBLISHED_RELEASE_TAG_RE,
    RECIPE_IDENTITY_NOTE_RE,
    RECOVERABLE_RELEASE_TAG_RE,
    WATCH_LIFECYCLE_NOTIFICATION_ACTIONS,
    WATCH_PUBLISH_ACTIONS,
    WATCH_RECOVERY_ACTION,
    action_filename,
    audit_reconstruction,
    email_digest,
    email_fallback,
    mutation_allowed,
    notification_decision,
    pending_recipe_rebuild,
    recipe_identity_note,
    release_event_recorded,
    release_is_newest,
    release_recipe_identity,
    release_transition,
    retained_notification_issue,
    route_watch_action,
    transition_event,
    unrecorded_published_release,
    validate_completed_event_record,
    watch_decision,
)
from autorelease._validation import (  # noqa: E402
    ACTION_KEY_RE,
    COMMIT_SHA_RE,
    PROTECTED_PATHS,
    PROTECTED_PATTERNS,
    ROOT,
    SECRET_PATTERNS,
    SHA256_RE,
    STABLE_VERSION_RE,
    ControlError,
    _archive_member_name,
    canonical_json,
    contained_path,
    load_json,
    path_is_allowed,
    path_is_protected,
    require,
    resolve_json_pointer,
    sha256_bytes,
    sha256_file,
    utc_now,
    validate_archive,
    write_json,
)


def project_release_identity(body: bytes) -> bytes:
    """Project a GitHub releases capture to its release identity.

    Per-asset download counters move whenever anyone fetches a published
    artifact, so a digest that covers them wakes the watcher, and can break a
    mid-transaction recapture, with no release consequence. Draft releases are
    listed only to a token with push access, so the read-only watcher never sees
    one while the publish job's write token does; covering them would make every
    recapture fail while a draft exists, including the draft a rebuild resumes.
    The projection drops only `assets[].download_count` and draft entries; every
    other field stays covered by the digest, and the capture client retains the
    unprojected list, its pages joined as one canonical array, beside the digested
    body. A body that is not a GitHub releases array is returned unchanged so an unexpected source format still
    registers as changed evidence. This projects identity only; the classifier
    reads release state from the stored projection, never from these rules.
    """
    try:
        releases = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return body
    if not isinstance(releases, list):
        return body
    releases = [
        release for release in releases if not (isinstance(release, dict) and release.get("draft") is True)
    ]
    for release in releases:
        if not isinstance(release, dict):
            continue
        assets = release.get("assets")
        if not isinstance(assets, list):
            continue
        for asset in assets:
            if isinstance(asset, dict):
                asset.pop("download_count", None)
    return canonical_json(releases)


def strip_supported_versions_date_presentation(body: bytes) -> bytes:
    """Project the supported-versions page to its lifecycle identity.

    The page renders the capture date into every response: an SVG "today"
    marker whose coordinates and label move daily, and relative-age table
    cells that restate the adjacent absolute dates as time since or until
    now. A digest covering them wakes the watcher every day with no
    lifecycle consequence, forcing a classification and an evidence-state PR on
    otherwise quiet days. The projection empties only those two renderings;
    branch rows and their absolute support dates stay covered, and the
    capture client retains the unprojected bytes beside the digested body.
    A body without the markers is returned unchanged so an unexpected page
    format still registers as changed evidence. This projects identity
    only: lifecycle state is read from the stored body by the reviewed
    parser in `_classifier`, which fails closed on any other page shape
    (verify.py check A11).
    """
    body = re.sub(rb'<g class="today">.*?</g>', b'<g class="today"></g>', body, flags=re.DOTALL)
    return re.sub(rb'(<td class="collapse-phone">)<em>[^<]*</em>(</td>)', rb"\1\2", body)


# Which sources are authoritative is a reviewed decision rather than a client detail, so
# the registry stays in this surface and is handed to the capture client. autorelease/
# verify.py check A11 reads this file to prove the raw sources are still fetched as
# opaque bytes; lifecycle state is read afterwards, from the stored capture, by the
# reviewed parser in `_classifier`. Two reviewed identity
# projections exist: the GitHub releases digests must not cover per-asset download
# counters or draft releases (visible only to some tokens), and the supported-versions
# digest must not cover the page's renderings of the capture date. None of these carry
# a release consequence. Every php.net source bypasses the CDN edge cache in front of
# it, because an edge can serve a snapshot weeks old and the watcher and the publish
# recapture reach different edges. Both GitHub releases lists are read page by page, so
# rebuild selection and record recovery see every release rather than the newest 100.
# The php-src tags list stays one page: no rule reads it, and its digest only wakes the
# watcher. These are the fixed
# sources; `evidence_sources` adds the per-branch release feeds the policy selects.
EVIDENCE_SOURCES = (
    EvidenceSource("php_supported_versions", "https://www.php.net/supported-versions.php", 2_000_000, normalize=strip_supported_versions_date_presentation, bypass_edge_cache=True),
    EvidenceSource("php_release_feed", "https://www.php.net/releases/index.php?json", 5_000_000, bypass_edge_cache=True),
    EvidenceSource("php_source_tags", "https://api.github.com/repos/php/php-src/tags?per_page=100", 5_000_000),
    EvidenceSource("php_bin_releases", "https://api.github.com/repos/bigpixelrocket/php-bin/releases?per_page=100", 20_000_000, normalize=project_release_identity, paginate=True),
    EvidenceSource("php_bin_state", "https://api.github.com/repos/bigpixelrocket/php-bin/commits/main", 2_000_000),
    EvidenceSource("mise_php_releases", "https://api.github.com/repos/bigpixelrocket/mise-php/releases?per_page=100", 20_000_000, normalize=project_release_identity, paginate=True),
    EvidenceSource("mise_php_state", "https://api.github.com/repos/bigpixelrocket/mise-php/commits/main", 2_000_000),
)


def evidence_sources(maintained_branches: list[str]) -> tuple[EvidenceSource, ...]:
    """Return the fixed sources plus one release feed per maintained branch.

    The aggregate feed keeps only the newest release of each major, so a patch on an
    older branch would otherwise never have official evidence. The branch list comes
    from the accepted support policy, so adding or retiring a branch changes what is
    captured without a code change. Branch feeds follow the aggregate feed in policy
    order, which keeps the manifest, and therefore its digest, deterministic.
    """
    branch_feeds = tuple(
        EvidenceSource(
            branch_feed_capture_id(branch),
            f"https://www.php.net/releases/index.php?json&version={branch}",
            5_000_000,
            bypass_edge_cache=True,
        )
        for branch in maintained_branches
    )
    position = next(
        index for index, source in enumerate(EVIDENCE_SOURCES) if source.capture_id == "php_release_feed"
    )
    return EVIDENCE_SOURCES[: position + 1] + branch_feeds + EVIDENCE_SOURCES[position + 1 :]


def cli_flag(value: str, name: str) -> bool:
    """Read a workflow-supplied boolean, where a skipped step legitimately supplies none."""
    require(value in {"", "true", "false"}, f"{name} must be true, false, or empty")
    return value == "true"


def cli_error(error: Exception) -> int:
    print(f"autorelease control rejected input: {error}", file=sys.stderr)
    return 1


def captured_php_bin_releases(manifest_path: pathlib.Path) -> list[dict[str, Any]]:
    """Return the php-bin releases a healthy capture lists, or none from an unhealthy one.

    An unhealthy capture already decides the run through the `source_unhealthy`
    trigger, so its body is never parsed.
    """
    capture, body = load_capture(manifest_path, "php_bin_releases")
    if capture.get("status") != 200:
        return []
    try:
        published = json.loads(body)
    except json.JSONDecodeError as error:
        raise ControlError(f"captured php-bin releases are not valid JSON: {error}") from error
    require(isinstance(published, list), "captured php-bin releases are not an array")
    return [item for item in published if isinstance(item, dict)]


def recipe_identities(root: pathlib.Path, commit: str) -> dict[str, str]:
    """Map every maintained branch in the accepted policy to its recipe identity at `commit`."""
    return {
        branch: recipe_identity(root, commit, branch)
        for branch in validate_support_policy(root)["maintainedBranches"]
    }


def due_recipe_rebuild(manifest_path: pathlib.Path, root: pathlib.Path, commit: str) -> str | None:
    """Select the rebuild due for a capture and one exact recipe commit.

    Admission calls this with the same capture, commit, and accepted policy the watcher
    used, so it re-derives the selection instead of trusting it. Like the watcher, it
    selects nothing from a capture with any unhealthy source: that run is decided by
    `source_unhealthy`, and its publication would fail recapture anyway.
    """
    manifest = load_json(manifest_path)
    captures = manifest.get("captures") if isinstance(manifest, dict) else None
    require(isinstance(captures, list), "evidence manifest captures must be an array")
    if any(not isinstance(capture, dict) or capture.get("status") != 200 for capture in captures):
        return None
    return pending_recipe_rebuild(captured_php_bin_releases(manifest_path), recipe_identities(root, commit))


def load_event_records(directory: pathlib.Path) -> list[dict[str, Any]]:
    """Load every durable event record, failing closed on a missing directory or bad file."""
    require(directory.is_dir(), f"events directory is missing: {directory}")
    records = [load_json(path) for path in sorted(directory.glob("*.json"))]
    require(all(isinstance(record, dict) for record in records), "event record must be an object")
    return records


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    digest_parser = subparsers.add_parser("digest")
    digest_parser.add_argument("path", type=pathlib.Path)

    classify_parser = subparsers.add_parser("classify")
    classify_parser.add_argument("--manifest", required=True, type=pathlib.Path)
    classify_parser.add_argument("--preconditions", required=True, type=pathlib.Path)
    classify_parser.add_argument("--events", required=True, type=pathlib.Path)
    classify_parser.add_argument("--output", required=True, type=pathlib.Path)

    apply_parser = subparsers.add_parser("apply-lifecycle")
    apply_parser.add_argument("--plan", required=True, type=pathlib.Path)
    apply_parser.add_argument("--manifest", required=True, type=pathlib.Path)
    apply_parser.add_argument("--repo", required=True, type=pathlib.Path)

    capture_parser = subparsers.add_parser("capture-evidence")
    capture_parser.add_argument("--output", required=True, type=pathlib.Path)

    recapture_parser = subparsers.add_parser("validate-recaptured-evidence")
    recapture_parser.add_argument("--plan", required=True, type=pathlib.Path)
    recapture_parser.add_argument("--admitted-manifest", required=True, type=pathlib.Path)
    recapture_parser.add_argument("--current-manifest", required=True, type=pathlib.Path)

    event_parser = subparsers.add_parser("transition-event")
    event_parser.add_argument("--event", required=True, type=pathlib.Path)
    event_parser.add_argument("--target", required=True)
    event_parser.add_argument("--evidence", required=True, type=pathlib.Path)
    event_parser.add_argument("--output", required=True, type=pathlib.Path)

    route_parser = subparsers.add_parser("route-watch-action")
    for name in ("--action", "--action-key", "--record-action-key"):
        route_parser.add_argument(name, default="")
    for name in ("--edits-required", "--recovery-merged", "--evidence-already-recorded"):
        route_parser.add_argument(name, default="")

    operator_parser = subparsers.add_parser("operator-gate")
    operator_parser.add_argument("--operator-file", required=True, type=pathlib.Path)
    operator_parser.add_argument("--require-enabled", action="store_true")

    # Whether main's copy of an event record already completes one published release;
    # an absent --record file means main has no record under that name.
    recorded_parser = subparsers.add_parser("release-recorded")
    recorded_parser.add_argument("--record", required=True, type=pathlib.Path)
    recorded_parser.add_argument("--action-key", required=True)
    recorded_parser.add_argument("--version", required=True)
    recorded_parser.add_argument("--transaction", type=pathlib.Path)

    filename_parser = subparsers.add_parser("action-filename")
    filename_parser.add_argument("action_key")
    filename_parser.add_argument("--suffix", default=".json")

    archive_parser = subparsers.add_parser("validate-archive")
    archive_parser.add_argument("--archive", required=True, type=pathlib.Path)
    archive_parser.add_argument("--version", required=True)

    email_parser = subparsers.add_parser("email-digest")
    email_parser.add_argument("--workflow", required=True)
    email_parser.add_argument("--conclusion", required=True)
    email_parser.add_argument("--run-url", required=True)
    email_parser.add_argument("--repository", required=True)
    # A run that crashed before retaining its state legitimately has none of these
    # files; email_digest decides per conclusion whether that absence is acceptable.
    email_parser.add_argument("--decision", type=pathlib.Path)
    email_parser.add_argument("--plan", type=pathlib.Path)
    email_parser.add_argument("--transaction", type=pathlib.Path)

    subparsers.add_parser("validate-policy")

    args = parser.parse_args(argv)
    try:
        if args.command == "digest":
            print(sha256_file(args.path))
        elif args.command == "classify":
            plan = classify_evidence(
                args.manifest,
                load_json(args.preconditions),
                load_event_records(args.events),
                validate_support_policy(ROOT)["maintainedBranches"],
            )
            write_json(args.output, plan)
            print(json.dumps({"action": plan["action"], "actionKey": plan["actionKey"]}))
        elif args.command == "apply-lifecycle":
            plan = load_json(args.plan)
            manifest = load_json(args.manifest)
            require(isinstance(plan, dict) and isinstance(manifest, dict), "plan and manifest must be objects")
            print(json.dumps({"changed": apply_lifecycle_plan(args.repo, plan, manifest)}))
        elif args.command == "capture-evidence":
            print(
                json.dumps(
                    capture_evidence(
                        args.output,
                        evidence_sources(validate_support_policy(ROOT)["maintainedBranches"]),
                        token=os.environ.get("GITHUB_TOKEN"),
                    )
                )
            )
        elif args.command == "validate-recaptured-evidence":
            plan = load_json(args.plan)
            result = validate_recaptured_evidence(
                plan,
                load_json(args.admitted_manifest),
                load_json(args.current_manifest),
            )
            # Recapture exempts feeds that cannot prove the version, so supersession is
            # rechecked on the fresh captures: a later patch on the branch in any feed
            # still stops the release, even one the digest comparison released.
            validate_release_is_newest_patch(plan.get("action", ""), plan.get("releaseIntent"), args.current_manifest)
            print(json.dumps(result))
        elif args.command == "transition-event":
            updated = transition_event(load_json(args.event), args.target, load_json(args.evidence))
            write_json(args.output, updated)
            print(json.dumps(updated))
        elif args.command == "route-watch-action":
            print(
                json.dumps(
                    route_watch_action(
                        {
                            "action": args.action,
                            "actionKey": args.action_key,
                            "recordActionKey": args.record_action_key,
                            "editsRequired": cli_flag(args.edits_required, "--edits-required"),
                            "recoveryMerged": cli_flag(args.recovery_merged, "--recovery-merged"),
                            "evidenceAlreadyRecorded": cli_flag(
                                args.evidence_already_recorded, "--evidence-already-recorded"
                            ),
                        }
                    )
                )
            )
        elif args.command == "operator-gate":
            state = load_json(args.operator_file)
            require(isinstance(state, dict), "operator control is not an object")
            require(
                state.get("unattendedMutation") in {"enabled", "paused"},
                "operator control carries an unknown unattended mutation state",
            )
            allowed = mutation_allowed(state)
            require(allowed or not args.require_enabled, "unattended mutation is paused")
            print("enabled" if allowed else "paused")
        elif args.command == "release-recorded":
            asset_digests = None
            if args.transaction is not None:
                transaction = load_json(args.transaction)
                asset_digests = transaction.get("assetDigests") if isinstance(transaction, dict) else None
                require(
                    isinstance(asset_digests, dict) and bool(asset_digests),
                    "release transaction carries no asset digests",
                )
            record = load_json(args.record) if args.record.exists() else None
            recorded = release_event_recorded(record, args.action_key, args.version, asset_digests)
            print("true" if recorded else "false")
        elif args.command == "action-filename":
            print(action_filename(args.action_key, args.suffix))
        elif args.command == "validate-archive":
            validate_archive(args.archive, args.version)
            print(json.dumps({"valid": True}))
        elif args.command == "email-digest":
            report = {
                "workflow": args.workflow,
                "conclusion": args.conclusion,
                "runUrl": args.run_url,
                "repository": args.repository,
            }
            # A corrupt artifact or an unclassifiable outcome must still email a
            # summary rather than go silent, so rejection selects the fallback
            # template instead of failing the digest run.
            try:
                message = email_digest(
                    {
                        **report,
                        "decision": load_json(args.decision) if args.decision and args.decision.exists() else None,
                        "plan": load_json(args.plan) if args.plan and args.plan.exists() else None,
                        "transaction": load_json(args.transaction)
                        if args.transaction and args.transaction.exists()
                        else None,
                    }
                )
            except ControlError as error:
                message = email_fallback(report, str(error))
            print(json.dumps(message))
        elif args.command == "validate-policy":
            print(json.dumps(validate_support_policy(ROOT)))
        return 0
    except (ControlError, OSError, subprocess.CalledProcessError) as error:
        return cli_error(error)


if __name__ == "__main__":
    raise SystemExit(main())
