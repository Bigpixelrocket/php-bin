#!/usr/bin/env python3
"""Deterministic autorelease controls.

This module deliberately does not classify PHP releases or lifecycle state.
It validates authority, evidence, state transitions, and immutable effects
selected by Codex.

It is the stable import surface for the package behind it, so every name the
workflows, scripts, verifier, and tests already use stays importable from here:

- `_validation` — digests, canonical JSON, path containment, and the regular
  expressions that fix the shape of every identifier.
- `_evidence` — the opaque capture client and the readers that re-derive a
  cited capture's identity.
- `_state` — the event, release, and watcher state machines, including the one
  routing table the watcher follows.
- `_admission` — the three gates model-authored work passes: the plan, the
  sealed patch, and the merge.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys

# Workflows run this file directly (`./autorelease/control.py <command>`), where only
# the autorelease directory is on the import path, while the scripts, verify.py, and
# the tests import it as `autorelease.control`. Direct execution therefore borrows the
# same repository-root shim the scripts use, so the absolute imports below resolve in
# both contexts and no consumer has to know which one it is in.
if __package__ in {None, ""}:
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from autorelease._admission import (  # noqa: E402
    PROHIBITED_AGENT_AUTHORITY,
    REQUIRED_PLAN_CHECKS,
    _validate_plan_shape,
    _validate_support_policy_document,
    changed_paths,
    git,
    seal_patch,
    validate_completion_assessment,
    validate_plan,
    validate_stable_release_evidence,
    validate_support_policy,
    validate_task_contract,
    verify_merge,
)
from autorelease._evidence import (  # noqa: E402
    EVIDENCE_CAPTURE_IDS,
    RUNTIME_PLAN_EVIDENCE_IDS,
    EvidenceSource,
    RestrictedRedirect,
    capture_evidence,
    load_capture,
    load_plan_evidence,
    manifest_digest,
    validate_evidence_attestation_predicate,
    validate_evidence_state_record,
    validate_recaptured_evidence,
)
from autorelease._state import (  # noqa: E402
    ACTION_FILENAME_MAP,
    LEGAL_EVENT_TRANSITIONS,
    LEGAL_RELEASE_TRANSITIONS,
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
    release_transition,
    retained_notification_issue,
    retry_decision,
    route_watch_action,
    transition_event,
    unrecorded_published_release,
    validate_completed_event_record,
    watch_decision,
)
from autorelease._validation import (  # noqa: E402
    ACTION_KEY_RE,
    COMMIT_SHA_RE,
    COMPLETION_EVIDENCE_REF_RE,
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
    instruction_digest,
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


def strip_release_download_counts(body: bytes) -> bytes:
    """Project a GitHub releases capture to its release identity.

    Per-asset download counters move whenever anyone fetches a published
    artifact, so a digest that covers them wakes the watcher — and can break a
    mid-transaction recapture — with no release consequence. The projection
    drops only `assets[].download_count`; every other field stays covered by
    the digest, and the capture client retains the unprojected bytes beside
    the digested body. A body that is not a GitHub releases array is returned
    unchanged so an unexpected source format still registers as changed
    evidence. This projects identity only: classifying lifecycle state from a
    body remains forbidden (verify.py check A11).
    """
    try:
        releases = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return body
    if not isinstance(releases, list):
        return body
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
    lifecycle consequence, forcing a model call and an evidence-state PR on
    otherwise quiet days. The projection empties only those two renderings;
    branch rows and their absolute support dates stay covered, and the
    capture client retains the unprojected bytes beside the digested body.
    A body without the markers is returned unchanged so an unexpected page
    format still registers as changed evidence. This projects identity
    only: classifying lifecycle state from a body remains forbidden
    (verify.py check A11).
    """
    body = re.sub(rb'<g class="today">.*?</g>', b'<g class="today"></g>', body, flags=re.DOTALL)
    return re.sub(rb'(<td class="collapse-phone">)<em>[^<]*</em>(</td>)', rb"\1\2", body)


# Which sources are authoritative is a reviewed decision rather than a client detail, so
# the registry stays in this surface and is handed to the capture client. autorelease/
# verify.py check A11 reads this file to prove the raw sources are still fetched as
# opaque bytes and never classified into lifecycle state. Two reviewed identity
# projections exist: the GitHub releases digests must not cover per-asset download
# counters, and the supported-versions digest must not cover the page's renderings of
# the capture date. Both change without any release consequence.
EVIDENCE_SOURCES = (
    EvidenceSource("php_supported_versions", "https://www.php.net/supported-versions.php", 2_000_000, normalize=strip_supported_versions_date_presentation),
    EvidenceSource("php_release_feed", "https://www.php.net/releases/index.php?json", 5_000_000),
    EvidenceSource("php_source_tags", "https://api.github.com/repos/php/php-src/tags?per_page=100", 5_000_000),
    EvidenceSource("php_bin_releases", "https://api.github.com/repos/bigpixelrocket/php-bin/releases?per_page=100", 10_000_000, normalize=strip_release_download_counts),
    EvidenceSource("php_bin_state", "https://api.github.com/repos/bigpixelrocket/php-bin/commits/main", 2_000_000),
    EvidenceSource("mise_php_releases", "https://api.github.com/repos/bigpixelrocket/mise-php/releases?per_page=100", 10_000_000, normalize=strip_release_download_counts),
    EvidenceSource("mise_php_state", "https://api.github.com/repos/bigpixelrocket/mise-php/commits/main", 2_000_000),
)


def cli_flag(value: str, name: str) -> bool:
    """Read a workflow-supplied boolean, where a skipped step legitimately supplies none."""
    require(value in {"", "true", "false"}, f"{name} must be true, false, or empty")
    return value == "true"


def cli_error(error: Exception) -> int:
    print(f"autorelease control rejected input: {error}", file=sys.stderr)
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
        elif args.command == "validate-contract":
            contract = load_json(args.contract)
            assessment = load_json(args.assessment)
            validate_completion_assessment(assessment, contract, assessment.get("instructionDigests"))
            print(json.dumps({"valid": True}))
        elif args.command == "capture-evidence":
            print(
                json.dumps(
                    capture_evidence(
                        args.output, EVIDENCE_SOURCES, token=os.environ.get("GITHUB_TOKEN")
                    )
                )
            )
        elif args.command == "validate-recaptured-evidence":
            print(
                json.dumps(
                    validate_recaptured_evidence(
                        load_json(args.plan),
                        load_json(args.admitted_manifest),
                        load_json(args.current_manifest),
                    )
                )
            )
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
