import contextlib
import io
import json
import pathlib
import re
import runpy
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

from autorelease.control import (
    ACTION_KEY_RE,
    COMPLETION_EVIDENCE_REF_RE,
    ControlError,
    action_filename,
    canonical_json,
    email_digest,
    email_fallback,
    load_plan_evidence,
    main as control_main,
    mutation_allowed,
    route_watch_action,
    notification_decision,
    retained_notification_issue,
    release_transition,
    retry_decision,
    seal_patch,
    sha256_bytes,
    sha256_file,
    transition_event,
    validate_archive,
    validate_completion_assessment,
    validate_completed_event_record,
    validate_evidence_attestation_predicate,
    validate_evidence_state_record,
    validate_recaptured_evidence,
    validate_stable_release_evidence,
    verify_merge,
    watch_decision,
    path_is_protected,
)


def run_control(*argv: str) -> tuple[int, str]:
    """Run a control CLI subcommand exactly as a workflow would, capturing its output."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        status = control_main(list(argv))
    return status, out.getvalue().strip()


class AutoreleaseControlTests(unittest.TestCase):
    @staticmethod
    def _contract():
        return {
            "contractVersion": 1,
            "phase": "implementation",
            "goal": "Update one admitted fixture.",
            "actionKey": "repair:8.5.9:deadbeef",
            "preconditions": {},
            "allowedAuthority": ["workspace_write_admitted_paths"],
            "nonGoals": ["irreversible_effect"],
            "completionCriteria": [
                {"id": "done", "requirement": "Done.", "evidenceRequired": "Diff."}
            ],
            "stopConditions": ["protected_change"],
        }

    @staticmethod
    def _assessment(contract, digests):
        return {
            "contractVersion": 1,
            "instructionDigests": digests,
            "phaseStatus": "complete",
            "criteria": [{"id": contract["completionCriteria"][0]["id"], "status": "passed", "evidence": ["diff"]}],
            "goNoGo": "go",
            "unresolved": [],
            "summary": "Done.",
        }

    def test_quiet_snapshot_does_not_wake_agent(self):
        manifest = {"manifestDigest": "sha256:" + "a" * 64, "captures": [{"status": 200}]}
        decision = watch_decision(manifest, manifest, [], {"healthy": True})
        self.assertEqual("quiet", decision["trigger"])
        self.assertFalse(decision["modelCall"])

    def test_evidence_recording_commit_does_not_wake_itself(self):
        previous = {
            "manifestDigest": "sha256:" + "a" * 64,
            "captures": [
                {"captureId": "php_bin_state", "status": 200, "digest": "sha256:" + "b" * 64},
                {"captureId": "php_release_feed", "status": 200, "digest": "sha256:" + "c" * 64},
            ],
        }
        current = {
            "manifestDigest": "sha256:" + "d" * 64,
            "captures": [
                {"captureId": "php_bin_state", "status": 200, "digest": "sha256:" + "e" * 64},
                {"captureId": "php_release_feed", "status": 200, "digest": "sha256:" + "c" * 64},
            ],
        }
        ordinary = watch_decision(current, previous, [], {"healthy": True})
        self_update = watch_decision(
            current,
            previous,
            [],
            {"healthy": True},
            self_evidence_update=True,
        )
        self.assertEqual("evidence_changed", ordinary["trigger"])
        self.assertEqual("quiet", self_update["trigger"])
        current["captures"][1]["digest"] = "sha256:" + "f" * 64
        external_change = watch_decision(
            current,
            previous,
            [],
            {"healthy": True},
            self_evidence_update=True,
        )
        self.assertEqual("evidence_changed", external_change["trigger"])

    @staticmethod
    def _releases_manifest(status=200):
        return {
            "manifestDigest": "sha256:" + "a" * 64,
            "captures": [{"captureId": "php_bin_releases", "status": status, "digest": "sha256:" + "b" * 64}],
        }

    def test_watch_flags_published_release_missing_event_record(self):
        manifest = self._releases_manifest()
        releases = [
            {"tag_name": "8.5.9", "draft": False, "prerelease": False, "immutable": True},
            {"tag_name": "8.5.8", "draft": False, "prerelease": False, "immutable": True},
        ]
        events = [{"actionKey": "new_patch:8.5.8", "state": "complete"}]
        decision = watch_decision(manifest, manifest, events, {"healthy": True}, releases=releases)
        self.assertEqual("record_completed_event", decision["action"])
        self.assertEqual("new_patch:8.5.9", decision["actionKey"])
        self.assertEqual("record_missing", decision["trigger"])
        self.assertFalse(decision["modelCall"])

        # A changed snapshot would otherwise select new work; the missing record wins the
        # trigger, but recovery never withholds the investigation those paths depend on,
        # so a repair that stays blocked cannot starve them run after run.
        changed = {"manifestDigest": "sha256:" + "c" * 64, "captures": manifest["captures"]}
        moved = watch_decision(changed, manifest, events, {"healthy": True}, releases=releases)
        self.assertEqual("record_completed_event", moved["action"])
        self.assertTrue(moved["modelCall"])
        incomplete = watch_decision(
            manifest,
            manifest,
            [*events, {"actionKey": "new_patch:8.5.7", "state": "released"}],
            {"healthy": True},
            releases=releases,
        )
        self.assertEqual("record_completed_event", incomplete["action"])
        self.assertTrue(incomplete["modelCall"])
        self.assertEqual(["new_patch:8.5.7"], incomplete["incompleteActions"])

        rebuild = watch_decision(
            manifest,
            manifest,
            [*events, {"actionKey": "new_patch:8.5.9", "state": "complete"}],
            {"healthy": True},
            releases=[*releases, {"tag_name": "8.5.9-2", "draft": False, "prerelease": False, "immutable": True}],
        )
        self.assertEqual("recipe_rebuild:8.5.9:2", rebuild["actionKey"])

    def test_unprovable_release_records_are_not_recovered(self):
        manifest = self._releases_manifest()
        published = {"tag_name": "8.5.9", "draft": False, "prerelease": False, "immutable": True}
        for release in (
            {**published, "immutable": False},
            {**published, "draft": True},
            {**published, "prerelease": True},
            {**published, "tag_name": "8.6.0"},
            {**published, "tag_name": "8.5.9-rc1"},
        ):
            decision = watch_decision(manifest, manifest, [], {"healthy": True}, releases=[release])
            self.assertEqual("none", decision["action"], release)
            self.assertEqual("quiet", decision["trigger"], release)
        unhealthy = self._releases_manifest(status=500)
        self.assertEqual(
            "source_unhealthy",
            watch_decision(unhealthy, unhealthy, [], {"healthy": True}, releases=[published])["trigger"],
        )
        for state in ("complete", "released"):
            decision = watch_decision(
                manifest,
                manifest,
                [{"actionKey": "new_patch:8.5.9", "state": state}],
                {"healthy": True},
                releases=[published],
            )
            self.assertEqual("none", decision["action"], state)
        # The filer refuses to overwrite an existing file, so a record filename already
        # taken by an unrelated document must not be requested again on every run.
        occupied = watch_decision(
            manifest,
            manifest,
            [],
            {"healthy": True},
            releases=[published],
            record_files=["new_patch-8.5.9.json"],
        )
        self.assertEqual("none", occupied["action"])
        self.assertEqual("quiet", occupied["trigger"])

    def test_completion_go_is_mechanical(self):
        contract = {
            "contractVersion": 1,
            "phase": "investigation",
            "goal": "Classify one fixture.",
            "actionKey": "new_patch:8.5.9",
            "preconditions": {},
            "allowedAuthority": ["read_repository"],
            "nonGoals": ["mutation"],
            "completionCriteria": [
                {"id": "done", "requirement": "Done.", "evidenceRequired": "Evidence."}
            ],
            "stopConditions": ["missing_evidence"],
        }
        digests = {
            "shared": "sha256:" + "a" * 64,
            "phaseTemplate": "sha256:" + "b" * 64,
            "eventContract": "sha256:" + "c" * 64,
        }
        assessment = {
            "contractVersion": 1,
            "instructionDigests": digests,
            "phaseStatus": "complete",
            "criteria": [{"id": "done", "status": "passed", "evidence": ["evidence[0]"]}],
            "goNoGo": "go",
            "unresolved": [],
            "summary": "Done.",
        }
        validate_completion_assessment(assessment, contract, digests)
        assessment["unresolved"] = ["contradiction"]
        with self.assertRaises(ControlError):
            validate_completion_assessment(assessment, contract, digests)

    def test_investigation_evidence_references_are_machine_resolvable(self):
        for reference in (
            "evidence[0]",
            "preconditions.phpBinHead",
            "preconditions.misePhpHead",
            "preconditions.supportPolicyDigest",
            "researchSources[2]",
        ):
            self.assertIsNotNone(COMPLETION_EVIDENCE_REF_RE.fullmatch(reference))
        self.assertIsNone(COMPLETION_EVIDENCE_REF_RE.fullmatch("watch-decision.json reports success"))

    def test_investigation_defers_required_checks_to_writable_jobs(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        instructions = (root / ".github/codex/autorelease/investigation.md").read_text()
        watcher = (root / ".github/workflows/autorelease-watch.yml").read_text()
        self.assertIn("Treat `requiredChecks` as downstream exact-head gates", instructions)
        self.assertIn("do not run them in this read-only", instructions)
        self.assertIn("not-yet-run status as unresolved", instructions)
        self.assertIn(
            "--non-goal repository_mutation \\\n"
            "            --non-goal required_check_execution \\\n"
            "            --non-goal irreversible_github_effect \\",
            watcher,
        )

    def test_deterministic_evidence_state_shape_is_fail_closed(self):
        capture_ids = (
            "php_supported_versions",
            "php_release_feed",
            "php_source_tags",
            "php_bin_releases",
            "php_bin_state",
            "mise_php_releases",
            "mise_php_state",
        )
        record = {
            "schemaVersion": 1,
            "manifestDigest": "sha256:" + "a" * 64,
            "planDigest": "sha256:" + "b" * 64,
            "captures": [
                {"captureId": capture_id, "digest": "sha256:" + "c" * 64, "status": 200}
                for capture_id in capture_ids
            ],
        }
        validate_evidence_state_record(record)
        record["captures"][0]["status"] = 500
        with self.assertRaisesRegex(ControlError, "not healthy"):
            validate_evidence_state_record(record)

    def test_evidence_attestation_is_bound_to_the_exact_watcher_run(self):
        predicate = {
            "schemaVersion": 1,
            "runId": "30359936149",
            "sourceSha": "a" * 40,
            "actionKey": "no_change:" + "c" * 16,
            "manifestDigest": "sha256:" + "c" * 64,
        }
        expected = {
            "run_id": predicate["runId"],
            "source_sha": predicate["sourceSha"],
            "action_key": predicate["actionKey"],
            "manifest_digest": predicate["manifestDigest"],
        }
        validate_evidence_attestation_predicate(predicate, **expected)
        predicate["runId"] = "30359936150"
        with self.assertRaisesRegex(ControlError, "run mismatch"):
            validate_evidence_attestation_predicate(predicate, **expected)

    def test_source_tag_alone_cannot_admit_a_stable_release(self):
        release_intent = {"version": "8.5.9", "sourceIdentifier": "php_source_tags:deadbeef"}
        tag_only = [{"captureId": "php_source_tags", "value": "php-8.5.9"}]
        with self.assertRaisesRegex(ControlError, "official PHP release feed"):
            validate_stable_release_evidence("new_patch", release_intent, tag_only)
        validate_stable_release_evidence(
            "new_patch",
            release_intent,
            [*tag_only, {"captureId": "php_release_feed", "value": "8.5.9"}],
        )

    def test_release_recapture_ignores_runtime_evidence_and_verifies_sources(self):
        capture_ids = sorted(
            {
                "php_supported_versions",
                "php_release_feed",
                "php_source_tags",
                "php_bin_releases",
                "php_bin_state",
                "mise_php_releases",
                "mise_php_state",
            }
        )
        captures = [
            {"captureId": capture_id, "status": 200, "digest": "sha256:" + f"{index:064x}"}
            for index, capture_id in enumerate(capture_ids, start=1)
        ]
        manifest = {
            "schemaVersion": 1,
            "captures": captures,
            "manifestDigest": sha256_bytes(
                canonical_json(
                    [
                        {"captureId": item["captureId"], "status": item["status"], "digest": item["digest"]}
                        for item in captures
                    ]
                )
            ),
        }
        plan = {
            "evidence": [
                {"captureId": item["captureId"], "digest": item["digest"]} for item in captures
            ]
            + [
                {"captureId": "watch_decision", "digest": "sha256:" + "a" * 64},
                {"captureId": "evidence_manifest", "digest": "sha256:" + "b" * 64},
            ]
        }
        result = validate_recaptured_evidence(plan, manifest, manifest)
        self.assertEqual(capture_ids, result["verifiedCaptureIds"])

        changed = json.loads(json.dumps(manifest))
        changed["captures"][0]["digest"] = "sha256:" + "f" * 64
        changed["manifestDigest"] = sha256_bytes(
            canonical_json(
                [
                    {"captureId": item["captureId"], "status": item["status"], "digest": item["digest"]}
                    for item in changed["captures"]
                ]
            )
        )
        with self.assertRaisesRegex(ControlError, "recaptured evidence changed"):
            validate_recaptured_evidence(plan, manifest, changed)

    def test_runtime_plan_evidence_is_exact_and_allowlisted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            evidence = root / "evidence"
            evidence.mkdir()
            manifest = evidence / "evidence-manifest.json"
            manifest.write_text('{"manifestDigest":"sha256:' + "a" * 64 + '"}')
            (root / "watch-decision.json").write_text('{"trigger":"evidence_changed"}')
            capture, body = load_plan_evidence(manifest, "watch_decision")
            self.assertEqual("watch_decision", capture["captureId"])
            self.assertEqual(sha256_bytes(body), capture["digest"])
            with self.assertRaisesRegex(ControlError, "does not resolve exactly once"):
                load_plan_evidence(manifest, "preconditions")

    def test_illegal_event_transition_fails_closed(self):
        with self.assertRaises(ControlError):
            transition_event({"state": "detected"}, "complete", [{"digest": "x"}])

    def test_completed_event_record_requires_contiguous_legal_evidenced_history(self):
        record = {
            "schemaVersion": 1,
            "actionKey": "new_patch:8.5.9",
            "state": "complete",
            "history": [
                {
                    "from": "release_requested",
                    "to": "released",
                    "at": "2026-07-31T10:00:00Z",
                    "evidence": [{"kind": "published_release"}],
                },
                {
                    "from": "released",
                    "to": "public_install_verified",
                    "at": "2026-07-31T10:01:00Z",
                    "evidence": [{"kind": "fresh_public_install"}],
                },
                {
                    "from": "public_install_verified",
                    "to": "complete",
                    "at": "2026-07-31T10:02:00Z",
                    "evidence": [{"kind": "transaction_complete"}],
                },
            ],
        }
        validate_completed_event_record(record)
        record["history"][1]["from"] = "detected"
        with self.assertRaisesRegex(ControlError, "not contiguous"):
            validate_completed_event_record(record)

    def test_future_branch_action_keys_admitted(self):
        for key in (
            "new_patch:8.6.1",
            "new_patch:9.0.1",
            "new_branch:8.6",
            "new_branch:9.0",
            "branch_eol:8.2:2026-12-31",
        ):
            self.assertIsNotNone(ACTION_KEY_RE.fullmatch(key), key)

    def test_published_asset_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "archive").write_text("staged")
            digests = {"archive": sha256_file(root / "archive")}
            transaction = {
                "state": "draft_verified",
                "publishedAssets": {"archive": "sha256:" + "0" * 64},
            }
            with self.assertRaises(ControlError):
                release_transition(transaction, "published", root, digests)

    def test_email_digest_selects_one_fixed_template_per_outcome(self):
        digest = "sha256:" + "a" * 64
        base = {
            "workflow": "watcher",
            "conclusion": "success",
            "runUrl": "https://github.com/bigpixelrocket/php-bin/actions/runs/1",
            "repository": "bigpixelrocket/php-bin",
        }
        changed = {"modelCall": True, "manifestDigest": digest}
        cases = (
            ({**base, "conclusion": "failure"}, "watcher_failed", "conclusion 'failure'"),
            (
                {**base, "decision": {"modelCall": False, "manifestDigest": digest}},
                "quiet_day",
                "no model call was made",
            ),
            (
                {**base, "decision": changed, "plan": {"action": "no_change", "actionKey": "no_change:" + "0" * 16}},
                "no_change_reviewed",
                digest,
            ),
            (
                {**base, "decision": changed, "plan": {"action": "new_patch", "actionKey": "new_patch:8.5.9"}},
                "new_patch_started",
                "PHP 8.5.9 release started",
            ),
            (
                {**base, "decision": changed, "plan": {"action": "new_branch", "actionKey": "new_branch:8.6"}},
                "new_branch_detected",
                "mise-php records matching exact-commit readiness",
            ),
            (
                {**base, "decision": changed, "plan": {"action": "branch_eol", "actionKey": "branch_eol:8.1:2026-12-31"}},
                "branch_eol_started",
                "PHP 8.1 reached end of life",
            ),
            (
                {**base, "decision": changed, "plan": {"action": "repair", "actionKey": "repair:8.5.9:deadbeef"}},
                "repair_started",
                "repair:8.5.9:deadbeef",
            ),
            (
                {**base, "decision": changed, "plan": {"action": "reconcile_partial", "actionKey": "new_patch:8.5.9"}},
                "reconcile_started",
                "last legal state",
            ),
            (
                {**base, "decision": changed, "plan": {"action": "needs_human", "actionKey": "auth_failure:" + "b" * 8}},
                "watcher_attention",
                "needs_human",
            ),
            (
                {**base, "workflow": "publish", "transaction": {"released": True, "version": "8.5.9"}},
                "release_published",
                "releases/tag/8.5.9",
            ),
            (
                {
                    **base,
                    "workflow": "publish",
                    "conclusion": "failure",
                    "transaction": {"released": True, "version": "8.5.9"},
                },
                "release_record_pending",
                "recovers the record",
            ),
            (
                {
                    **base,
                    "workflow": "publish",
                    "conclusion": "failure",
                    "transaction": {"released": False, "version": "8.5.9"},
                },
                "publish_failed",
                "Publish failed for PHP 8.5.9",
            ),
            ({**base, "workflow": "publish", "conclusion": "failure"}, "publish_failed", "Publish failed"),
        )
        for report, template, needle in cases:
            with self.subTest(template=template):
                message = email_digest(report)
                self.assertEqual(template, message["template"])
                self.assertTrue(message["subject"].startswith("[php-bin autorelease] "))
                self.assertIn(needle, message["subject"] + "\n" + message["body"])
                self.assertIn(base["runUrl"], message["body"])

    def test_email_digest_rejects_unroutable_or_unvalidated_run_state(self):
        digest = "sha256:" + "a" * 64
        base = {
            "workflow": "watcher",
            "conclusion": "success",
            "runUrl": "https://github.com/bigpixelrocket/php-bin/actions/runs/1",
            "repository": "bigpixelrocket/php-bin",
        }
        changed = {"modelCall": True, "manifestDigest": digest}
        rejected = (
            {**base, "workflow": "consumer"},
            {**base, "runUrl": "https://example.invalid/run"},
            {**base, "repository": "php-bin"},
            base,
            {**base, "decision": {"modelCall": False, "manifestDigest": "sha256:short"}},
            {**base, "decision": {"modelCall": False, "manifestDigest": None}},
            {**base, "decision": {"manifestDigest": "sha256:" + "a" * 64}},
            {**base, "decision": {"modelCall": 1, "manifestDigest": "sha256:" + "a" * 64}},
            {**base, "decision": changed},
            {**base, "decision": changed, "plan": {"action": "new_patch", "actionKey": "new_patch:8.5.9; rm -rf"}},
            {**base, "decision": changed, "plan": {"action": "new_patch", "actionKey": None}},
            {**base, "decision": changed, "plan": {"action": "new_patch", "actionKey": "repair:8.5.9:deadbeef"}},
            {**base, "decision": changed, "plan": {"action": "publish", "actionKey": "new_patch:8.5.9"}},
            {**base, "workflow": "publish", "transaction": {"released": True, "version": "main"}},
            {**base, "workflow": "publish"},
            {**base, "workflow": "publish", "transaction": {"released": False, "version": "8.5.9"}},
            {
                **base,
                "workflow": "publish",
                "conclusion": "failure",
                "transaction": {"released": "true", "version": "8.5.9"},
            },
            {
                **base,
                "workflow": "publish",
                "conclusion": "failure",
                "transaction": {"released": True, "version": None},
            },
        )
        for report in rejected:
            with self.subTest(report=report):
                with self.assertRaises(ControlError):
                    email_digest(report)

    def test_email_fallback_summarizes_unclassifiable_state_with_revalidated_values(self):
        report = {
            "workflow": "watcher",
            "conclusion": "success",
            "runUrl": "https://github.com/bigpixelrocket/php-bin/actions/runs/1",
            "repository": "bigpixelrocket/php-bin",
        }
        message = email_fallback(report, "no email template exists for action: publish")
        self.assertEqual("unexpected_state", message["template"])
        self.assertIn("(watcher, success)", message["subject"])
        self.assertIn("no email template exists for action: publish", message["body"])
        self.assertIn(report["runUrl"], message["body"])
        # Values that fail revalidation are replaced, never interpolated.
        hostile = {
            "workflow": "consumer",
            "conclusion": "FAILURE; curl evil",
            "runUrl": "https://example.invalid/run",
        }
        message = email_fallback(hostile, "email digest workflow is unknown")
        self.assertIn("(unknown, unknown)", message["subject"])
        self.assertNotIn("consumer", message["body"])
        self.assertNotIn("curl evil", message["body"])
        self.assertNotIn("example.invalid", message["body"])

    def test_email_digest_cli_falls_back_instead_of_failing(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = pathlib.Path(scratch)
            (root / "watch-decision.json").write_text(
                json.dumps({"modelCall": True, "manifestDigest": "sha256:" + "a" * 64})
            )
            (root / "autorelease-plan.json").write_text("{not json")
            status, output = run_control(
                "email-digest",
                "--workflow",
                "watcher",
                "--conclusion",
                "success",
                "--run-url",
                "https://github.com/bigpixelrocket/php-bin/actions/runs/1",
                "--repository",
                "bigpixelrocket/php-bin",
                "--decision",
                str(root / "watch-decision.json"),
                "--plan",
                str(root / "autorelease-plan.json"),
            )
            self.assertEqual(0, status)
            self.assertEqual("unexpected_state", json.loads(output)["template"])

    def test_notification_replay_is_deduplicated(self):
        event = {"actionKey": "new_patch:8.5.9", "state": "released"}
        first = notification_decision(event, None)
        self.assertEqual(["autorelease"], first["labels"])
        replay = notification_decision(event, {"fingerprint": first["fingerprint"]})
        self.assertEqual("none", replay["action"])

    def test_notification_search_covers_current_and_pre_rename_markers(self):
        namespace = runpy.run_path(
            str(pathlib.Path(__file__).resolve().parents[1] / "scripts/notify-autorelease")
        )
        find_issue = namespace["find_issue"]
        for prefix, number in (("autorelease", 47), ("maintenance", 46)):
            with self.subTest(prefix=prefix):
                issue = {
                    "number": number,
                    "url": f"https://example.invalid/issues/{number}",
                    "state": "CLOSED",
                    "body": f"<!-- {prefix}-action-key:new_patch:8.5.9 -->",
                }
                gh = mock.Mock(
                    side_effect=lambda *arguments, issue=issue, prefix=prefix: json.dumps([issue])
                    if f"{prefix}-action-key" in " ".join(arguments)
                    else "[]"
                )
                with mock.patch.dict(find_issue.__globals__, {"gh": gh}):
                    found = find_issue("Bigpixelrocket/php-bin", "new_patch:8.5.9")
                self.assertEqual(issue, found)

    def test_notification_transition_reuses_retained_issue_identity(self):
        issue = {"number": 10, "url": "https://example.invalid/issues/10", "state": "OPEN"}
        self.assertEqual(issue, retained_notification_issue({"issue": issue}))
        self.assertIsNone(retained_notification_issue({"issue": {}}))
        self.assertIsNone(retained_notification_issue({"issue": {"number": True}}))

        namespace = runpy.run_path(
            str(pathlib.Path(__file__).resolve().parents[1] / "scripts/notify-autorelease")
        )
        apply_github = namespace["apply_github"]
        gh = mock.Mock(return_value="")
        find_issue = mock.Mock(side_effect=AssertionError("search must not run"))
        decision = {
            "action": "comment_and_close",
            "fingerprint": "sha256:" + "a" * 64,
            "labels": ["autorelease"],
        }
        event = {"actionKey": "fixture", "state": "complete", "summary": "Done."}
        with mock.patch.dict(apply_github.__globals__, {"gh": gh, "find_issue": find_issue}):
            result = apply_github("Bigpixelrocket/php-bin", "loadinglucian", event, decision, {"issue": issue})
        find_issue.assert_not_called()
        self.assertEqual("CLOSED", result["state"])
        self.assertEqual("10", gh.call_args_list[0].args[2])
        self.assertEqual("10", gh.call_args_list[1].args[2])

    def test_retry_and_pause_bounds(self):
        self.assertFalse(retry_decision({"attemptCount": 2, "failureFingerprint": "x"}, "x", 2)["recallAgent"])
        self.assertFalse(mutation_allowed({"unattendedMutation": "paused"}))
        self.assertTrue(mutation_allowed({"unattendedMutation": "enabled"}))

    def test_action_filename(self):
        self.assertEqual("branch_eol-8.2-2026-12-31.json", action_filename("branch_eol:8.2:2026-12-31"))
        self.assertEqual("new_patch-8.5.9", action_filename("new_patch:8.5.9", ""))
        with self.assertRaises(ControlError):
            action_filename("../escape")

    def test_route_watch_action_covers_every_decision(self):
        def route(**decision):
            return route_watch_action(decision)

        # No-op routes stay green: an idle run must not fail the watcher.
        self.assertEqual("none", route()["route"])
        self.assertEqual("no_admitted_plan", route(action="none")["reason"])
        self.assertEqual(
            "record_write_deferred_by_recovery",
            route(action="branch_eol", recoveryMerged=True)["reason"],
        )
        # A recovery merge moves main mid-run, so the no-change evidence record — which
        # also commits against an untouched base — waits for the next scheduled run
        # rather than wedging the evidence PR against a base the exemption cannot match.
        deferred_no_change = route(action="no_change", recoveryMerged=True)
        self.assertEqual("none", deferred_no_change["route"])
        self.assertEqual("record_write_deferred_by_recovery", deferred_no_change["reason"])
        self.assertEqual(
            "evidence_state_already_recorded",
            route(action="no_change", evidenceAlreadyRecorded=True)["reason"],
        )
        self.assertEqual(
            "release_published_pending_record",
            route(action="new_patch", actionKey="new_patch:8.5.9", recordActionKey="new_patch:8.5.9")["reason"],
        )
        # Dispatching routes.
        self.assertEqual("notify_blocked", route(action="blocked")["route"])
        self.assertEqual("notify_blocked", route(action="needs_human")["route"])
        self.assertEqual("no_change_evidence", route(action="no_change")["route"])
        self.assertEqual("dispatch_implementation", route(action="repair", editsRequired=True)["route"])
        self.assertEqual("dispatch_implementation", route(action="new_branch", editsRequired=True)["route"])
        self.assertEqual("dispatch_publish", route(action="new_patch")["route"])
        self.assertEqual("dispatch_publish", route(action="new_branch")["route"])
        self.assertEqual("dispatch_publish", route(action="reconcile_partial")["route"])
        self.assertEqual("complete_branch_eol", route(action="branch_eol")["route"])
        # Recovery is an overlay: it carries its own route beside any plan route.
        self.assertEqual("none", route(action="new_patch")["recoveryRoute"])
        self.assertEqual(
            "recover_record",
            route(action="new_patch", recordActionKey="recipe_rebuild:8.5.9:2")["recoveryRoute"],
        )
        self.assertEqual("recover_record", route(recordActionKey="new_patch:8.5.9")["recoveryRoute"])
        # Composing the two functions is the reading their names invite, so a raw
        # watch_decision must route rather than raise: its own action names the repair the
        # recovery overlay owns, and its own key is the key that overlay recovers.
        missing_record = watch_decision(
            self._releases_manifest(),
            self._releases_manifest(),
            [{"actionKey": "new_patch:8.5.8", "state": "complete"}],
            {"healthy": True},
            releases=[
                {"tag_name": "8.5.9", "draft": False, "prerelease": False, "immutable": True},
                {"tag_name": "8.5.8", "draft": False, "prerelease": False, "immutable": True},
            ],
        )
        self.assertEqual("record_completed_event", missing_record["action"])
        composed = route_watch_action(missing_record)
        self.assertEqual("none", composed["route"])
        self.assertEqual("recovery_routed_by_recovery_route", composed["reason"])
        self.assertEqual("recover_record", composed["recoveryRoute"])
        self.assertEqual("new_patch:8.5.9", composed["recordActionKey"])
        # Only the lifecycle actions notify, and blocked plans notify through their route.
        self.assertEqual("lifecycle", route(action="new_branch")["notify"])
        self.assertEqual("lifecycle", route(action="branch_eol")["notify"])
        self.assertEqual("none", route(action="new_patch")["notify"])
        self.assertEqual("none", route(action="blocked")["notify"])
        # Unrouted combinations fail loudly instead of exiting green.
        with self.assertRaises(ControlError):
            route_watch_action({"action": "repair", "editsRequired": False})
        with self.assertRaises(ControlError):
            route_watch_action({"action": "recipe_rebuild", "editsRequired": False})

    def test_operator_gate_blocks_paused_state(self):
        self.assertTrue(mutation_allowed({"unattendedMutation": "enabled"}))
        self.assertFalse(mutation_allowed({"unattendedMutation": "paused"}))
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            enabled = root / "enabled.json"
            enabled.write_text('{"schemaVersion":1,"unattendedMutation":"enabled"}\n')
            paused = root / "paused.json"
            paused.write_text('{"schemaVersion":1,"unattendedMutation":"paused"}\n')
            unknown = root / "unknown.json"
            unknown.write_text('{"schemaVersion":1}\n')
            self.assertEqual((0, "enabled"), run_control("operator-gate", "--operator-file", str(enabled)))
            self.assertEqual((0, "paused"), run_control("operator-gate", "--operator-file", str(paused)))
            self.assertEqual(
                (0, "enabled"),
                run_control("operator-gate", "--operator-file", str(enabled), "--require-enabled"),
            )
            # A paused control and an unreadable control both refuse the hard gate.
            self.assertEqual(
                1, run_control("operator-gate", "--operator-file", str(paused), "--require-enabled")[0]
            )
            self.assertEqual(1, run_control("operator-gate", "--operator-file", str(unknown))[0])
            self.assertEqual(1, run_control("operator-gate", "--operator-file", str(root / "absent.json"))[0])

    def test_route_watch_action_cli_reports_the_route(self):
        status, output = run_control(
            "route-watch-action",
            "--action", "new_patch",
            "--action-key", "new_patch:8.5.9",
            "--record-action-key", "new_patch:8.5.9",
            "--edits-required", "false",
        )
        self.assertEqual(0, status)
        self.assertEqual(
            {"route": "none", "reason": "release_published_pending_record", "recoveryRoute": "recover_record"},
            {key: json.loads(output)[key] for key in ("route", "reason", "recoveryRoute")},
        )
        self.assertEqual("new_patch-8.5.9.json", run_control("action-filename", "new_patch:8.5.9")[1])
        # An unrouted combination exits non-zero rather than dispatching nothing quietly.
        self.assertEqual(1, run_control("route-watch-action", "--action", "repair")[0])
        # Only exact booleans reach the table.
        self.assertEqual(1, run_control("route-watch-action", "--action", "repair", "--edits-required", "yes")[0])

    def test_invariants_and_durable_state_are_protected(self):
        self.assertTrue(path_is_protected(".github/codex-action-contract.json"))
        self.assertTrue(path_is_protected("autorelease/policy-invariants.json"))
        self.assertTrue(path_is_protected("scripts/validate-codex-action-inputs"))
        self.assertTrue(path_is_protected("scripts/dispatch-pr-checks"))
        self.assertTrue(path_is_protected("autorelease-events/new-branch.json"))
        self.assertTrue(path_is_protected("autorelease-state/last-evidence.json"))
        self.assertFalse(path_is_protected("support-policy.json"))

    def test_gate_harness_paths_are_protected(self):
        for path in ("scripts/test.sh", "scripts/build.sh", "scripts/package.sh",
                     "scripts/compare-modules.sh", "scripts/check-public-language.sh",
                     "tests/test_autorelease.py",
                     # Sourced by the protected gate scripts, so agent-authored bash would
                     # otherwise execute inside the gate run that judges the patch.
                     "scripts/lib.sh",
                     # Pin the compiler toolchain that produces published binaries.
                     "scripts/install-spc.sh", "scripts/install-build-deps.sh",
                     ".spc-version", ".spc-sha256"):
            self.assertTrue(path_is_protected(path), path)

    def test_codeowners_covers_every_protected_script(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        patterns = json.loads((root / "autorelease/protected-paths.json").read_text())["patterns"]
        codeowners = (root / ".github/CODEOWNERS").read_text()
        for pattern in patterns:
            if "*" not in pattern:
                self.assertRegex(codeowners, rf"(?m)^/{re.escape(pattern)}\s", pattern)

    def test_token_created_prs_explicitly_dispatch_required_checks(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        ci = (root / ".github/workflows/ci.yml").read_text()
        protected = (root / ".github/workflows/protected-controls.yml").read_text()
        dispatcher = (root / "scripts/dispatch-pr-checks").read_text()
        self.assertIn("workflow_dispatch:", ci)
        self.assertIn("workflow_dispatch:", protected)
        self.assertIn("paths-ignore:", ci)
        self.assertIn("autorelease-state/**", ci)
        self.assertIn("paths-ignore:", protected)
        self.assertIn("autorelease-events/**", protected)
        self.assertIn("validate_completed_event_record", protected)
        self.assertIn('autorelease/(event|eol-complete)-', protected)
        self.assertIn("pr_number:", protected)
        self.assertIn("gh workflow run ci.yml", dispatcher)
        self.assertIn("gh workflow run protected-controls.yml", dispatcher)
        self.assertIn('"repos/$repository/check-runs"', dispatcher)
        self.assertIn('"repos/$repository/statuses/$head_sha"', dispatcher)
        self.assertIn("Exact-head validator passed", dispatcher)
        for workflow in (
            "autorelease-watch.yml",
            "autorelease-implement.yml",
            "autorelease-publish.yml",
        ):
            body = (root / ".github/workflows" / workflow).read_text()
            self.assertIn("./scripts/dispatch-pr-checks", body)
            self.assertNotIn("gh pr checks", body)
            self.assertIn("checks: write", body)
            self.assertIn("statuses: write", body)

        release = (root / ".github/workflows/autorelease-publish.yml").read_text()
        self.assertIn("validate-recaptured-evidence", release)
        self.assertIn("Notify actionable release failure", release)
        self.assertIn("release-run/failure.json", release)
        self.assertLess(
            release.index("Validate and merge final event record"),
            release.index("Notify owner of completed release"),
        )

    def test_protected_controls_pass_owner_authored_changes_before_bot_exemptions(self):
        # The owner short-circuit must sit after the no-protected-path exit and
        # before the automation exemptions, so it can never widen what a bot
        # identity is allowed to merge.
        root = pathlib.Path(__file__).resolve().parents[1]
        protected = (root / ".github/workflows/protected-controls.yml").read_text()
        owner_pass = protected.index("if author.lower() == reviewer:")
        self.assertLess(protected.index("No protected control path changed."), owner_pass)
        self.assertLess(owner_pass, protected.index('re.fullmatch(r"autorelease/evidence-'))

    def test_recovered_event_records_use_the_trusted_watcher_branch_prefix(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        watcher = (root / ".github/workflows/autorelease-watch.yml").read_text()
        release = (root / ".github/workflows/autorelease-publish.yml").read_text()
        protected = (root / ".github/workflows/protected-controls.yml").read_text()
        start = watcher.index("- name: Recover the event record of a published release")
        recovery = watcher[start:watcher.index("- name: Prepare deterministic no-change evidence")]
        # The exemption only trusts this prefix from this workflow on these events.
        self.assertIn('branch="autorelease/eol-complete-${{ github.run_id }}"', recovery)
        self.assertIn("--require-protected-controls", recovery)
        self.assertIn('".github/workflows/autorelease-watch.yml"', protected)
        self.assertIn('{"schedule", "workflow_dispatch"}', protected)
        self.assertIn("schedule:", watcher)
        self.assertIn("workflow_dispatch:", watcher)
        # Assets and checksums of a hand-made release prove each other and nothing else.
        self.assertIn('gh release verify "$version" --repo "${{ github.repository }}" --format json', recovery)
        self.assertIn('git merge-base --is-ancestor "$release_commit" origin/main', recovery)
        # A failing repair yields to the other paths, is raised only after them, and
        # says so even when one of those paths failed too.
        self.assertIn("continue-on-error: true", recovery)
        self.assertLess(start, watcher.index("- name: Dispatch implementation or no-edit release"))
        self.assertLess(
            watcher.index("- name: Dispatch implementation or no-edit release"),
            watcher.index("if: ${{ !cancelled() && steps.recover.outcome == 'failure' }}"),
        )
        # The recovery overlay is routed by the same table as the dispatch, so an
        # unrouted repair fails loudly instead of skipping the step silently.
        self.assertIn("route-watch-action --record-action-key", recovery)
        self.assertIn("recoveryRoute", recovery)
        # Later steps keep writing this checkout, and the EOL path files on this very
        # branch name in the same run, so recovery owns neither past its own step.
        self.assertIn('git worktree add -B "$branch" "$worktree" HEAD', recovery)
        self.assertNotIn("git checkout", recovery)
        self.assertIn('git push origin --delete "$branch"', recovery)
        self.assertIn('git worktree remove --force "$worktree"', recovery)
        self.assertIn('exit "$status"', recovery)
        # Every gh call here names the repository: without it gh also deletes the local
        # branch, which git refuses while the recovery worktree still holds it. Line
        # continuations are folded first, or a call could hide --repo's absence by
        # wrapping its arguments onto the next line.
        folded = re.sub(r"\\\n[^\S\n]*", " ", recovery)
        calls = re.findall(r"^\s*gh\s+pr\s+(?:merge|close)\s.*$", folded, re.MULTILINE)
        self.assertEqual(2, len(calls))
        for call in calls:
            self.assertIn('--repo "${{ github.repository }}"', call)
        # A published release downgrades the publish alarm from critical to warning.
        self.assertIn("release-transaction-state-${{ github.run_id }}", release)
        self.assertIn("jq -r .released release-state/transaction-state.json", release)

    def test_the_jq_built_recovery_record_validates_as_a_completed_event(self):
        # The recovery record is assembled by four `jq -n` programs in the watcher and
        # was only ever judged by the protected-controls evaluator at merge time, so a
        # field drifting out of one of those programs surfaced as a wedged PR on a live
        # run rather than as a failing test. The programs are asserted to still be the
        # workflow's own text and then run for real, so this test moves with the
        # workflow or fails.
        root = pathlib.Path(__file__).resolve().parents[1]
        watcher = (root / ".github/workflows/autorelease-watch.yml").read_text()
        recovery = watcher[
            watcher.index("- name: Recover the event record of a published release"):
            watcher.index("- name: Prepare deterministic no-change evidence")
        ]
        record_program = (
            '{schemaVersion:1,actionKey:$actionKey,classification:$classification,'
            'state:"release_requested",history:[],phpBinCommit:$commit,'
            'evidenceManifestDigest:$evidenceManifestDigest,recoveredByRunId:$runId}'
        )
        released_program = (
            '[{kind:"published_immutable_release",version:$version,phpBinCommit:$commit,'
            'attestationDigest:$attestation,assetDigests:'
            '{("php-"+$version+"-cli-macos-aarch64.tar.gz"):$archive,"SHA256SUMS":$checksums}}]'
        )
        verified_program = '[{kind:"public_release_bytes_reverified",version:$version,modes:["public_download"]}]'
        complete_program = '[{kind:"record_recovered_by_watcher",runId:$runId}]'
        for program in (record_program, released_program, verified_program, complete_program):
            self.assertIn(program, recovery)

        def jq(program, **args):
            argv = ["jq", "-n"]
            for name, value in args.items():
                argv += ["--arg", name, value]
            return subprocess.run(argv + [program], capture_output=True, text=True, check=True).stdout

        version = "8.5.9"
        commit = "c" * 40
        with tempfile.TemporaryDirectory() as temporary:
            work = pathlib.Path(temporary)
            event = work / "recovered-event.json"
            evidence = work / "recovery-evidence.json"
            output = work / "recovered-event.next"
            event.write_text(
                jq(
                    record_program,
                    actionKey=f"new_patch:{version}",
                    classification="new_patch",
                    commit=commit,
                    runId="4242",
                    evidenceManifestDigest="sha256:" + "d" * 64,
                )
            )
            transitions = (
                ("released", lambda: jq(
                    released_program,
                    version=version,
                    commit=commit,
                    archive="sha256:" + "a" * 64,
                    checksums="sha256:" + "b" * 64,
                    attestation="sha256:" + "e" * 64,
                )),
                ("public_install_verified", lambda: jq(verified_program, version=version)),
                ("complete", lambda: jq(complete_program, runId="4242")),
            )
            for target, build in transitions:
                self.assertIn(f"--target {target}", recovery)
                evidence.write_text(build())
                subprocess.run(
                    [str(root / "scripts/autorelease-event"),
                     "--event", str(event), "--target", target,
                     "--evidence", str(evidence), "--output", str(output)],
                    capture_output=True, check=True,
                )
                output.replace(event)
            validate_completed_event_record(json.loads(event.read_text()))

    def test_assert_admission_checks(self):
        script = str(pathlib.Path(__file__).resolve().parents[1] / "scripts/assert-admission-checks")
        ok = [{"name": "Script checks", "bucket": "pass"},
              {"name": "Protected controls", "bucket": "pass"}]
        missing_protected = [{"name": "Script checks", "bucket": "pass"}]
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary, "checks.json")
            path.write_text(json.dumps(ok))
            subprocess.run([script, "--checks", str(path),
                            "--require-protected-controls"], check=True)
            path.write_text(json.dumps(missing_protected))
            subprocess.run([script, "--checks", str(path)], check=True)
            result = subprocess.run([script, "--checks", str(path),
                                     "--require-protected-controls"], capture_output=True)
            self.assertNotEqual(result.returncode, 0)

            # mise-php merge gates only ever assert this renamed bucket.
            path.write_text(json.dumps([{"name": "Plugin contract", "bucket": "pass"}]))
            subprocess.run([script, "--checks", str(path),
                            "--check-name", "Plugin contract"], check=True)
            path.write_text(json.dumps(missing_protected))
            result = subprocess.run([script, "--checks", str(path),
                                     "--check-name", "Plugin contract"], capture_output=True)
            self.assertNotEqual(result.returncode, 0)

    def test_malformed_contract_shapes_fail_closed(self):
        contract = self._contract()
        contract["allowedAuthority"] = [[]]
        with self.assertRaisesRegex(ControlError, "allowedAuthority"):
            validate_completion_assessment({}, contract)
        contract = self._contract()
        contract["completionCriteria"] = ["not-an-object"]
        with self.assertRaisesRegex(ControlError, "objects"):
            validate_completion_assessment({}, contract)

    def test_archive_absolute_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = pathlib.Path(temporary) / "php-8.5.9-cli-macos-aarch64.tar.gz"
            with tarfile.open(archive, "w:gz") as handle:
                info = tarfile.TarInfo("/bin/php")
                body = b"php"
                info.size = len(body)
                handle.addfile(info, io.BytesIO(body))
            with self.assertRaisesRegex(ControlError, "unsafe archive path"):
                validate_archive(archive, "8.5.9")

    def test_seal_and_exact_merge_gate_run_in_routine_suite(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = pathlib.Path(temporary) / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Fixture"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "fixture@invalid"], cwd=repo, check=True)
            (repo / "allowed.txt").write_text("before\n")
            subprocess.run(["git", "add", "allowed.txt"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "baseline"], cwd=repo, check=True)
            base = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=repo, check=True, text=True, stdout=subprocess.PIPE
            ).stdout.strip()
            (repo / "allowed.txt").write_text("after\n")
            contract = self._contract()
            digests = {
                "shared": "sha256:" + "a" * 64,
                "phaseTemplate": "sha256:" + "b" * 64,
                "eventContract": sha256_bytes(canonical_json(contract)),
            }
            plan = {
                "actionKey": contract["actionKey"],
                "agentContract": {"instructionDigests": digests},
                "allowedPaths": {"php-bin": ["allowed.txt"]},
            }
            sealed = pathlib.Path(temporary) / "sealed"
            manifest = seal_patch(
                repo,
                base,
                plan,
                self._assessment(contract, digests),
                contract,
                sealed,
            )
            subprocess.run(["git", "add", "allowed.txt"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "validated"], cwd=repo, check=True)
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=repo, check=True, text=True, stdout=subprocess.PIPE
            ).stdout.strip()
            admitted = verify_merge(repo, head, manifest, {"Script checks": "success"}, {}, {})
            self.assertEqual(head, admitted["headSha"])
            with self.assertRaisesRegex(ControlError, "exact commit SHA"):
                seal_patch(repo, "--help", plan, self._assessment(contract, digests), contract, sealed)
            with self.assertRaisesRegex(ControlError, "exact commit SHA"):
                verify_merge(repo, "--help", manifest, {"Script checks": "success"}, {}, {})


if __name__ == "__main__":
    unittest.main()
