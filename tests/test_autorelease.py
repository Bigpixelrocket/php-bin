import io
import json
import pathlib
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
    canonical_json,
    load_plan_evidence,
    mutation_allowed,
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
        patterns = json.loads(pathlib.Path("autorelease/protected-paths.json").read_text())["patterns"]
        codeowners = pathlib.Path(".github/CODEOWNERS").read_text()
        for pattern in patterns:
            if "*" not in pattern:
                self.assertIn(f"/{pattern} ", codeowners, pattern)

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
