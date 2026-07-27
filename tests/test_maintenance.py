import io
import json
import pathlib
import runpy
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

from maintenance.control import (
    ControlError,
    canonical_json,
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
    verify_merge,
    watch_decision,
    path_is_protected,
)


class MaintenanceControlTests(unittest.TestCase):
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

    def test_illegal_event_transition_fails_closed(self):
        with self.assertRaises(ControlError):
            transition_event({"state": "detected"}, "complete", [{"digest": "x"}])

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
        replay = notification_decision(event, {"fingerprint": first["fingerprint"]})
        self.assertEqual("none", replay["action"])

    def test_notification_transition_reuses_retained_issue_identity(self):
        issue = {"number": 10, "url": "https://example.invalid/issues/10", "state": "OPEN"}
        self.assertEqual(issue, retained_notification_issue({"issue": issue}))
        self.assertIsNone(retained_notification_issue({"issue": {}}))
        self.assertIsNone(retained_notification_issue({"issue": {"number": True}}))

        namespace = runpy.run_path(
            str(pathlib.Path(__file__).resolve().parents[1] / "scripts/notify-maintenance")
        )
        apply_github = namespace["apply_github"]
        gh = mock.Mock(return_value="")
        find_issue = mock.Mock(side_effect=AssertionError("search must not run"))
        decision = {
            "action": "comment_and_close",
            "fingerprint": "sha256:" + "a" * 64,
            "labels": ["maintenance"],
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
        self.assertTrue(path_is_protected("maintenance/policy-invariants.json"))
        self.assertTrue(path_is_protected("maintenance-events/new-branch.json"))
        self.assertTrue(path_is_protected("maintenance-state/last-evidence.json"))
        self.assertFalse(path_is_protected("support-policy.json"))

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
