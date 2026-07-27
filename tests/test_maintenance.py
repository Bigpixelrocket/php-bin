import json
import pathlib
import tempfile
import unittest

from maintenance.control import (
    ControlError,
    mutation_allowed,
    notification_decision,
    release_transition,
    retry_decision,
    sha256_file,
    transition_event,
    validate_completion_assessment,
    watch_decision,
    path_is_protected,
)


class MaintenanceControlTests(unittest.TestCase):
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

    def test_retry_and_pause_bounds(self):
        self.assertFalse(retry_decision({"attemptCount": 2, "failureFingerprint": "x"}, "x", 2)["recallAgent"])
        self.assertFalse(mutation_allowed({"unattendedMutation": "paused"}))
        self.assertTrue(mutation_allowed({"unattendedMutation": "enabled"}))

    def test_invariants_and_durable_state_are_protected(self):
        self.assertTrue(path_is_protected("maintenance/policy-invariants.json"))
        self.assertTrue(path_is_protected("maintenance-events/new-branch.json"))
        self.assertTrue(path_is_protected("maintenance-state/last-evidence.json"))
        self.assertFalse(path_is_protected("support-policy.json"))


if __name__ == "__main__":
    unittest.main()
