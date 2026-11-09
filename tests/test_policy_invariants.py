import json
import pathlib
import shutil
import tempfile
import unittest

from autorelease._admission import REVIEWED_POLICY_TARGETS, validate_support_policy
from autorelease._validation import RELEASE_PLATFORMS, ControlError, sha256_file


ROOT = pathlib.Path(__file__).resolve().parents[1]
INVARIANTS = "autorelease/policy-invariants.json"


class PolicyInvariantTests(unittest.TestCase):
    """The reviewed invariants name exactly the platforms every release publishes."""

    def policy_root(self, invariants: dict) -> pathlib.Path:
        """Copy the reviewed policy pair, replace the invariants, and rebind the policy digest."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = pathlib.Path(directory.name)
        (root / "autorelease").mkdir()
        (root / INVARIANTS).write_text(json.dumps(invariants))
        policy = json.loads((ROOT / "support-policy.json").read_text())
        policy["policyInvariantsDigest"] = sha256_file(root / INVARIANTS)
        (root / "support-policy.json").write_text(json.dumps(policy))
        return root

    def test_reviewed_invariants_list_every_release_platform(self):
        invariants = json.loads((ROOT / INVARIANTS).read_text())
        self.assertEqual(REVIEWED_POLICY_TARGETS, invariants["targets"])
        spelled = [
            f"{target['os'].lower()}-{'aarch64' if target['architecture'] == 'arm64' else target['architecture']}"
            for target in invariants["targets"]
        ]
        self.assertEqual(list(RELEASE_PLATFORMS), spelled)
        result = validate_support_policy(ROOT)
        self.assertEqual(sha256_file(ROOT / INVARIANTS), result["invariantsDigest"])

    def test_schema_matches_admission(self):
        schema = json.loads((ROOT / "schemas/policy-invariants.schema.json").read_text())
        invariants = json.loads((ROOT / INVARIANTS).read_text())
        self.assertEqual(set(schema["required"]), set(schema["properties"]))
        self.assertEqual(set(invariants), set(schema["required"]))
        self.assertEqual(REVIEWED_POLICY_TARGETS, schema["properties"]["targets"]["const"])
        self.assertEqual(invariants["schemaVersion"], schema["properties"]["schemaVersion"]["const"])

    def test_admission_rejects_any_other_target_set(self):
        reviewed = json.loads((ROOT / INVARIANTS).read_text())
        legacy = {key: value for key, value in reviewed.items() if key != "targets"}
        legacy.update(
            schemaVersion=1,
            target={"os": "macOS", "minimumVersion": "26.0", "architecture": "arm64", "sapi": "cli"},
        )
        cases = {
            "the retired single macOS target": (legacy, "unknown or missing fields"),
            "version 1 with the new targets": ({**reviewed, "schemaVersion": 1}, "unsupported policy invariants version"),
            "a dropped platform": ({**reviewed, "targets": reviewed["targets"][:1]}, "reviewed target invariant changed"),
            "reordered platforms": ({**reviewed, "targets": reviewed["targets"][::-1]}, "reviewed target invariant changed"),
            "a newer glibc baseline": (
                {**reviewed, "targets": [reviewed["targets"][0], {**reviewed["targets"][1], "minimumGlibcVersion": "2.28"}, reviewed["targets"][2]]},
                "reviewed target invariant changed",
            ),
        }
        for name, (invariants, message) in cases.items():
            with self.subTest(name):
                with self.assertRaisesRegex(ControlError, message):
                    validate_support_policy(self.policy_root(invariants))

    def test_policy_not_rebound_to_new_invariants_is_rejected(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = pathlib.Path(directory.name)
        (root / "autorelease").mkdir()
        shutil.copy(ROOT / INVARIANTS, root / INVARIANTS)
        policy = json.loads((ROOT / "support-policy.json").read_text())
        policy["policyInvariantsDigest"] = "sha256:" + "0" * 64
        (root / "support-policy.json").write_text(json.dumps(policy))
        with self.assertRaisesRegex(ControlError, "not bound to reviewed invariants"):
            validate_support_policy(root)


if __name__ == "__main__":
    unittest.main()
