import json
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

from autorelease.control import (
    ROOT,
    ControlError,
    SourceFormatError,
    apply_lifecycle_plan,
    canonical_json,
    classify_evidence,
    parse_supported_versions,
    render_support_policy,
    route_watch_action,
    seal_patch,
    sha256_bytes,
    sha256_file,
    validate_plan,
)
from autorelease.verify import FIXTURE_HEADS, FIXTURE_POLICY_DIGEST, fixture_capture, support_page


MAINTAINED = {"8.4": ("stable", "31 Dec 2028"), "8.5": ("stable", "31 Dec 2029")}
PUBLISHED = [
    {"tag_name": "8.5.9", "draft": False, "prerelease": False},
    {"tag_name": "8.4.20", "draft": False, "prerelease": False},
]
PRECONDITIONS = {**FIXTURE_HEADS, "supportPolicyDigest": FIXTURE_POLICY_DIGEST}
# The live page wraps the support table in its calendar and colour key.
PAGE_SHELL = (
    '<h3>Currently Supported Versions</h3>\n{table}<svg><g class="branch-labels"><g class="eol">'
    '<text>8.1</text></g></g></svg>\n<h4>Key</h4>\n<table class="standard">\n'
    '<tr class="stable"><td>Active support</td><td>Maintained.</td></tr>\n'
    '<tr class="eol"><td>End of life</td><td>Unsupported.</td></tr>\n</table>\n'
)


def page(rows=None) -> bytes:
    return PAGE_SHELL.format(table=support_page(rows or MAINTAINED).decode()).encode()


class ClassifierTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = pathlib.Path(self._tmp.name)
        self.count = 0

    def tearDown(self):
        self._tmp.cleanup()

    def capture(self, *, feeds=None, aggregate="8.5.9", rows=None, releases=PUBLISHED, rebuild="",
                incomplete=None, raw_page=None):
        self.count += 1
        return fixture_capture(
            self.tmp / f"run-{self.count}",
            branch_feeds=feeds or {"8.4": "8.4.20", "8.5": "8.5.9"},
            aggregate=aggregate,
            page=raw_page if raw_page is not None else page(rows),
            releases=releases,
            rebuild=rebuild,
            incomplete=incomplete,
        )

    def classify(self, manifest, events=(), branches=("8.4", "8.5")):
        return classify_evidence(manifest, PRECONDITIONS, list(events), list(branches))

    def admit(self, plan, manifest, pending=None, completed=()):
        return validate_plan(plan, manifest, FIXTURE_HEADS, FIXTURE_POLICY_DIGEST, set(completed), pending)

    # The supported-versions reader ----------------------------------------------------

    def test_reader_parses_the_reviewed_table_and_ignores_the_key(self):
        body = page({**MAINTAINED, "8.2": ("eol", "31 Dec 2026"), "8.3": ("security", "31 Dec 2027")})
        rows = parse_supported_versions(body)
        self.assertEqual(["8.4", "8.5", "8.2", "8.3"], list(rows))
        self.assertEqual("eol", rows["8.2"].state)
        self.assertEqual("2026-12-31", rows["8.2"].security_until.isoformat())
        self.assertIn(rows["8.2"].fragment.encode(), body)
        self.assertTrue(rows["8.2"].fragment.startswith('<tr class="eol">'))
        self.assertTrue(rows["8.2"].fragment.endswith("<td>31 Dec 2026</td>"))

    def test_reader_parses_retained_live_captures(self):
        # A real capture shape: header cells with colspan, whitespace-heavy rows, and
        # projected relative-age cells, exactly as the watcher stores them.
        row = (
            '<tr class="security">\n\t\t\t\t\t<td>\n\t\t\t\t\t\t<a href="/downloads.php?version=8.2">8.2</a>\n'
            "\t\t\t\t\t</td>\n\t\t\t\t\t<td>8 Dec 2022</td>\n\t\t\t\t\t<td class=\"collapse-phone\"></td>\n"
            "\t\t\t\t\t<td>31 Dec 2024</td>\n\t\t\t\t\t<td class=\"collapse-phone\"></td>\n"
            "\t\t\t\t\t<td>31 Dec 2026</td>\n\t\t\t\t\t<td class=\"collapse-phone\"></td>\n"
            "\t\t\t\t\t<td>\n\t\t\t\t\t\t<a href=\"https://www.php.net/manual/migration82.php\">Guide</a>\n"
            "\t\t\t\t\t</td>\n\t\t\t\t</tr>\n"
        )
        body = (
            '<table class="standard">\n\t<thead>\n\t\t<tr>\n\t\t\t<th>Branch</th>\n'
            '\t\t\t<th colspan="2">Initial Release</th>\n\t\t\t<th colspan="2">Active Support Until</th>\n'
            '\t\t\t<th colspan="2">Security Support Until</th>\n\t\t\t<th colspan="2">Notes</th>\n'
            "\t\t</tr>\n\t</thead>\n\t<tbody>\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t" + row + "\t\t\t\t\t\t</tbody>\n</table>\n"
        ).encode()
        rows = parse_supported_versions(body)
        self.assertEqual({"8.2"}, set(rows))
        self.assertEqual("security", rows["8.2"].state)

    def test_reader_fails_closed_on_any_other_shape(self):
        good = page().decode()
        broken = {
            "no table": "<main>Supported versions moved.</main>",
            "renamed header": good.replace("<th>Branch</th>", "<th>Version</th>"),
            "unknown state": good.replace('<tr class="stable">\n<td>\n<a href="/downloads.php?version=8.4"',
                                          '<tr class="preview">\n<td>\n<a href="/downloads.php?version=8.4"'),
            "stray content": good.replace("</tbody>", "<p>Note</p>\n</tbody>"),
            "duplicate branch": good.replace("version=8.5\">8.5", "version=8.4\">8.4"),
            "mismatched link": good.replace("version=8.5\">8.5", "version=8.5\">8.6"),
            "missing date": good.replace("<td>31 Dec 2029</td>", "<td>TBD</td>"),
            "empty body": re.sub(r"<tbody>.*</tbody>", "<tbody>\n</tbody>", good, flags=re.DOTALL),
            "two support tables": good.replace("<h4>Key</h4>", support_page(MAINTAINED).decode()),
        }
        for name, body in broken.items():
            with self.assertRaises(SourceFormatError, msg=name):
                parse_supported_versions(body.encode())

    # Priority rules ------------------------------------------------------------------

    def test_same_capture_always_yields_the_same_plan_bytes(self):
        first = self.classify(self.capture(feeds={"8.4": "8.4.21", "8.5": "8.5.9"}))
        second = self.classify(self.capture(feeds={"8.4": "8.4.21", "8.5": "8.5.9"}))
        self.assertEqual(canonical_json(first), canonical_json(second))

    def test_quiet_evidence_is_no_change_keyed_on_the_embedded_manifest_digest(self):
        manifest = self.capture()
        plan = self.classify(manifest)
        embedded = json.loads(manifest.read_text())["manifestDigest"]
        self.assertEqual("no_change:" + embedded.removeprefix("sha256:")[:16], plan["actionKey"])
        # The evidence digest is the manifest file's own hash, never the embedded field.
        self.assertEqual(sha256_file(manifest), plan["evidence"][0]["digest"])
        self.assertNotEqual(embedded, plan["evidence"][0]["digest"])
        self.admit(plan, manifest)

    def test_new_patch_cites_only_its_own_branch_feed_oldest_branch_first(self):
        manifest = self.capture(feeds={"8.4": "8.4.21", "8.5": "8.5.10"}, aggregate="8.5.10")
        plan = self.classify(manifest)
        self.assertEqual("new_patch:8.4.21", plan["actionKey"])
        self.assertEqual({"version": "8.4.21", "sourceIdentifier": "php_release_feed_8.4"}, plan["releaseIntent"])
        self.assertEqual(
            [("php_release_feed_8.4", "/version")],
            [(item["captureId"], item["locator"]["value"]) for item in plan["evidence"]],
        )
        body = (manifest.parent / "raw/php_release_feed_8.4.body").read_bytes()
        self.assertEqual(sha256_bytes(body), plan["evidence"][0]["digest"])
        self.assertFalse(plan["editsRequired"])
        self.admit(plan, manifest)
        self.assertEqual("dispatch_publish", route_watch_action(plan)["route"])
        # Once 8.4.21 ships, the next branch's patch is next.
        shipped = [*PUBLISHED, {"tag_name": "8.4.21"}]
        self.assertEqual(
            "new_patch:8.5.10",
            self.classify(self.capture(feeds={"8.4": "8.4.21", "8.5": "8.5.10"}, aggregate="8.5.10", releases=shipped))["actionKey"],
        )

    def test_a_stale_or_superseded_feed_never_proposes_an_intermediate_patch(self):
        # The branch feed lags what already shipped: a stale edge snapshot, not news.
        stale = self.capture(feeds={"8.4": "8.4.19", "8.5": "8.5.9"})
        self.assertEqual("no_change", self.classify(stale)["action"])
        # The aggregate feed already names a later patch on the branch: wait for the
        # branch's own feed rather than publish 8.5.10 after its successor.
        superseded = self.capture(feeds={"8.4": "8.4.20", "8.5": "8.5.10"}, aggregate="8.5.11")
        self.assertEqual("no_change", self.classify(superseded)["action"])
        # A completed record counts as shipped even when the release fell off the capture.
        recorded = self.capture(feeds={"8.4": "8.4.21", "8.5": "8.5.9"})
        self.assertEqual(
            "no_change",
            self.classify(recorded, events=[{"actionKey": "new_patch:8.4.21", "state": "complete"}])["action"],
        )

    def test_a_due_patch_outranks_a_due_rebuild(self):
        manifest = self.capture(feeds={"8.4": "8.4.21", "8.5": "8.5.9"}, rebuild="recipe_rebuild:8.5.9:1")
        plan = self.classify(manifest)
        self.assertEqual("new_patch:8.4.21", plan["actionKey"])
        self.admit(plan, manifest, pending="recipe_rebuild:8.5.9:1")
        rebuild = self.classify(self.capture(rebuild="recipe_rebuild:8.5.9:1"))
        self.assertEqual("recipe_rebuild:8.5.9:1", rebuild["actionKey"])
        self.assertEqual({"version": "8.5.9-1", "sourceIdentifier": "php_bin_releases"}, rebuild["releaseIntent"])
        self.assertEqual("/0/tag_name", rebuild["evidence"][0]["locator"]["value"])

    def test_a_new_branch_needs_its_first_official_release(self):
        rows = {**MAINTAINED, "8.6": ("stable", "31 Dec 2030")}
        # Listed but not yet named by the release feed: nothing to publish yet.
        self.assertEqual("no_change", self.classify(self.capture(rows=rows))["action"])
        manifest = self.capture(rows=rows, aggregate="8.6.0")
        plan = self.classify(manifest)
        self.assertEqual("new_branch:8.6", plan["actionKey"])
        self.assertTrue(plan["editsRequired"])
        self.assertEqual("lifecycle", plan["risk"])
        self.assertEqual(["php-bin", "mise-php"], plan["repositories"])
        self.assertEqual(["expected-modules/8.6.txt", "support-policy.json"], plan["allowedPaths"]["php-bin"])
        self.assertEqual({"version": "8.6.0", "sourceIdentifier": "php_release_feed"}, plan["releaseIntent"])
        self.assertEqual(["php_release_feed", "php_supported_versions"], [item["captureId"] for item in plan["evidence"]])
        self.admit(plan, manifest)
        decision = route_watch_action(plan)
        self.assertEqual(("dispatch_implementation", "lifecycle"), (decision["route"], decision["notify"]))

    def test_a_maintained_branch_marked_end_of_life_is_retired_on_its_date(self):
        manifest = self.capture(rows={**MAINTAINED, "8.4": ("eol", "31 Dec 2026")})
        plan = self.classify(manifest)
        self.assertEqual("branch_eol:8.4:2026-12-31", plan["actionKey"])
        self.assertEqual(["support-policy.json"], plan["allowedPaths"]["php-bin"])
        self.assertIsNone(plan["releaseIntent"])
        self.assertIn('<tr class="eol">', plan["evidence"][0]["locator"]["value"])
        self.admit(plan, manifest)
        # A new branch is handled before a retirement.
        both = self.classify(
            self.capture(rows={"8.4": ("eol", "31 Dec 2026"), "8.5": MAINTAINED["8.5"], "8.6": ("stable", "31 Dec 2030")},
                         aggregate="8.6.0")
        )
        self.assertEqual("new_branch:8.6", both["actionKey"])

    def test_a_lifecycle_contradiction_needs_a_human(self):
        for rows in (
            {"8.5": MAINTAINED["8.5"]},  # a maintained branch lost its row
            {**MAINTAINED, "8.3": ("security", "31 Dec 2027")},  # an older supported branch
            {"8.4": ("future", "31 Dec 2028"), "8.5": MAINTAINED["8.5"]},
        ):
            manifest = self.capture(rows=rows)
            plan = self.classify(manifest)
            self.assertEqual("needs_human", plan["action"], rows)
            self.assertTrue(plan["actionKey"].startswith("policy_failure:"))
            self.assertTrue(plan["notification"]["humanActionRequired"])
            self.admit(plan, manifest)
            self.assertEqual("notify_blocked", route_watch_action(plan)["route"])
            # The same contradiction on a later capture refreshes the same owner issue,
            # although the manifest file (and its own digest) differs.
            later = self.capture(rows=rows, releases=[*PUBLISHED, {"tag_name": "8.4.20-1"}])
            self.assertNotEqual(sha256_file(manifest), sha256_file(later))
            self.assertEqual(plan["actionKey"], self.classify(later)["actionKey"])

    def test_an_unrecognised_lifecycle_page_blocks_instead_of_guessing(self):
        first = self.capture(raw_page=b"<main>We moved the table.</main>")
        plan = self.classify(first)
        self.assertEqual("blocked", plan["action"])
        self.assertTrue(plan["actionKey"].startswith("source_unhealthy:"))
        self.assertIn("reviewed shape", plan["summary"])
        self.admit(plan, first)
        # The same broken page keys the same deduplicated issue on every run.
        again = self.classify(self.capture(raw_page=b"<main>We moved the table.</main>"))
        self.assertEqual(plan["actionKey"], again["actionKey"])
        # A feed that names another branch is just as unreadable.
        wrong = self.capture(feeds={"8.4": "8.5.9", "8.5": "8.5.9"})
        self.assertEqual("blocked", self.classify(wrong)["action"])
        # So is an aggregate feed whose major entry lost its stable version: a new
        # branch it would prove must not read as a quiet day.
        rows = {**MAINTAINED, "8.6": ("stable", "31 Dec 2030")}
        shapeless = self.capture(rows=rows, aggregate="8.6.0")
        body = shapeless.parent / "raw/php_release_feed.body"
        body.write_bytes(canonical_json({"8": {"announcement": True}}))
        document = json.loads(shapeless.read_text())
        for item in document["captures"]:
            if item["captureId"] == "php_release_feed":
                item["digest"] = sha256_bytes(body.read_bytes())
        shapeless.write_bytes(canonical_json(document))
        self.assertEqual("blocked", self.classify(shapeless)["action"])

    def test_unhealthy_or_failed_capture_blocks_everything(self):
        manifest = self.capture(feeds={"8.4": "8.4.21", "8.5": "8.5.9"})
        document = json.loads(manifest.read_text())
        document["captures"][1]["status"] = 0
        manifest.write_bytes(canonical_json(document))
        plan = self.classify(manifest)
        self.assertEqual("blocked", plan["action"])
        self.assertTrue(plan["actionKey"].startswith("source_unhealthy:"))
        self.assertEqual("/captures/1/status", plan["evidence"][0]["locator"]["value"])
        self.admit(plan, manifest)
        decision_path = manifest.parent.parent / "watch-decision.json"
        decision = json.loads(decision_path.read_text())
        decision_path.write_bytes(canonical_json({**decision, "trigger": "health_failed"}))
        self.assertTrue(self.classify(manifest)["actionKey"].startswith("health_failed:"))

    def test_incomplete_records_resume_under_their_own_key(self):
        feeds = {"8.4": "8.4.20", "8.5": "8.5.9", "8.6": "8.6.1"}
        branches = ("8.4", "8.5", "8.6")
        rows = {**MAINTAINED, "8.6": ("stable", "31 Dec 2030")}
        manifest = self.capture(feeds=feeds, rows=rows, aggregate="8.6.1", incomplete=["new_branch:8.6"])
        plan = self.classify(manifest, [{"actionKey": "new_branch:8.6", "state": "php_bin_ready"}], branches)
        self.assertEqual(("new_branch", "new_branch:8.6", False), (plan["action"], plan["actionKey"], plan["editsRequired"]))
        self.assertEqual({"version": "8.6.1", "sourceIdentifier": "php_release_feed_8.6"}, plan["releaseIntent"])
        self.admit(plan, manifest)
        self.assertEqual("dispatch_publish", route_watch_action(plan)["route"])

        eol_key = "branch_eol:8.4:2026-12-31"
        manifest = self.capture(rows={**MAINTAINED, "8.4": ("eol", "31 Dec 2026")}, incomplete=[eol_key])
        plan = self.classify(manifest, [{"actionKey": eol_key, "state": "php_bin_ready"}], ("8.5",))
        self.assertEqual((eol_key, False), (plan["actionKey"], plan["editsRequired"]))
        self.admit(plan, manifest)
        self.assertEqual("complete_branch_eol", route_watch_action(plan)["route"])

        # A record stopped by an operator, or one a later patch supersedes, needs a human.
        manifest = self.capture(incomplete=["new_patch:8.5.8"])
        stopped = self.classify(manifest, [{"actionKey": "new_patch:8.5.8", "state": "blocked"}])
        self.assertEqual(("needs_human", "new_patch:8.5.8"), (stopped["action"], stopped["actionKey"]))
        self.admit(stopped, manifest)
        superseded = self.classify(manifest, [{"actionKey": "new_patch:8.5.8", "state": "released"}])
        self.assertEqual("needs_human", superseded["action"])
        self.assertIn("8.5.9 supersedes it", superseded["summary"])

    def test_a_due_patch_goes_before_lifecycle_work(self):
        due = {"8.4": "8.4.21", "8.5": "8.5.9"}
        for rows, aggregate in (
            ({**MAINTAINED, "8.6": ("stable", "31 Dec 2030")}, "8.6.0"),  # a new branch
            ({**MAINTAINED, "8.4": ("eol", "31 Dec 2026")}, "8.5.9"),  # a retirement
            ({"8.5": MAINTAINED["8.5"]}, "8.5.9"),  # a lifecycle contradiction
        ):
            manifest = self.capture(feeds=due, rows=rows, aggregate=aggregate)
            plan = self.classify(manifest)
            self.assertEqual("new_patch:8.4.21", plan["actionKey"], rows)
            self.admit(plan, manifest)
        # Patches never read the lifecycle page, so an unreadable one blocks only a run
        # with no patch due.
        broken = b"<main>We moved the table.</main>"
        manifest = self.capture(feeds=due, raw_page=broken)
        self.assertEqual("new_patch:8.4.21", self.classify(manifest)["actionKey"])
        self.assertEqual("blocked", self.classify(self.capture(raw_page=broken))["action"])

    def test_a_lifecycle_record_waiting_for_readiness_lets_a_patch_go_first(self):
        feeds = {"8.4": "8.4.21", "8.5": "8.5.9", "8.6": "8.6.0"}
        branches = ("8.4", "8.5", "8.6")
        rows = {**MAINTAINED, "8.6": ("stable", "31 Dec 2030")}
        waiting = [{"actionKey": "new_branch:8.6", "state": "php_bin_ready"}]
        manifest = self.capture(feeds=feeds, rows=rows, aggregate="8.6.0", incomplete=["new_branch:8.6"])
        plan = self.classify(manifest, waiting, branches)
        self.assertEqual("new_patch:8.4.21", plan["actionKey"])
        self.admit(plan, manifest)
        # The waiting branch's own first release is never a plain patch, so with no
        # other patch due the record resumes.
        idle = self.capture(feeds={**feeds, "8.4": "8.4.20"}, rows=rows, aggregate="8.6.0", incomplete=["new_branch:8.6"])
        self.assertEqual("new_branch:8.6", self.classify(idle, waiting, branches)["actionKey"])
        # Another branch's unreadable feed does not stop the record's own resume.
        unreadable = self.capture(feeds={**feeds, "8.4": "8.5.9"}, rows=rows, aggregate="8.6.0", incomplete=["new_branch:8.6"])
        self.assertEqual("new_branch:8.6", self.classify(unreadable, waiting, branches)["actionKey"])
        # A record past readiness, or one beside another incomplete record, still goes first.
        started = [{"actionKey": "new_branch:8.6", "state": "release_requested"}]
        self.assertEqual("new_branch:8.6", self.classify(manifest, started, branches)["actionKey"])
        both = self.capture(feeds=feeds, rows=rows, aggregate="8.6.0", incomplete=["new_branch:8.6", "new_patch:8.5.9"])
        self.assertEqual(
            "new_branch:8.6",
            self.classify(both, [*waiting, {"actionKey": "new_patch:8.5.9", "state": "release_requested"}],
                          branches)["actionKey"],
        )
        # A retirement waiting for mise-php readiness yields the same way.
        eol_key = "branch_eol:8.3:2025-12-31"
        retired = self.capture(feeds={"8.4": "8.4.21", "8.5": "8.5.9"}, incomplete=[eol_key])
        plan = self.classify(retired, [{"actionKey": eol_key, "state": "php_bin_ready"}])
        self.assertEqual("new_patch:8.4.21", plan["actionKey"])

    def test_a_maintained_branch_that_never_shipped_is_never_a_plain_patch(self):
        # The policy maintains 8.6 but its new_branch record is missing: its first
        # release must not skip the mise-php readiness gate as a plain patch.
        feeds = {"8.4": "8.4.20", "8.5": "8.5.9", "8.6": "8.6.0"}
        rows = {**MAINTAINED, "8.6": ("stable", "31 Dec 2030")}
        manifest = self.capture(feeds=feeds, rows=rows, aggregate="8.6.0")
        plan = self.classify(manifest, branches=("8.4", "8.5", "8.6"))
        self.assertEqual(("needs_human", "new_branch:8.6"), (plan["action"], plan["actionKey"]))
        self.assertEqual("php_release_feed_8.6", plan["evidence"][0]["captureId"])
        self.admit(plan, manifest)
        self.assertEqual("notify_blocked", route_watch_action(plan)["route"])
        # A completed new_branch record counts as shipped even once its release fell
        # off the captured page.
        shipped = self.classify(
            self.capture(feeds={**feeds, "8.6": "8.6.1"}, rows=rows, aggregate="8.6.1"),
            [{"actionKey": "new_branch:8.6", "state": "complete"}],
            ("8.4", "8.5", "8.6"),
        )
        self.assertEqual("new_patch:8.6.1", shipped["actionKey"])
        # Admission rejects the plain patch on its own, whatever proposed it.
        patch = {
            **plan,
            "action": "new_patch",
            "actionKey": "new_patch:8.6.0",
            "releaseIntent": {"version": "8.6.0", "sourceIdentifier": "php_release_feed_8.6"},
            "risk": "routine",
            "notification": {**plan["notification"], "humanActionRequired": False, "suggestedSeverity": "info"},
        }
        with self.assertRaisesRegex(ControlError, "first PHP 8.6 release"):
            self.admit(patch, manifest)
        self.admit(patch, manifest, completed=["new_branch:8.6"])

    def test_inconsistent_watcher_inputs_fail_the_job(self):
        manifest = self.capture()
        with self.assertRaisesRegex(ControlError, "preconditions"):
            classify_evidence(manifest, {}, [], ["8.4", "8.5"])
        with self.assertRaisesRegex(ControlError, "no event record"):
            self.classify(self.capture(incomplete=["new_patch:8.5.8"]))
        decision_path = manifest.parent.parent / "watch-decision.json"
        decision = json.loads(decision_path.read_text())
        decision_path.write_bytes(canonical_json({**decision, "manifestDigest": "sha256:" + "0" * 64}))
        with self.assertRaisesRegex(ControlError, "not taken on this evidence manifest"):
            self.classify(manifest)

    def test_classify_cli_writes_the_plan(self):
        # The CLI reads the accepted policy on disk, so the capture covers its branches.
        maintained = json.loads((ROOT / "support-policy.json").read_text())["maintainedBranches"]
        feeds = {branch: f"{branch}.1" for branch in maintained}
        feeds[maintained[-1]] = f"{maintained[-1]}.2"
        manifest = self.capture(
            feeds=feeds,
            aggregate=f"{maintained[-1]}.2",
            rows={branch: ("stable", "31 Dec 2029") for branch in maintained},
            releases=[{"tag_name": f"{branch}.1"} for branch in maintained],
        )
        (self.tmp / "preconditions.json").write_text(json.dumps(PRECONDITIONS))
        (self.tmp / "events").mkdir()
        result = subprocess.run(
            [str(ROOT / "scripts/classify-autorelease-evidence"),
             "--manifest", str(manifest),
             "--preconditions", str(self.tmp / "preconditions.json"),
             "--events", str(self.tmp / "events"),
             "--output", str(self.tmp / "plan.json")],
            capture_output=True, text=True,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(
            f"new_patch:{maintained[-1]}.2", json.loads((self.tmp / "plan.json").read_text())["actionKey"]
        )


class LifecycleEditTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = pathlib.Path(self._tmp.name)
        self.repo = self.tmp / "repo"
        for path in ("support-policy.json", "autorelease/policy-invariants.json", "expected-modules"):
            source = ROOT / path
            target = self.repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir():
                shutil.copytree(source, target)
            else:
                shutil.copy(source, target)
        for argv in (["init", "-q"], ["config", "user.name", "Fixture"], ["config", "user.email", "fixture@invalid"],
                     ["add", "."], ["commit", "-q", "-m", "base"]):
            subprocess.run(["git", *argv], cwd=self.repo, check=True)
        self.base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.repo, check=True, text=True,
                                   stdout=subprocess.PIPE).stdout.strip()
        self.maintained = json.loads((ROOT / "support-policy.json").read_text())["maintainedBranches"]

    def tearDown(self):
        self._tmp.cleanup()

    def lifecycle_plan(self, rows, aggregate):
        feeds = {branch: f"{branch}.1" for branch in self.maintained}
        shipped = [{"tag_name": version} for version in feeds.values()]
        manifest = fixture_capture(self.tmp / "run", branch_feeds=feeds, aggregate=aggregate, page=page(rows),
                                   releases=shipped)
        plan = classify_evidence(manifest, PRECONDITIONS, [], self.maintained)
        return plan, manifest

    def test_rendering_reproduces_the_accepted_policy_byte_for_byte(self):
        policy = json.loads((ROOT / "support-policy.json").read_text())
        self.assertEqual((ROOT / "support-policy.json").read_text(), render_support_policy(policy))

    def test_new_branch_copies_the_newest_module_list_and_seals(self):
        newest = self.maintained[-1]
        major, minor = newest.split(".")
        branch = f"{major}.{int(minor) + 1}"
        rows = {item: ("stable", "31 Dec 2029") for item in self.maintained}
        rows[branch] = ("stable", "31 Dec 2031")
        plan, manifest = self.lifecycle_plan(rows, f"{branch}.0")
        self.assertEqual(f"new_branch:{branch}", plan["actionKey"])
        changed = apply_lifecycle_plan(self.repo, plan, json.loads(manifest.read_text()))
        self.assertEqual([f"expected-modules/{branch}.txt", "support-policy.json"], changed)
        self.assertEqual(
            (ROOT / f"expected-modules/{newest}.txt").read_bytes(),
            (self.repo / f"expected-modules/{branch}.txt").read_bytes(),
        )
        policy = json.loads((self.repo / "support-policy.json").read_text())
        self.assertEqual([*self.maintained, branch], policy["maintainedBranches"])
        self.assertEqual(plan["actionKey"], policy["actionKey"])
        self.assertEqual(sorted({item["digest"] for item in plan["evidence"]}), policy["sourceEvidenceDigests"])
        self.assertEqual("2026-09-28T00:00:00Z", policy["acceptedAt"])
        sealed = seal_patch(self.repo, self.base, plan, self.tmp / "sealed")
        self.assertEqual(changed, [item["path"] for item in sealed["files"]])
        # A reviewed module list already on main is never overwritten on a retry.
        subprocess.run(["git", "checkout", "-q", "--", "support-policy.json"], cwd=self.repo, check=True)
        (self.repo / f"expected-modules/{branch}.txt").write_text("reviewed\n")
        self.assertEqual(["support-policy.json"], apply_lifecycle_plan(self.repo, plan, json.loads(manifest.read_text())))
        self.assertEqual("reviewed\n", (self.repo / f"expected-modules/{branch}.txt").read_text())

    def test_branch_eol_only_removes_the_branch_from_the_policy(self):
        oldest = self.maintained[0]
        rows = {item: ("stable", "31 Dec 2029") for item in self.maintained}
        rows[oldest] = ("eol", "31 Dec 2026")
        plan, manifest = self.lifecycle_plan(rows, f"{self.maintained[-1]}.1")
        self.assertEqual(f"branch_eol:{oldest}:2026-12-31", plan["actionKey"])
        self.assertEqual(["support-policy.json"], apply_lifecycle_plan(self.repo, plan, json.loads(manifest.read_text())))
        self.assertEqual(self.maintained[1:], json.loads((self.repo / "support-policy.json").read_text())["maintainedBranches"])
        self.assertTrue((self.repo / f"expected-modules/{oldest}.txt").is_file())
        seal_patch(self.repo, self.base, plan, self.tmp / "sealed")

    def test_only_admitted_lifecycle_plans_edit_the_repository(self):
        manifest = {"capturedAt": "2026-09-28T00:00:00Z"}
        for plan in (
            {"action": "new_patch", "editsRequired": False, "actionKey": "new_patch:8.5.9"},
            {"action": "new_branch", "editsRequired": False, "actionKey": "new_branch:8.6"},
            {"action": "new_branch", "editsRequired": True, "actionKey": f"new_branch:{self.maintained[0]}",
             "evidence": [{"digest": "sha256:" + "a" * 64}]},
            {"action": "branch_eol", "editsRequired": True, "actionKey": "branch_eol:7.4:2022-11-28",
             "evidence": [{"digest": "sha256:" + "a" * 64}]},
        ):
            with self.assertRaises(ControlError, msg=plan):
                apply_lifecycle_plan(self.repo, plan, manifest)
        self.assertEqual("", subprocess.run(["git", "status", "--porcelain"], cwd=self.repo, check=True, text=True,
                                            stdout=subprocess.PIPE).stdout)


class WorkflowWiringTests(unittest.TestCase):
    def test_watcher_classifies_and_admits_without_any_model(self):
        watcher = (ROOT / ".github/workflows/autorelease-watch.yml").read_text()
        classify = watcher.index("./scripts/classify-autorelease-evidence")
        admit = watcher.index("./scripts/admit-autorelease-plan")
        self.assertLess(classify, admit)
        self.assertIn("steps.decision.outputs.classify == 'true'", watcher)
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            text = path.read_text().lower()
            self.assertNotIn("openai", text, path.name)
            self.assertNotIn("codex", text, path.name)

    def test_only_a_named_module_mismatch_asks_for_a_module_list_fix(self):
        implement = (ROOT / ".github/workflows/autorelease-implement.yml").read_text()
        self.assertIn("grep -qE '^(Missing modules:|Unexpected modules:)' new-branch-build/module-diff.txt", implement)
        self.assertIn("rm -f new-branch-build/module-diff.txt", implement)
        self.assertIn("-s new-branch-build/module-diff.txt", implement)

    def test_new_branch_publication_verifies_the_plugin_at_the_readiness_commit(self):
        publish = (ROOT / ".github/workflows/autorelease-publish.yml").read_text()
        self.assertIn('compare/$ready_commit...$(git -C mise-php rev-parse HEAD)', publish)
        self.assertIn('git -C mise-php checkout --detach "$ready_commit"', publish)
        self.assertNotIn('.misePhpCommit release-run/mise-readiness.json)" = "$(git -C mise-php rev-parse HEAD)"', publish)

    def test_module_diff_extraction_matches_the_comparison_output(self):
        implement = (ROOT / ".github/workflows/autorelease-implement.yml").read_text()
        pattern = re.search(r"grep -E '([^']+)'", implement).group(1)
        result = subprocess.run(
            [str(ROOT / "scripts/compare-modules.sh"), str(ROOT / "tests/fixtures/modules.txt"),
             str(ROOT / "tests/fixtures/expected-missing.txt"), "exact"],
            capture_output=True, text=True,
        )
        self.assertNotEqual(0, result.returncode)
        diff = [line for line in result.stderr.splitlines() if re.match(pattern, line)]
        self.assertIn("Missing modules:", diff)
        self.assertTrue(any(line.startswith("  - ") for line in diff), diff)


if __name__ == "__main__":
    unittest.main()
