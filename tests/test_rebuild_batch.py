"""One watcher run admits every due recipe rebuild as one batch.

A recipe change makes the newest version of every maintained branch rebuild-due. The
watcher selects all of them from one capture, the classifier proposes them as one
plan, admission re-derives the exact set, and each key publishes in its own concurrent
publish run bound to the same admitted commit. These tests cover the selection, the
admission of exactly that set, the unchanged single-rebuild plan, the priority of
every other action, and the recapture that lets siblings publish around each other.
"""

import contextlib
import io
import json
import pathlib
import tempfile
import unittest

from autorelease.control import (
    ControlError,
    _validate_plan_shape,
    canonical_json,
    classify_evidence,
    email_digest,
    main as control_main,
    pending_recipe_rebuild,
    pending_recipe_rebuilds,
    plan_releases,
    recipe_identity_note,
    require_plan_release,
    resumable_action_keys,
    validate_plan,
    validate_publish_recapture,
    validate_recaptured_evidence,
    watch_decision,
)
from autorelease._state import status_block, validate_status_document
from autorelease._status import status_document
from autorelease.verify import FIXTURE_HEADS, FIXTURE_POLICY_DIGEST, fixture_capture, support_page

from test_status import RUN_URL, status_run


BRANCHES = ["8.2", "8.3", "8.4", "8.5"]
ROWS = {
    "8.2": ("security", "31 Dec 2026"),
    "8.3": ("security", "31 Dec 2027"),
    "8.4": ("stable", "31 Dec 2028"),
    "8.5": ("stable", "31 Dec 2029"),
}
FEEDS = {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"}
OLD = "sha256:" + "1" * 64
NEW = "sha256:" + "2" * 64
# The 2026-11-09 cascade, newest version first: each branch's newest release and the
# revision a recipe change makes due next.
CASCADE = [
    "recipe_rebuild:8.5.12:2",
    "recipe_rebuild:8.4.27:2",
    "recipe_rebuild:8.3.36:3",
    "recipe_rebuild:8.2.35:3",
]
PRECONDITIONS = {**FIXTURE_HEADS, "supportPolicyDigest": FIXTURE_POLICY_DIGEST}


def published(tag, identity=OLD):
    return {
        "tag_name": tag,
        "draft": False,
        "prerelease": False,
        "body": "Autorelease publication.\n\n" + recipe_identity_note(identity),
    }


def releases(*extra):
    """Every branch's history before the batch: older patches and earlier revisions."""
    return [
        *extra,
        published("8.5.12-1"),
        published("8.5.12"),
        published("8.5.11-4"),
        published("8.4.27-1"),
        published("8.4.27"),
        published("8.3.36-2"),
        published("8.3.36-1"),
        published("8.3.36"),
        published("8.2.35-2"),
        published("8.2.35"),
        published("8.2.34-3"),
    ]


class BatchSelectionTests(unittest.TestCase):
    def test_every_branch_newest_version_is_selected_newest_first(self):
        identities = dict.fromkeys(BRANCHES, NEW)
        self.assertEqual(CASCADE, pending_recipe_rebuilds(releases(), identities))
        # The first key is exactly the one key a run selected before batches.
        self.assertEqual(CASCADE[0], pending_recipe_rebuild(releases(), identities))
        # Older patches never join, even though every one records an old identity.
        selected = {key.split(":")[1] for key in pending_recipe_rebuilds(releases(), identities)}
        self.assertEqual({"8.5.12", "8.4.27", "8.3.36", "8.2.35"}, selected)
        # A branch already on the current recipe drops out; the rest keep their order.
        current_84 = releases(published("8.4.27-2", NEW))
        self.assertEqual([CASCADE[0], *CASCADE[2:]], pending_recipe_rebuilds(current_84, identities))
        self.assertEqual([], pending_recipe_rebuilds(releases(), dict.fromkeys(BRANCHES, OLD)))

    def test_watch_decision_reports_the_whole_selection(self):
        manifest = {
            "manifestDigest": "sha256:" + "a" * 64,
            "captures": [{"captureId": "php_bin_releases", "status": 200, "digest": "sha256:" + "b" * 64}],
        }
        events = [{"actionKey": f"new_patch:{version}", "state": "complete"} for version in FEEDS.values()]
        decision = watch_decision(
            manifest, manifest, events, {"healthy": True},
            releases=releases(), recipe_identities=dict.fromkeys(BRANCHES, NEW),
        )
        self.assertEqual(("rebuild_due", CASCADE[0], CASCADE), (
            decision["trigger"], decision["rebuildActionKey"], decision["rebuildActionKeys"]
        ))
        quiet = watch_decision(
            manifest, manifest, events, {"healthy": True},
            releases=releases(), recipe_identities=dict.fromkeys(BRANCHES, OLD),
        )
        self.assertEqual(("quiet", "", []), (quiet["trigger"], quiet["rebuildActionKey"], quiet["rebuildActionKeys"]))


class BatchClassificationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = pathlib.Path(self._tmp.name)
        self.count = 0

    def tearDown(self):
        self._tmp.cleanup()

    def capture(self, rebuild, *, feeds=FEEDS, rows=ROWS, release_list=None, incomplete=None, legacy=False):
        self.count += 1
        manifest = fixture_capture(
            self.tmp / f"run-{self.count}",
            branch_feeds=feeds,
            aggregate="8.5.12",
            page=support_page(rows),
            releases=release_list if release_list is not None else releases(),
            rebuild=rebuild,
            incomplete=incomplete,
        )
        if legacy:
            # A decision written before batches names only `rebuildActionKey`.
            path = manifest.parent.parent / "watch-decision.json"
            decision = json.loads(path.read_text())
            del decision["rebuildActionKeys"]
            path.write_bytes(canonical_json(decision))
        return manifest

    def classify(self, manifest, events=()):
        return classify_evidence(manifest, PRECONDITIONS, list(events), BRANCHES)

    def admit(self, plan, manifest, pending, completed=(), resumable=None):
        return validate_plan(
            plan, manifest, FIXTURE_HEADS, FIXTURE_POLICY_DIGEST, set(completed), pending,
            resumable_keys=resumable,
        )

    def records(self, *records):
        """Write durable event records to a fresh directory, as admission reads them."""
        self.count += 1
        directory = self.tmp / f"events-{self.count}"
        directory.mkdir()
        for position, record in enumerate(records):
            (directory / f"{position}.json").write_bytes(canonical_json(record))
        return directory

    def test_all_due_rebuilds_classify_and_admit_as_one_batch(self):
        manifest = self.capture(CASCADE)
        plan = self.classify(manifest)
        self.assertEqual(("recipe_rebuild", CASCADE[0], CASCADE), (
            plan["action"], plan["actionKey"], plan["rebuildActionKeys"]
        ))
        self.assertEqual({"version": "8.5.12-2", "sourceIdentifier": "php_bin_releases"}, plan["releaseIntent"])
        cited = [item["locator"]["value"] for item in plan["evidence"]]
        release_list = releases()
        self.assertEqual(
            ["8.5.12-1", "8.4.27-1", "8.3.36-2", "8.2.35-2"],
            [release_list[int(pointer.split("/")[1])]["tag_name"] for pointer in cited],
        )
        self.assertEqual(CASCADE[0], self.admit(plan, manifest, CASCADE)["actionKey"])
        self.assertEqual(
            [
                {"actionKey": "recipe_rebuild:8.5.12:2", "version": "8.5.12-2"},
                {"actionKey": "recipe_rebuild:8.4.27:2", "version": "8.4.27-2"},
                {"actionKey": "recipe_rebuild:8.3.36:3", "version": "8.3.36-3"},
                {"actionKey": "recipe_rebuild:8.2.35:3", "version": "8.2.35-3"},
            ],
            plan_releases(plan),
        )

    def test_a_batch_naming_a_wrong_missing_or_extra_version_never_admits(self):
        manifest = self.capture(CASCADE)
        plan = self.classify(manifest)
        wrong = [*CASCADE[:3], "recipe_rebuild:8.2.34:4"]
        for pending in (
            CASCADE[:3],                                   # the plan names an extra version
            [*CASCADE, "recipe_rebuild:8.1.33:1"],         # the plan misses a due version
            wrong,                                         # the plan names a wrong version
            CASCADE[::-1],                                 # the plan's order is not the selection
            [],                                            # nothing is due at all
        ):
            with self.assertRaisesRegex(ControlError, "selected rebuild", msg=pending):
                self.admit(plan, manifest, pending)
        # The same holds from the plan's side against the real selection.
        for forged in (
            {**plan, "rebuildActionKeys": CASCADE[:3]},
            {**plan, "rebuildActionKeys": [*CASCADE, "recipe_rebuild:8.1.33:1"]},
            {**plan, "rebuildActionKeys": wrong},
            {key: value for key, value in plan.items() if key != "rebuildActionKeys"},
        ):
            with self.assertRaisesRegex(ControlError, "selected rebuild"):
                self.admit(forged, manifest, CASCADE, resumable=set())
        # Every listed key must cite the release it supersedes.
        with self.assertRaisesRegex(ControlError, "supersedes"):
            self.admit({**plan, "evidence": plan["evidence"][:3]}, manifest, CASCADE)
        # A key already completed never admits again, wherever it sits in the batch.
        with self.assertRaisesRegex(ControlError, "already completed"):
            self.admit(plan, manifest, CASCADE, completed={CASCADE[2]})
        # Only a rebuild plan may list rebuild keys.
        with self.assertRaisesRegex(ControlError, "only a recipe rebuild plan"):
            _validate_plan_shape({**plan, "action": "new_patch", "rebuildActionKeys": CASCADE}, manifest, set(), [])

    def test_one_due_rebuild_classifies_exactly_as_before(self):
        key = CASCADE[3]
        current = releases(*(published(tag, NEW) for tag in ("8.5.12-2", "8.4.27-2", "8.3.36-3")))
        modern = self.classify(self.capture([key], release_list=current))
        legacy_manifest = self.capture(key, release_list=current, legacy=True)
        legacy = self.classify(legacy_manifest)
        # The plan carries no batch field and is byte-identical whether the decision
        # lists the one key or, as before batches, only names it.
        self.assertNotIn("rebuildActionKeys", modern)
        self.assertEqual(canonical_json(legacy), canonical_json(modern))
        self.assertEqual("8.2.35-3", modern["releaseIntent"]["version"])
        self.admit(legacy, legacy_manifest, [key])
        self.admit(legacy, legacy_manifest, key)
        with self.assertRaisesRegex(ControlError, "only recipe_rebuild:8.2.35:3 is due"):
            self.admit({**legacy, "rebuildActionKeys": [key]}, legacy_manifest, [key])

    def test_every_other_action_keeps_its_priority_over_a_batch(self):
        # A due patch goes first.
        patch = self.capture(CASCADE, feeds={**FEEDS, "8.3": "8.3.37"})
        plan = self.classify(patch)
        self.assertEqual("new_patch:8.3.37", plan["actionKey"])
        self.admit(plan, patch, CASCADE)
        # So does a new branch.
        rows = {**ROWS, "8.6": ("stable", "31 Dec 2030")}
        self.count += 1
        branch = fixture_capture(
            self.tmp / f"run-{self.count}", branch_feeds=FEEDS, aggregate="8.6.0",
            page=support_page(rows), releases=releases(), rebuild=CASCADE,
        )
        self.assertEqual("new_branch:8.6", self.classify(branch)["actionKey"])
        # And a retirement.
        eol = self.capture(CASCADE, rows={**ROWS, "8.2": ("eol", "31 Dec 2026")})
        self.assertEqual("branch_eol", self.classify(eol)["action"])
        # An incomplete record resumes under its own key; one the selection does not
        # lead with stops for a human exactly as before.
        incomplete = self.capture(CASCADE, incomplete=[CASCADE[1]])
        resumed = self.classify(incomplete, events=[{"actionKey": CASCADE[1], "state": "release_requested"}])
        self.assertEqual(("needs_human", CASCADE[1]), (resumed["action"], resumed["actionKey"]))
        # One the selection leads with but an operator must resolve stops the same way.
        for state in ("blocked", "needs_human"):
            stopped = self.capture(CASCADE, incomplete=[CASCADE[0]])
            plan = self.classify(stopped, events=[{"actionKey": CASCADE[0], "state": state}])
            self.assertEqual(("needs_human", CASCADE[0]), (plan["action"], plan["actionKey"]), state)
        # An unhealthy capture blocks before anything is selected.
        unhealthy = self.capture(CASCADE)
        manifest = json.loads(unhealthy.read_text())
        manifest["captures"][0]["status"] = 503
        unhealthy.write_bytes(canonical_json(manifest))
        self.assertEqual("blocked", self.classify(unhealthy)["action"])
        # Nothing may record the evidence as unchanged while any rebuild is due.
        quiet = self.capture([])
        no_change = self.classify(quiet)
        self.assertEqual("no_change", no_change["action"])
        with self.assertRaisesRegex(ControlError, "due rebuild pending"):
            self.admit(no_change, quiet, CASCADE[2:])


    def test_an_incomplete_first_rebuild_resumes_alone_ahead_of_a_due_patch(self):
        key = CASCADE[0]
        record = {"actionKey": key, "state": "release_requested"}
        # PHP 8.4's feed names 8.4.28, so new_patch:8.4.28 is due behind the resume.
        manifest = self.capture(CASCADE, feeds={**FEEDS, "8.4": "8.4.28"}, incomplete=[key])
        plan = self.classify(manifest, events=[record])
        # The resumed key alone, byte for byte the plan a fresh single rebuild of it gets,
        # so the other three rebuilds never jump ahead of the due patch.
        fresh = self.classify(self.capture([key]))
        self.assertNotIn("rebuildActionKeys", plan)
        self.assertEqual(canonical_json(fresh), canonical_json(plan))
        self.assertEqual([{"actionKey": key, "version": "8.5.12-2"}], plan_releases(plan))
        resumable = resumable_action_keys(self.records(record))
        self.assertEqual({key}, resumable)
        self.assertEqual(key, self.admit(plan, manifest, CASCADE, resumable=resumable)["actionKey"])
        # The resumed plan keeps the whole-capture recapture binding at publish time.
        result = validate_publish_recapture(plan, manifest, manifest, key, "8.5.12-2")
        self.assertIn("php_bin_releases", result["verifiedCaptureIds"])
        self.assertNotIn("branchScopedCaptureIds", result)

    def test_admission_re_derives_a_resumed_rebuild_from_the_event_records(self):
        key = CASCADE[0]
        resumed = self.classify(
            self.capture(CASCADE, incomplete=[key]), events=[{"actionKey": key, "state": "release_requested"}]
        )
        manifest = self.capture(CASCADE)
        batch = self.classify(manifest)
        self.assertEqual(CASCADE, batch["rebuildActionKeys"])
        # While the first due key has a resumable record, the batch around it never admits.
        for state in ("detected", "release_requested", "released"):
            resumable = resumable_action_keys(self.records({"actionKey": key, "state": state}))
            with self.assertRaisesRegex(ControlError, "resumes its incomplete record alone", msg=state):
                self.admit(batch, manifest, CASCADE, resumable=resumable)
            self.admit(resumed, manifest, CASCADE, resumable=resumable)
        # Without such a record the single plan never admits, and the batch does.
        for records in (
            (),
            ({"actionKey": key, "state": "complete"},),
            ({"actionKey": key, "state": "blocked"},),
            ({"actionKey": key, "state": "needs_human"},),
            ({"actionKey": CASCADE[1], "state": "release_requested"},),
        ):
            resumable = resumable_action_keys(self.records(*records))
            with self.assertRaisesRegex(ControlError, "selected rebuild", msg=records):
                self.admit(resumed, manifest, CASCADE, resumable=resumable)
            self.admit(batch, manifest, CASCADE, resumable=resumable)
        # Without the records the resume cannot be re-derived, so it is rejected.
        with self.assertRaisesRegex(ControlError, "only against the event records"):
            self.admit(resumed, manifest, CASCADE)
        # With one rebuild due the single plan needs no records, exactly as before.
        self.admit(resumed, self.capture([key]), [key])


class BatchPublicationTests(unittest.TestCase):
    """Each batch member publishes alone, so a sibling never stops it."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = pathlib.Path(self._tmp.name)
        self.count = 0

    def tearDown(self):
        self._tmp.cleanup()

    def capture(self, release_list, rebuild=CASCADE):
        self.count += 1
        return fixture_capture(
            self.tmp / f"run-{self.count}", branch_feeds=FEEDS, aggregate="8.5.12",
            page=support_page(ROWS), releases=release_list, rebuild=rebuild,
        )

    def admitted(self, rebuild=CASCADE):
        manifest = self.capture(releases(), rebuild)
        plan = classify_evidence(manifest, PRECONDITIONS, [], BRANCHES)
        validate_plan(plan, manifest, FIXTURE_HEADS, FIXTURE_POLICY_DIGEST, set(), rebuild)
        return plan, manifest

    def test_sibling_publications_never_stop_a_batch_member(self):
        plan, admitted = self.admitted()
        siblings = self.capture(releases(published("8.5.12-2", NEW), published("8.3.36-3", NEW)))
        result = validate_publish_recapture(plan, admitted, siblings, CASCADE[1], "8.4.27-2")
        self.assertEqual(["php_bin_releases"], result["branchScopedCaptureIds"])
        self.assertNotIn("php_bin_releases", result["verifiedCaptureIds"])
        # Unchanged evidence passes for every member.
        for release in plan_releases(plan):
            validate_publish_recapture(plan, admitted, admitted, release["actionKey"], release["version"])

    def test_a_change_on_the_member_branch_still_stops_it(self):
        plan, admitted = self.admitted()
        for extra in (
            published("8.4.27-2", NEW),   # its own revision appeared some other way
            published("8.4.28"),          # a later patch shipped on the branch
            {"tag_name": "nightly", "draft": False},  # an entry that is no release tag stays bound
        ):
            moved = self.capture(releases(extra))
            with self.assertRaisesRegex(ControlError, "recaptured evidence changed", msg=extra):
                validate_publish_recapture(plan, admitted, moved, CASCADE[1], "8.4.27-2")
        # The publish run must carry a release the plan admits, and a batch must name one.
        for action_key, version in ((CASCADE[1], "8.4.27-3"), ("recipe_rebuild:8.1.33:1", "8.1.33-1")):
            with self.assertRaisesRegex(ControlError, "does not release"):
                validate_publish_recapture(plan, admitted, admitted, action_key, version)
        with self.assertRaisesRegex(ControlError, "must name its release"):
            validate_publish_recapture(plan, admitted, admitted)
        with self.assertRaisesRegex(ControlError, "names both"):
            validate_publish_recapture(plan, admitted, admitted, CASCADE[1], None)

    def test_a_single_rebuild_stays_bound_to_the_whole_capture(self):
        plan, admitted = self.admitted([CASCADE[0]])
        self.assertNotIn("rebuildActionKeys", plan)
        result = validate_publish_recapture(plan, admitted, admitted, CASCADE[0], "8.5.12-2")
        self.assertIn("php_bin_releases", result["verifiedCaptureIds"])
        self.assertNotIn("branchScopedCaptureIds", result)
        # Exactly as before batches: a release on any branch stops it.
        moved = self.capture(releases(published("8.2.35-3", NEW)))
        with self.assertRaisesRegex(ControlError, "recaptured evidence changed: php_bin_releases"):
            validate_publish_recapture(plan, admitted, moved, CASCADE[0], "8.5.12-2")
        with self.assertRaisesRegex(ControlError, "recaptured evidence changed: php_bin_releases"):
            validate_publish_recapture(plan, admitted, moved)
        # Only a batch may scope a capture by branch, and only the releases capture.
        manifest = json.loads(admitted.read_text())
        with self.assertRaisesRegex(ControlError, "only a batch rebuild"):
            validate_recaptured_evidence(plan, manifest, manifest, branch_scoped=frozenset({"php_bin_releases"}))
        with self.assertRaisesRegex(ControlError, "only the php-bin releases capture"):
            validate_recaptured_evidence(plan, manifest, manifest, branch_scoped=frozenset({"php_bin_state"}))

    def test_partial_failure_retries_only_the_versions_still_due(self):
        plan, admitted = self.admitted()
        # 8.5 and 8.3 published and recorded; 8.4 and 8.2 failed and published nothing,
        # though 8.4 left a draft, which every reader ignores.
        after = releases(published("8.5.12-2", NEW), published("8.3.36-3", NEW))
        identities = dict.fromkeys(BRANCHES, NEW)
        draft = {**published("8.4.27-2", NEW), "draft": True}
        retry = pending_recipe_rebuilds([draft, *after], identities)
        self.assertEqual([CASCADE[1], CASCADE[3]], retry)
        # The next watcher admits exactly those two as a smaller batch.
        manifest = self.capture(after, retry)
        retried = classify_evidence(manifest, PRECONDITIONS, [], BRANCHES)
        self.assertEqual(retry, retried["rebuildActionKeys"])
        completed = {CASCADE[0], CASCADE[2]}
        validate_plan(retried, manifest, FIXTURE_HEADS, FIXTURE_POLICY_DIGEST, completed, retry)
        # Re-running a failed member's own publish run still passes its recapture.
        current = self.capture(after)
        validate_publish_recapture(plan, admitted, current, CASCADE[1], "8.4.27-2")
        validate_publish_recapture(plan, admitted, current, CASCADE[3], "8.2.35-3")
        # With one version left, the retry is an ordinary single rebuild.
        last = releases(*after, published("8.4.27-2", NEW))
        self.assertEqual([CASCADE[3]], pending_recipe_rebuilds(last, identities))

    def test_plan_release_membership_and_cli(self):
        plan, _admitted = self.admitted()
        require_plan_release(plan, CASCADE[2], "8.3.36-3")
        with self.assertRaisesRegex(ControlError, "does not release"):
            require_plan_release(plan, CASCADE[2], "8.3.36-2")
        path = self.tmp / "plan.json"
        path.write_bytes(canonical_json(plan))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(0, control_main(["plan-releases", "--plan", str(path)]))
        self.assertEqual(
            ["recipe_rebuild:8.5.12:2 8.5.12-2", "recipe_rebuild:8.4.27:2 8.4.27-2",
             "recipe_rebuild:8.3.36:3 8.3.36-3", "recipe_rebuild:8.2.35:3 8.2.35-3"],
            out.getvalue().splitlines(),
        )
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(1, control_main(
                ["require-plan-release", "--plan", str(path), "--action-key", CASCADE[0], "--version", "8.4.27-2"]
            ))
        # A single plan releases its own key and intent, as before.
        single = {**plan, "actionKey": "new_patch:8.5.13", "action": "new_patch",
                  "releaseIntent": {"version": "8.5.13", "sourceIdentifier": "php_release_feed_8.5"}}
        del single["rebuildActionKeys"]
        self.assertEqual([{"actionKey": "new_patch:8.5.13", "version": "8.5.13"}], plan_releases(single))


class BatchReportingTests(unittest.TestCase):
    def test_status_lists_every_selected_rebuild(self):
        keys = ["recipe_rebuild:8.5.11:4", "recipe_rebuild:8.4.26:3"]
        with tempfile.TemporaryDirectory() as scratch:
            run_dir, previous = status_run(
                pathlib.Path(scratch) / "run",
                decision={"trigger": "rebuild_due", "classify": True, "rebuildActionKey": keys[0], "rebuildActionKeys": keys},
            )
            document = status_document(run_dir, previous, RUN_URL)
        self.assertEqual((keys[0], keys), (document["rebuildDueActionKey"], document["rebuildDueActionKeys"]))
        self.assertIn(f"Rebuilds due: {keys[0]}, {keys[1]}", status_block(document))
        for change in ({"rebuildDueActionKeys": keys[::-1]}, {"rebuildDueActionKeys": [keys[0], "new_patch:8.5.12"]}):
            with self.assertRaisesRegex(ControlError, "status rebuild action keys are invalid"):
                validate_status_document({**document, **change})

    def test_watcher_digest_names_every_batch_revision(self):
        report = {
            "workflow": "watcher",
            "conclusion": "success",
            "runUrl": RUN_URL,
            "repository": "bigpixelrocket/php-bin",
            "decision": {"manifestDigest": "sha256:" + "a" * 64, "classify": True},
            "plan": {"action": "recipe_rebuild", "actionKey": CASCADE[0], "rebuildActionKeys": CASCADE},
            "status": None,
        }
        message = email_digest(report)
        self.assertEqual("recipe_rebuilds_started", message["template"])
        self.assertIn("4 PHP rebuilds started (8.5.12-2, 8.4.27-2, 8.3.36-3, 8.2.35-3)", message["subject"])
        for key in CASCADE:
            self.assertIn(key, message["body"])
        with self.assertRaisesRegex(ControlError, "rebuild keys are invalid"):
            email_digest({**report, "plan": {**report["plan"], "rebuildActionKeys": ["new_patch:8.5.13", *CASCADE]}})
        single = email_digest({**report, "plan": {"action": "recipe_rebuild", "actionKey": CASCADE[0]}})
        self.assertEqual("recipe_rebuild_started", single["template"])


if __name__ == "__main__":
    unittest.main()
