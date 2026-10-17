import contextlib
import copy
import io
import json
import pathlib
import tempfile
import unittest

from autorelease._classifier import SUPPORT_STATES
from autorelease._state import (
    STATUS_ACTIONS,
    STATUS_BRANCH_FIELDS,
    STATUS_BRANCH_STATES,
    STATUS_FIELDS,
    STATUS_SUPPORT_STATES,
    STATUS_TRIGGERS,
    status_block,
    validate_status_document,
)
from autorelease._status import status_document, status_page
from autorelease.control import (
    PLAN_ACTIONS,
    ROOT,
    ControlError,
    canonical_json,
    email_digest,
    email_fallback,
    main as control_main,
    manifest_digest,
    recipe_identity_note,
    sha256_bytes,
)
from autorelease.verify import load_workflow, support_page


RUN_URL = "https://github.com/bigpixelrocket/php-bin/actions/runs/39021079957"
IDENTITY = "sha256:" + "1" * 64
OTHER_IDENTITY = "sha256:" + "2" * 64
FEEDS = {"8.4": ("8.4.26", "24 Sep 2026"), "8.5": ("8.5.11", "24 Sep 2026")}
PAGE_ROWS = {"8.4": ("stable", "31 Dec 2028"), "8.5": ("stable", "31 Dec 2029")}


def release(tag: str, published_at: str = "2026-09-29T15:57:43Z", identity: str = IDENTITY, **fields) -> dict:
    """Return one php-bin release as the projected releases capture lists it."""
    return {
        "tag_name": tag,
        "draft": False,
        "prerelease": False,
        "published_at": published_at,
        "body": recipe_identity_note(identity),
        **fields,
    }


RELEASES = [release("8.5.11-3"), release("8.5.11-2"), release("8.5.10-3"), release("8.4.26-2")]


def status_run(
    directory: pathlib.Path,
    *,
    feeds=FEEDS,
    releases=RELEASES,
    page_rows=PAGE_ROWS,
    captured_at="2026-10-17T09:25:46Z",
    statuses=None,
    bodies=None,
    decision=None,
    plan=None,
    admitted=True,
    previous="same",
) -> tuple[pathlib.Path, pathlib.Path]:
    """Write one retained watcher run in the artifact layout and its reviewed snapshot.

    `statuses` and `bodies` override single captures. `decision` updates the default
    quiet watch decision. `previous` is "same" (the snapshot matches this capture),
    None (no snapshot), or a mapping of capture IDs to digests that differ.
    """
    captured = {
        "php_supported_versions": support_page(page_rows),
        "php_release_feed": canonical_json({"8": {"version": "8.5.11"}}),
        **{
            f"php_release_feed_{branch}": canonical_json({"version": version, "date": date})
            for branch, (version, date) in feeds.items()
        },
        "php_source_tags": canonical_json([]),
        "php_bin_releases": canonical_json(releases),
        "php_bin_state": canonical_json({"sha": "a" * 40}),
        "mise_php_releases": canonical_json([]),
        "mise_php_state": canonical_json({"sha": "b" * 40}),
        **(bodies or {}),
    }
    raw = directory / "evidence/raw"
    raw.mkdir(parents=True)
    captures = []
    for capture_id, body in captured.items():
        (raw / f"{capture_id}.body").write_bytes(body)
        captures.append(
            {
                "captureId": capture_id,
                "status": (statuses or {}).get(capture_id, 200),
                "digest": sha256_bytes(body),
                "bodyPath": f"raw/{capture_id}.body",
            }
        )
    manifest = {
        "schemaVersion": 1,
        "capturedAt": captured_at,
        "captures": captures,
        "manifestDigest": manifest_digest(captures),
    }
    (directory / "evidence/evidence-manifest.json").write_bytes(canonical_json(manifest))
    watch = {
        "schemaVersion": 1,
        "trigger": "quiet",
        "manifestDigest": manifest["manifestDigest"],
        "incompleteActions": [],
        "action": "none",
        "actionKey": "",
        "rebuildActionKey": "",
        "classify": False,
        **(decision or {}),
    }
    (directory / "watch-decision.json").write_bytes(canonical_json(watch))
    if plan is not None:
        (directory / "autorelease-plan.json").write_bytes(canonical_json(plan))
        if admitted:
            (directory / "admission.json").write_bytes(
                canonical_json(
                    {
                        "actionKey": plan["actionKey"],
                        "admitted": True,
                        "admittedAt": captured_at,
                        "planDigest": sha256_bytes(canonical_json(plan)),
                    }
                )
            )
    previous_path = directory.parent / f"{directory.name}-last-evidence.json"
    if previous is not None:
        recorded = [
            {
                "captureId": item["captureId"],
                "digest": (previous if isinstance(previous, dict) else {}).get(item["captureId"], item["digest"]),
                "status": 200,
            }
            for item in captures
        ]
        previous_path.write_bytes(
            canonical_json(
                {
                    "schemaVersion": 1,
                    "manifestDigest": manifest_digest(recorded),
                    "planDigest": "sha256:" + "c" * 64,
                    "captures": recorded,
                }
            )
        )
    return directory, previous_path


def branch(document: dict, name: str) -> dict:
    return next(item for item in document["branches"] if item["branch"] == name)


class BranchStatusTests(unittest.TestCase):
    def derive(self, identities=None, **fixture) -> dict:
        with tempfile.TemporaryDirectory() as scratch:
            run_dir, previous = status_run(pathlib.Path(scratch) / "run", **fixture)
            return status_document(
                run_dir, previous, RUN_URL, identities if identities is not None else {"8.4": IDENTITY, "8.5": IDENTITY}
            )

    def test_quiet_day_reports_every_branch_current(self):
        document = self.derive()
        self.assertEqual("All 2 branches current", document["summary"])
        self.assertEqual({"8.5": "8.5.11-3, current", "8.4": "8.4.26-2, current"}, document["badges"])
        self.assertEqual(["8.5", "8.4"], [item["branch"] for item in document["branches"]])
        newest = branch(document, "8.5")
        self.assertEqual("current", newest["status"])
        self.assertEqual({"version": "8.5.11", "releaseDate": "2026-09-24"}, newest["upstream"])
        # The newest revision of the newest patch, not the last one listed.
        self.assertEqual(
            {"tag": "8.5.11-3", "version": "8.5.11", "revision": 3, "publishedAt": "2026-09-29T15:57:43Z"},
            newest["phpBin"],
        )
        self.assertIs(False, newest["rebuildDue"])
        self.assertEqual(("stable", "2029-12-31", 1171), (newest["supportState"], newest["securitySupportUntil"], newest["securitySupportDaysLeft"]))
        self.assertEqual("2026-10-17T09:25:46Z", document["checkedAt"])
        self.assertEqual(("quiet", None, None), (document["trigger"], document["action"], document["actionKey"]))
        self.assertEqual([], document["inProgressActionKeys"])
        self.assertIsNone(document["rebuildDueActionKey"])
        self.assertEqual([], document["changedCaptures"])
        self.assertEqual({"healthy": True, "unhealthyCaptures": [], "unreadableCaptures": []}, document["captureHealth"])
        block = status_block(document)
        self.assertEqual(
            [
                "Branch status at 2026-10-17 09:25 UTC:",
                "",
                "Branch  php.net               php-bin            Status   Security EOL",
                "8.5     8.5.11 (24 Sep 2026)  8.5.11-3 (29 Sep)  current  31 Dec 2029",
                "8.4     8.4.26 (24 Sep 2026)  8.4.26-2 (29 Sep)  current  31 Dec 2028",
                "",
                "In progress: none   Rebuilds due: none   Changed inputs: none",
            ],
            block.splitlines(),
        )

    def test_unpublished_upstream_patch_is_behind(self):
        document = self.derive(feeds={**FEEDS, "8.5": ("8.5.12", "22 Oct 2026")})
        self.assertEqual("behind", branch(document, "8.5")["status"])
        self.assertEqual("1 of 2 branches current, 1 behind", document["summary"])
        # A branch that never shipped is behind too, and its php-bin cell reads none.
        document = self.derive(releases=[release("8.5.11-3")])
        self.assertEqual("behind", branch(document, "8.4")["status"])
        self.assertIsNone(branch(document, "8.4")["phpBin"])
        self.assertIn("8.4     8.4.26 (24 Sep 2026)  none ", status_block(document))
        self.assertEqual("none, behind", document["badges"]["8.4"])

    def test_admitted_or_incomplete_release_work_reads_releasing(self):
        plan = {"action": "new_patch", "actionKey": "new_patch:8.5.12", "summary": "Fixture."}
        document = self.derive(
            feeds={**FEEDS, "8.5": ("8.5.12", "22 Oct 2026")},
            decision={"trigger": "event_incomplete", "classify": True, "incompleteActions": ["recipe_rebuild:8.4.26:3"]},
            plan=plan,
        )
        self.assertEqual(["releasing", "releasing"], [item["status"] for item in document["branches"]])
        self.assertEqual(("new_patch", "new_patch:8.5.12"), (document["action"], document["actionKey"]))
        self.assertEqual(["new_patch:8.5.12", "recipe_rebuild:8.4.26:3"], document["inProgressActionKeys"])
        self.assertIn("In progress: new_patch:8.5.12, recipe_rebuild:8.4.26:3", status_block(document))
        # A plan that failed admission authorized nothing, so it names no action.
        document = self.derive(feeds={**FEEDS, "8.5": ("8.5.12", "22 Oct 2026")}, plan=plan, admitted=False)
        self.assertEqual("behind", branch(document, "8.5")["status"])
        self.assertEqual((None, None, []), (document["action"], document["actionKey"], document["inProgressActionKeys"]))
        # Neither does a plan whose admission record names other bytes.
        with tempfile.TemporaryDirectory() as scratch:
            run_dir, previous = status_run(pathlib.Path(scratch) / "run", plan=plan)
            (run_dir / "autorelease-plan.json").write_bytes(canonical_json({**plan, "summary": "Edited."}))
            self.assertIsNone(status_document(run_dir, previous, RUN_URL)["action"])
        # A no-change plan is not work in flight.
        document = self.derive(plan={"action": "no_change", "actionKey": "no_change:" + "0" * 16})
        self.assertEqual("no_change", document["action"])
        self.assertEqual([], document["inProgressActionKeys"])

    def test_recipe_change_marks_the_branch_rebuild_due(self):
        document = self.derive(
            identities={"8.4": IDENTITY, "8.5": OTHER_IDENTITY},
            decision={"trigger": "rebuild_due", "classify": True, "rebuildActionKey": "recipe_rebuild:8.5.11:4"},
        )
        self.assertEqual((True, "current"), (branch(document, "8.5")["rebuildDue"], branch(document, "8.5")["status"]))
        self.assertIs(False, branch(document, "8.4")["rebuildDue"])
        self.assertEqual("recipe_rebuild:8.5.11:4", document["rebuildDueActionKey"])
        self.assertEqual("All 2 branches current, 1 rebuild due", document["summary"])
        block = status_block(document)
        self.assertIn("8.5.11-3 (29 Sep)  current, rebuild due  31 Dec 2029", block)
        self.assertIn("Rebuilds due: recipe_rebuild:8.5.11:4", block)
        # Without the watcher's recipe identities nothing is claimed either way, and
        # neither is anything from a capture with an unhealthy source, exactly as the
        # watch decision selects no rebuild from one.
        document = self.derive(identities={})
        self.assertEqual([None, None], [item["rebuildDue"] for item in document["branches"]])
        document = self.derive(identities={"8.4": IDENTITY, "8.5": OTHER_IDENTITY}, statuses={"php_source_tags": 502})
        self.assertEqual([None, None], [item["rebuildDue"] for item in document["branches"]])
        self.assertNotIn("rebuild due", status_block(document))

    def test_unhealthy_or_unreadable_captures_are_unknown_never_guessed(self):
        document = self.derive(statuses={"php_release_feed_8.4": 503})
        self.assertEqual(("unknown", None), (branch(document, "8.4")["status"], branch(document, "8.4")["upstream"]))
        self.assertEqual("current", branch(document, "8.5")["status"])
        self.assertEqual(
            {"healthy": False, "unhealthyCaptures": ["php_release_feed_8.4"], "unreadableCaptures": []},
            document["captureHealth"],
        )
        block = status_block(document)
        self.assertIn("8.4     unknown ", block)
        self.assertIn("Unhealthy captures: php_release_feed_8.4", block)
        self.assertEqual("1 of 2 branches current, 1 unknown", document["summary"])

        # Without a trustworthy releases list no branch is compared or rebuilt.
        document = self.derive(statuses={"php_bin_releases": 500})
        self.assertEqual(["unknown", "unknown"], [item["status"] for item in document["branches"]])
        self.assertEqual([None, None], [item["phpBin"] for item in document["branches"]])
        self.assertEqual([None, None], [item["rebuildDue"] for item in document["branches"]])
        self.assertIn("8.5     8.5.11 (24 Sep 2026)  unknown  unknown", status_block(document))
        self.assertEqual({"8.5": "unknown", "8.4": "unknown"}, document["badges"])

        # A healthy body in an unreviewed shape is named as unreadable.
        document = self.derive(
            bodies={
                "php_release_feed_8.5": canonical_json({"version": "8.4.26", "date": "24 Sep 2026"}),
                "php_release_feed_8.4": canonical_json({"version": "8.4.26", "date": "2026-09-24"}),
                "php_supported_versions": b"<main>redesigned</main>",
            }
        )
        self.assertEqual(
            ["php_release_feed_8.4", "php_release_feed_8.5", "php_supported_versions"],
            document["captureHealth"]["unreadableCaptures"],
        )
        self.assertEqual(["unknown", "unknown"], [item["status"] for item in document["branches"]])
        self.assertEqual([None, None], [item["securitySupportUntil"] for item in document["branches"]])
        self.assertIn("Unreadable captures: php_release_feed_8.4, php_release_feed_8.5, php_supported_versions", status_block(document))

        # A published tag without its publication time could hide the newest revision,
        # so the whole releases list is unreadable rather than partly skipped.
        for broken in ({"published_at": None}, {"published_at": "29 Sep 2026"}):
            document = self.derive(releases=[{**release("8.5.11-3"), **broken}, *RELEASES[1:]])
            with self.subTest(broken=broken):
                self.assertEqual(["php_bin_releases"], document["captureHealth"]["unreadableCaptures"])
                self.assertEqual(["unknown", "unknown"], [item["status"] for item in document["branches"]])
                self.assertEqual([None, None], [item["phpBin"] for item in document["branches"]])
                self.assertEqual({"8.5": "unknown", "8.4": "unknown"}, document["badges"])
        # A draft or a tag that is not a release version is not held to that rule.
        document = self.derive(
            releases=[*RELEASES, {"tag_name": "8.5.12", "draft": True, "published_at": None}, {"tag_name": "nightly"}]
        )
        self.assertEqual("8.5.11-3", branch(document, "8.5")["phpBin"]["tag"])
        self.assertTrue(document["captureHealth"]["healthy"])

        # A body that no longer matches its recorded digest is not read either.
        with tempfile.TemporaryDirectory() as scratch:
            run_dir, previous = status_run(pathlib.Path(scratch) / "run")
            (run_dir / "evidence/raw/php_release_feed_8.5.body").write_bytes(canonical_json({"version": "8.5.99"}))
            document = status_document(run_dir, previous, RUN_URL)
            self.assertEqual(["php_release_feed_8.5"], document["captureHealth"]["unreadableCaptures"])
            self.assertIsNone(branch(document, "8.5")["upstream"])

    def test_security_support_end_counts_down_once_it_is_near(self):
        rows = {"8.2": ("security", "31 Dec 2026"), "8.3": ("security", "18 Oct 2026"), "8.4": ("eol", "31 Dec 2025")}
        feeds = {"8.2": ("8.2.34", "24 Sep 2026"), "8.3": ("8.3.35", "24 Sep 2026"), "8.4": ("8.4.26", "24 Sep 2026")}
        releases = [release("8.2.34-2"), release("8.3.35-2"), release("8.4.26-2", published_at="2025-12-01T00:00:00Z")]
        document = self.derive(feeds=feeds, page_rows=rows, releases=releases, identities={})
        self.assertEqual([-290, 1, 75], [item["securitySupportDaysLeft"] for item in document["branches"]])
        block = status_block(document)
        self.assertIn("31 Dec 2026 (75 days)", block)
        self.assertIn("18 Oct 2026 (1 day)", block)
        self.assertIn("31 Dec 2025 (ended)", block)
        # A publication in another year than the capture keeps its year.
        self.assertIn("8.4.26-2 (01 Dec 2025)", block)
        self.assertEqual("eol", branch(document, "8.4")["supportState"])
        # A maintained branch the page no longer lists has no end date to show.
        document = self.derive(page_rows={"8.5": ("stable", "31 Dec 2029")})
        self.assertEqual((None, None, None), tuple(branch(document, "8.4")[field] for field in ("supportState", "securitySupportUntil", "securitySupportDaysLeft")))
        self.assertIn("current  unknown", status_block(document))

    def test_changed_captures_are_named_against_the_reviewed_snapshot(self):
        document = self.derive(previous={"php_bin_state": "sha256:" + "d" * 64, "php_supported_versions": "sha256:" + "e" * 64})
        self.assertEqual(["php_bin_state", "php_supported_versions"], document["changedCaptures"])
        self.assertIn("Changed inputs: php_bin_state, php_supported_versions", status_block(document))
        document = self.derive(previous=None)
        self.assertIsNone(document["changedCaptures"])
        self.assertIn("Changed inputs: unknown", status_block(document))

    def test_run_state_that_contradicts_the_capture_is_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            run_dir, previous = status_run(pathlib.Path(scratch) / "run")
            decision = json.loads((run_dir / "watch-decision.json").read_text())
            (run_dir / "watch-decision.json").write_text(json.dumps({**decision, "manifestDigest": "sha256:" + "f" * 64}))
            with self.assertRaisesRegex(ControlError, "not taken on this evidence manifest"):
                status_document(run_dir, previous, RUN_URL)
            with self.assertRaisesRegex(ControlError, "run url is invalid"):
                (run_dir / "watch-decision.json").write_text(json.dumps(decision))
                status_document(run_dir, previous, "https://example.invalid/run")
            manifest = json.loads((run_dir / "evidence/evidence-manifest.json").read_text())
            (run_dir / "evidence/evidence-manifest.json").write_text(json.dumps({**manifest, "capturedAt": "2026-13-01T00:00:00Z"}))
            with self.assertRaisesRegex(ControlError, "capture time is invalid"):
                status_document(run_dir, previous, RUN_URL)


class StatusDocumentValidationTests(unittest.TestCase):
    def setUp(self):
        with tempfile.TemporaryDirectory() as scratch:
            run_dir, previous = status_run(pathlib.Path(scratch) / "run")
            self.document = status_document(run_dir, previous, RUN_URL, {"8.4": IDENTITY, "8.5": IDENTITY})

    def test_every_rendered_value_is_revalidated(self):
        def edited(change):
            document = copy.deepcopy(self.document)
            change(document)
            return document

        hostile = "8.5.11 <script>; curl evil"
        cases = (
            lambda d: d.update(summary="All good, trust me"),
            lambda d: d["badges"].update({"8.5": "8.5.11-3, current, trust me"}),
            lambda d: d["badges"].update({"8.6": "8.6.0, current"}),
            lambda d: d.update(extra=True),
            lambda d: d.update(schemaVersion=True),
            lambda d: d.update(runUrl="https://github.com/a/b/actions/runs/1?x=" + hostile),
            lambda d: d.update(trigger=["quiet"]),
            lambda d: d.update(action="publish", actionKey="new_patch:8.5.11"),
            lambda d: d.update(action="new_patch", actionKey="new_branch:8.6"),
            lambda d: d.update(action="no_change", actionKey=None),
            lambda d: d.update(inProgressActionKeys=["new_patch:8.5.12", "new_patch:8.5.12"]),
            lambda d: d.update(rebuildDueActionKey="new_patch:8.5.12"),
            lambda d: d.update(changedCaptures=[hostile]),
            lambda d: d["captureHealth"].update(healthy=False),
            lambda d: d["captureHealth"].update(unhealthyCaptures=["php_release_feed_8.5"]),
            lambda d: d.update(branches=[]),
            lambda d: d.update(branches=list(reversed(d["branches"]))),
            lambda d: d["branches"][0].update(status="ahead"),
            lambda d: d["branches"][0].update(rebuildDue=[True]),
            lambda d: d["branches"][0]["upstream"].update(version=hostile),
            lambda d: d["branches"][0]["upstream"].update(version="8.4.26"),
            lambda d: d["branches"][0]["upstream"].update(releaseDate="24 Sep 2026"),
            lambda d: d["branches"][0]["phpBin"].update(tag="8.4.26-2"),
            lambda d: d["branches"][0]["phpBin"].update(revision=True),
            lambda d: d["branches"][0]["phpBin"].update(revision=2),
            lambda d: d["branches"][0]["phpBin"].update(publishedAt=hostile),
            # A comparison state is a claim the versions must support.
            lambda d: d["branches"][0]["upstream"].update(version="8.5.12"),
            lambda d: d["branches"][0].update(status="behind"),
            lambda d: d["branches"][0].update(securitySupportDaysLeft=1170),
            lambda d: d["branches"][0].update(supportState=None),
            lambda d: d["branches"][0].update(supportState="maintained"),
        )
        validate_status_document(copy.deepcopy(self.document))
        for change in cases:
            document = edited(change)
            with self.subTest(document=document):
                with self.assertRaises(ControlError) as raised:
                    validate_status_document(document)
                # Rejection reasons reach an email, so they never repeat a value.
                self.assertNotIn("curl evil", str(raised.exception))
                self.assertNotIn("trust me", str(raised.exception))

    def test_schema_matches_the_validator(self):
        schema = json.loads((ROOT / "schemas/autorelease-status.schema.json").read_text())
        self.assertEqual(STATUS_FIELDS, set(schema["required"]))
        self.assertEqual(STATUS_FIELDS, set(schema["properties"]))
        items = schema["properties"]["branches"]["items"]
        self.assertEqual(STATUS_BRANCH_FIELDS, set(items["required"]))
        self.assertEqual(STATUS_BRANCH_FIELDS, set(items["properties"]))
        self.assertEqual(list(STATUS_BRANCH_STATES), items["properties"]["status"]["enum"])
        self.assertEqual(STATUS_TRIGGERS | {None}, set(schema["properties"]["trigger"]["enum"]))
        self.assertEqual(STATUS_ACTIONS | {None}, set(schema["properties"]["action"]["enum"]))
        self.assertEqual(STATUS_SUPPORT_STATES | {None}, set(items["properties"]["supportState"]["enum"]))
        # The shared vocabularies are the ones the classifier and admission enforce.
        self.assertEqual(PLAN_ACTIONS, STATUS_ACTIONS)
        self.assertEqual(SUPPORT_STATES, STATUS_SUPPORT_STATES)
        self.assertEqual(set(self.document), STATUS_FIELDS)

    def test_published_page_escapes_and_links_the_document(self):
        page = status_page(self.document)
        self.assertIn("<title>php-bin release status</title>", page)
        self.assertIn("<p>All 2 branches current.</p>", page)
        self.assertIn('<a href="status.json">status.json</a>', page)
        self.assertIn(f'<a href="{RUN_URL}">', page)
        self.assertIn("8.5     8.5.11 (24 Sep 2026)", page)
        broken = {**self.document, "summary": "<script>"}
        with self.assertRaises(ControlError):
            status_page(broken)


def run_control(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        status = control_main(list(argv))
    return status, out.getvalue()


class StatusEmailTests(unittest.TestCase):
    BASE = {
        "workflow": "watcher",
        "conclusion": "success",
        "runUrl": RUN_URL,
        "repository": "bigpixelrocket/php-bin",
    }

    def setUp(self):
        with tempfile.TemporaryDirectory() as scratch:
            run_dir, previous = status_run(pathlib.Path(scratch) / "run")
            self.status = status_document(run_dir, previous, RUN_URL, {"8.4": IDENTITY, "8.5": IDENTITY})
        self.quiet = {"classify": False, "manifestDigest": "sha256:" + "a" * 64}
        self.changed = {"classify": True, "manifestDigest": "sha256:" + "a" * 64}

    def test_quiet_day_subject_summarizes_state_and_body_carries_the_table(self):
        message = email_digest({**self.BASE, "decision": self.quiet, "status": self.status})
        self.assertEqual("quiet_day", message["template"])
        self.assertEqual(
            "[php-bin autorelease] All 2 branches current (checked 2026-10-17 09:25 UTC)", message["subject"]
        )
        self.assertIn(status_block(self.status), message["body"])
        self.assertIn("In progress: none   Rebuilds due: none   Changed inputs: none", message["body"])
        self.assertTrue(message["body"].endswith(f"Run: {RUN_URL}"))

    def test_quiet_day_names_its_own_evidence_commit(self):
        status = {**self.status, "changedCaptures": ["php_bin_state"]}
        message = email_digest({**self.BASE, "decision": self.quiet, "status": status})
        self.assertIn("The php_bin_state change below is the commit that recorded that capture.", message["body"])
        self.assertIn("Changed inputs: php_bin_state", message["body"])
        message = email_digest({**self.BASE, "decision": self.quiet, "status": self.status})
        self.assertNotIn("recorded that capture", message["body"])

    def test_fallback_digest_keeps_the_watcher_table(self):
        message = email_fallback({**self.BASE, "status": self.status}, "no email template exists for action: publish")
        self.assertEqual("unexpected_state", message["template"])
        self.assertIn(status_block(self.status), message["body"])
        message = email_fallback(self.BASE, "no email template exists for action: publish")
        self.assertIn("Branch status: unavailable; this run retained no status document.", message["body"])
        message = email_fallback({**self.BASE, "workflow": "publish", "status": self.status}, "rejected")
        self.assertNotIn("Branch status", message["body"])

    def test_every_watcher_template_carries_the_table_and_publish_does_not(self):
        plans = (
            {"action": "no_change", "actionKey": "no_change:" + "0" * 16},
            {"action": "new_patch", "actionKey": "new_patch:8.5.12"},
            {"action": "new_branch", "actionKey": "new_branch:8.6"},
            {"action": "branch_eol", "actionKey": "branch_eol:8.1:2026-12-31"},
            {"action": "recipe_rebuild", "actionKey": "recipe_rebuild:8.5.11:4"},
            {"action": "blocked", "actionKey": "source_unhealthy:" + "b" * 16},
        )
        reports = [{**self.BASE, "decision": self.changed, "plan": plan, "status": self.status} for plan in plans]
        reports += [
            {**self.BASE, "decision": self.quiet, "status": self.status},
            {**self.BASE, "conclusion": "failure", "status": self.status},
        ]
        table = status_block(self.status)
        for report in reports:
            with self.subTest(plan=report.get("plan"), conclusion=report["conclusion"]):
                self.assertIn(table, email_digest(report)["body"])
        message = email_digest(
            {**self.BASE, "decision": self.changed, "plan": plans[0], "status": self.status}
        )
        self.assertEqual(
            "[php-bin autorelease] Watcher: evidence changed, no release needed (all 2 branches current)",
            message["subject"],
        )
        published = email_digest(
            {**self.BASE, "workflow": "publish", "transaction": {"released": True, "version": "8.5.12"}, "status": self.status}
        )
        self.assertNotIn("Branch status", published["body"])

    def test_missing_or_rejected_status_keeps_the_template_with_a_fixed_line(self):
        cases = (
            ({}, "Branch status: unavailable; this run retained no status document."),
            ({"statusUnreadable": True}, "Branch status: unavailable; the retained status document is not valid JSON."),
            (
                {"status": {**self.status, "summary": "All good <script>"}},
                "Branch status: unavailable; the retained status document was rejected "
                "(status summary does not match its branches).",
            ),
        )
        for extra, line in cases:
            with self.subTest(line=line):
                message = email_digest({**self.BASE, "decision": self.quiet, **extra})
                self.assertEqual("quiet_day", message["template"])
                self.assertEqual("[php-bin autorelease] Watcher: no upstream changes", message["subject"])
                self.assertIn(line, message["body"])
                self.assertNotIn("<script>", message["body"])

    def test_cli_publishes_the_document_and_the_digest_reads_it_back(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = pathlib.Path(scratch)
            run_dir, previous = status_run(root / "run")
            status, output = run_control(
                "status", "--run-dir", str(run_dir), "--previous", str(previous),
                "--run-url", RUN_URL, "--output", str(root / "site"),
            )
            self.assertEqual(0, status)
            self.assertIn("Branch status at 2026-10-17 09:25 UTC:", output)
            published = json.loads((root / "site/status.json").read_text())
            validate_status_document(published)
            # Without --recipe-commit no rebuild is claimed either way.
            self.assertEqual([None, None], [item["rebuildDue"] for item in published["branches"]])
            self.assertIn("<pre>", (root / "site/index.html").read_text())
            status, output = run_control(
                "status", "--run-dir", str(run_dir), "--previous", str(previous),
                "--run-url", RUN_URL, "--recipe-commit", "main", "--output", str(root / "other"),
            )
            self.assertEqual(1, status)
            digest_args = [
                "email-digest", "--workflow", "watcher", "--conclusion", "success",
                "--run-url", RUN_URL, "--repository", "bigpixelrocket/php-bin",
                "--decision", str(run_dir / "watch-decision.json"),
                "--plan", str(run_dir / "autorelease-plan.json"),
            ]
            status, output = run_control(*digest_args, "--status", str(root / "site/status.json"))
            self.assertEqual(0, status)
            self.assertEqual("All 2 branches current (checked 2026-10-17 09:25 UTC)", json.loads(output)["subject"].split("] ", 1)[1])
            # Run state that matches no template still sends the fallback, table included.
            (root / "decision.json").write_bytes(b"\xff\xfe{")
            status, output = run_control(
                *digest_args[:-2], "--decision", str(root / "decision.json"), "--status", str(root / "site/status.json")
            )
            self.assertEqual(0, status)
            self.assertEqual("unexpected_state", json.loads(output)["template"])
            self.assertIn("Branch status at 2026-10-17 09:25 UTC:", json.loads(output)["body"])
            # A status document that is not JSON, or not even UTF-8, only loses the table.
            for corrupt in (b"{not json", b"\xff\xfe{"):
                (root / "site/status.json").write_bytes(corrupt)
                status, output = run_control(*digest_args, "--status", str(root / "site/status.json"))
                with self.subTest(corrupt=corrupt):
                    self.assertEqual(0, status)
                    self.assertEqual("quiet_day", json.loads(output)["template"])
                    self.assertIn("is not valid JSON", json.loads(output)["body"])


class StatusWorkflowTests(unittest.TestCase):
    def test_watcher_publishes_status_from_an_isolated_main_only_job(self):
        workflows = ROOT / ".github/workflows"
        jobs = load_workflow(workflows / "autorelease-watch.yml")["jobs"]
        investigate = jobs["investigate"]["steps"]
        names = [step.get("name") for step in investigate]
        derive = investigate[names.index("Derive the branch status")]
        # A status defect can never hold back classification or the dispatch after it.
        self.assertIs(True, derive["continue-on-error"])
        self.assertIn("!cancelled()", derive["if"])
        self.assertIn("--previous autorelease-state/last-evidence.json", derive["run"])
        self.assertLess(names.index("Expose admitted plan"), names.index("Derive the branch status"))
        self.assertLess(names.index("Derive the branch status"), names.index("Retain evidence and admitted plan"))
        stage = investigate[names.index("Stage the branch status for GitHub Pages")]
        self.assertTrue(stage["uses"].startswith("actions/upload-pages-artifact@"))
        self.assertIs(True, stage["continue-on-error"])
        self.assertIn("github.ref == 'refs/heads/main'", stage["if"])
        self.assertEqual("github-pages-${{ github.run_attempt }}", stage["with"]["name"])

        deploy = jobs["publish-status"]
        self.assertEqual("investigate", deploy["needs"])
        # A Pages outage cannot turn the digest of a healthy run into a failure.
        self.assertIs(True, deploy["continue-on-error"])
        self.assertEqual({"contents": "read", "pages": "write", "id-token": "write"}, deploy["permissions"])
        self.assertIn("github.ref == 'refs/heads/main'", deploy["if"])
        self.assertEqual("github-pages", deploy["environment"]["name"])
        self.assertEqual(1, len(deploy["steps"]))
        self.assertTrue(deploy["steps"][0]["uses"].startswith("actions/deploy-pages@"))
        self.assertEqual("${{ needs.investigate.outputs.status_artifact }}", deploy["steps"][0]["with"]["artifact_name"])
        # No other job may deploy, and the failure notifier still covers only the pipeline.
        self.assertEqual(
            ["publish-status"],
            [name for name, job in jobs.items() if "pages" in (job.get("permissions") or {})],
        )
        self.assertEqual(["investigate", "coordinate"], jobs["notify-failure"]["needs"])

        email = load_workflow(workflows / "autorelease-email.yml")["jobs"]["digest"]["steps"]
        render = next(step for step in email if step.get("name") == "Render the deterministic digest")
        self.assertIn("--status email-run/state/status/status.json", render["run"])

    def test_configuration_and_snapshot_cover_the_pages_site(self):
        configure = (ROOT / "scripts/configure-github-autorelease").read_text()
        self.assertIn('input_value={"build_type": "workflow"}', configure)
        snapshot = (ROOT / "scripts/snapshot-github-admin-state").read_text()
        self.assertIn('gh_api(f"repos/{args.repo}/pages", allow_missing=True)', snapshot)
        settings = (ROOT / "docs/repository-settings.md").read_text()
        self.assertIn("--environment github-pages", settings)


if __name__ == "__main__":
    unittest.main()
