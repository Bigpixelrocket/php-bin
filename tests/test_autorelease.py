import contextlib
import hashlib
import http.client
import io
import json
import os
import pathlib
import re
import runpy
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

from autorelease.control import (
    ACTION_KEY_RE,
    EDGE_CACHE_BYPASS_PARAMETER,
    EVIDENCE_CAPTURE_IDS,
    EVIDENCE_SOURCES,
    RECIPE_INPUT_PATHS,
    ROOT,
    ControlError,
    EvidenceSource,
    _validate_plan_shape,
    action_filename,
    canonical_json,
    capture_evidence,
    due_recipe_rebuild,
    git,
    pending_recipe_rebuild,
    recipe_identity,
    recipe_identity_note,
    release_event_recorded,
    release_is_newest,
    release_recipe_identity,
    validate_recipe_rebuild_evidence,
    email_digest,
    email_fallback,
    evidence_sources,
    fetch_url,
    load_plan_evidence,
    PLAN_ACTIONS,
    PLAN_FIELDS,
    REQUIRED_PLAN_CHECKS,
    main as control_main,
    manifest_digest,
    mutation_allowed,
    route_watch_action,
    notification_decision,
    retained_notification_issue,
    release_transition,
    seal_patch,
    sha256_bytes,
    sha256_file,
    project_release_identity,
    strip_supported_versions_date_presentation,
    transition_event,
    validate_archive,
    validate_completed_event_record,
    validate_evidence_attestation_predicate,
    validate_evidence_state_record,
    validate_recaptured_evidence,
    validate_release_is_newest_patch,
    validate_stable_release_evidence,
    verify_merge,
    watch_decision,
    path_is_protected,
)


def full_plan(**fields) -> dict:
    """Return a plan with every reviewed field, overridden by `fields`."""
    return {
        "schemaVersion": 1,
        "actionKey": "no_change:" + "c" * 16,
        "action": "no_change",
        "evidence": [],
        "repositories": ["php-bin"],
        "preconditions": {},
        "editsRequired": False,
        "allowedPaths": {"php-bin": [], "mise-php": []},
        "requiredChecks": ["Script checks"],
        "releaseIntent": None,
        "notification": {"suggestedSeverity": "info", "summary": "Fixture.", "humanActionRequired": False},
        "risk": "routine",
        "summary": "Fixture.",
        **fields,
    }


def run_control(*argv: str) -> tuple[int, str]:
    """Run a control CLI subcommand exactly as a workflow would, capturing its output."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        status = control_main(list(argv))
    return status, out.getvalue().strip()


def evidence_manifest(digests: dict[str, str]) -> dict:
    """Build a healthy evidence manifest whose identity covers the given capture digests."""
    captures = [
        {"captureId": capture_id, "status": 200, "digest": digest} for capture_id, digest in digests.items()
    ]
    return {
        "schemaVersion": 1,
        "captures": captures,
        "manifestDigest": sha256_bytes(canonical_json(captures)),
    }


def supported_versions_page(today_x: str, today_label: str, ages: tuple[str, ...]) -> bytes:
    """Render the volatile shape of php.net/supported-versions.php for a capture date."""
    rows = "".join(
        f'\t\t\t\t\t<td>31 Dec 2025</td>\n'
        f'\t\t\t\t\t<td class="collapse-phone"><em>{age}</em></td>\n'
        for age in ages
    )
    return (
        "<table>\n"
        "\t\t\t\t\t<td>PHP 8.4</td>\n"
        f"{rows}"
        "</table>\n"
        "<svg>\n"
        "\t<!-- Today -->\n"
        '\t<g class="today">\n'
        f'\t\t\t\t<line x1="{today_x}" y1="24" x2="{today_x}" y2="204" />\n'
        f'\t\t<text x="{today_x}" y="223.2">\n'
        f"\t\t\tToday: {today_label}\t\t</text>\n"
        "\t</g>\n"
        "</svg>\n"
    ).encode()


class AutoreleaseControlTests(unittest.TestCase):
    def test_quiet_snapshot_does_not_wake_the_classifier(self):
        manifest = {"manifestDigest": "sha256:" + "a" * 64, "captures": [{"status": 200}]}
        decision = watch_decision(manifest, manifest, [], {"healthy": True})
        self.assertEqual("quiet", decision["trigger"])
        self.assertFalse(decision["classify"])

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

    def test_release_download_counter_churn_does_not_change_capture_identity(self):
        def releases(binary_count, checksum_count):
            return json.dumps(
                [
                    {
                        "tag_name": "8.5.9",
                        "immutable": True,
                        "assets": [
                            {"name": "php-8.5.9-cli-macos-aarch64.tar.gz", "download_count": binary_count},
                            {"name": "SHA256SUMS", "download_count": checksum_count},
                        ],
                    }
                ]
            ).encode()

        self.assertEqual(
            project_release_identity(releases(20, 9)),
            project_release_identity(releases(21, 10)),
        )
        self.assertNotEqual(
            project_release_identity(releases(20, 9)),
            project_release_identity(releases(20, 9).replace(b"8.5.9", b"8.5.10")),
        )
        for body in (b"<html>service unavailable</html>", b'{"message": "API rate limit exceeded"}'):
            self.assertEqual(body, project_release_identity(body))
        # Drafts are listed only to a token with push access, so the watcher and the
        # publish job's recapture digest the same list whether or not one exists.
        published = json.loads(releases(20, 9))
        draft = {"tag_name": "8.5.9-1", "draft": True, "assets": []}
        self.assertEqual(
            project_release_identity(canonical_json(published)),
            project_release_identity(canonical_json([draft, *published])),
        )
        self.assertNotEqual(
            project_release_identity(canonical_json(published)),
            project_release_identity(canonical_json([{**draft, "draft": False}, *published])),
        )

    def test_only_reviewed_sources_carry_identity_projections(self):
        projected = {
            source.capture_id
            for source in evidence_sources(["8.4", "8.5"])
            if source.normalize is not None
        }
        self.assertEqual(
            {"php_bin_releases", "mise_php_releases", "php_supported_versions"}, projected
        )

    def test_every_maintained_branch_has_its_own_release_feed_capture(self):
        # The aggregate feed names only the newest release of each major, which left
        # every older maintained branch without admissible evidence for a new patch.
        sources = evidence_sources(["8.2", "8.3", "8.4", "8.5"])
        ids = [source.capture_id for source in sources]
        self.assertEqual(
            [
                "php_supported_versions",
                "php_release_feed",
                "php_release_feed_8.2",
                "php_release_feed_8.3",
                "php_release_feed_8.4",
                "php_release_feed_8.5",
                *[source.capture_id for source in EVIDENCE_SOURCES[2:]],
            ],
            ids,
        )
        feeds = {source.capture_id: source for source in sources}
        self.assertEqual(
            "https://www.php.net/releases/index.php?json&version=8.4",
            feeds["php_release_feed_8.4"].url,
        )
        self.assertEqual(feeds["php_release_feed"].max_bytes, feeds["php_release_feed_8.4"].max_bytes)
        # The branch set follows the policy, so a new branch is captured with no code change.
        self.assertIn("php_release_feed_8.6", {s.capture_id for s in evidence_sources(["8.5", "8.6"])})
        self.assertEqual(list(EVIDENCE_SOURCES), list(evidence_sources([])))
        for branch in ("8", "8.4.1", "../8.4", ""):
            with self.assertRaises(ControlError, msg=branch):
                evidence_sources([branch])

    def test_capture_command_derives_branch_feeds_from_the_accepted_policy(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        branches = json.loads((root / "support-policy.json").read_text())["maintainedBranches"]
        with tempfile.TemporaryDirectory() as tmp, mock.patch(
            "autorelease.control.capture_evidence", return_value={}
        ) as capture:
            self.assertEqual(0, run_control("capture-evidence", "--output", tmp)[0])
        captured = [source.capture_id for source in capture.call_args.args[1]]
        self.assertEqual([f"php_release_feed_{branch}" for branch in branches], captured[2 : 2 + len(branches)])

    def test_every_php_net_source_bypasses_the_edge_cache(self):
        # php.net's CDN served a feed weeks stale to one runner and fresh to another,
        # so the watcher and the publish recapture disagreed about the same URL.
        for source in evidence_sources(["8.2", "8.3", "8.4", "8.5"]):
            php_net = source.url.startswith("https://www.php.net/")
            self.assertEqual(php_net, source.bypass_edge_cache, source.capture_id)
            fetched = [fetch_url(source) for _ in range(2)]
            if not php_net:
                self.assertEqual([source.url, source.url], fetched)
                continue
            separator = "&" if "?" in source.url else "?"
            for url in fetched:
                self.assertRegex(
                    url,
                    "^" + re.escape(f"{source.url}{separator}{EDGE_CACHE_BYPASS_PARAMETER}=") + "[0-9a-f]{32}$",
                )
            # A fixed value would become one more cached key, so every fetch differs.
            self.assertNotEqual(fetched[0], fetched[1])

    def test_capture_bypasses_the_cache_per_attempt_and_records_the_canonical_url(self):
        body = b'{"version": "8.3.35"}'
        response = mock.Mock(status=200, headers={})
        response.read.return_value = body
        opener = mock.MagicMock()
        opener.open.return_value.__enter__.return_value = response
        opener.open.side_effect = [
            OSError("edge reset"),
            opener.open.return_value,
            opener.open.return_value,
        ]
        canonical = "https://www.php.net/releases/index.php?json&version=8.3"
        bypassing = EvidenceSource("php_release_feed_8.3", canonical, 1_000_000, bypass_edge_cache=True)
        plain = EvidenceSource("php_release_feed_8.3", canonical, 1_000_000)
        with tempfile.TemporaryDirectory() as tmp, mock.patch(
            "autorelease._evidence.urllib.request.build_opener", return_value=opener
        ), mock.patch("autorelease._evidence.time.sleep"):
            bypassed = capture_evidence(pathlib.Path(tmp) / "a", [bypassing])
            direct = capture_evidence(pathlib.Path(tmp) / "b", [plain])
        requested = [call.args[0].full_url for call in opener.open.call_args_list]
        self.assertEqual(3, len(requested))
        # The retry is a new cache key too, and only the fetch carries the parameter.
        self.assertEqual(2, len(set(requested[:2])))
        self.assertTrue(all(url.startswith(canonical + f"&{EDGE_CACHE_BYPASS_PARAMETER}=") for url in requested[:2]))
        self.assertEqual(canonical, requested[2])
        self.assertEqual(canonical, bypassed["captures"][0]["url"])
        # Evidence identity covers the body alone, so the fetch address never moves it.
        self.assertEqual(direct["manifestDigest"], bypassed["manifestDigest"])

    def test_paginated_capture_reads_every_page_and_digests_the_same_identity(self):
        def release(tag, draft=False):
            return {"tag_name": tag, "draft": draft, "assets": [{"name": "a", "download_count": 3}]}

        def capture(pages, per_page=2, max_pages=None):
            responses = []
            for page in pages:
                response = mock.MagicMock(status=200, headers={"ETag": "first"})
                response.read.return_value = page if isinstance(page, bytes) else json.dumps(page).encode()
                context = mock.MagicMock()
                context.__enter__.return_value = response
                responses.append(context)
            opener = mock.MagicMock()
            opener.open.side_effect = responses
            source = EvidenceSource(
                "php_bin_releases",
                f"https://api.github.com/repos/bigpixelrocket/php-bin/releases?per_page={per_page}",
                1_000_000,
                normalize=project_release_identity,
                paginate=True,
            )
            patches = [mock.patch("autorelease._evidence.urllib.request.build_opener", return_value=opener)]
            if max_pages is not None:
                patches.append(mock.patch("autorelease._evidence.PAGINATED_CAPTURE_MAX_PAGES", max_pages))
            with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
                for patch in patches:
                    stack.enter_context(patch)
                manifest = capture_evidence(pathlib.Path(tmp), [source])
                entry = manifest["captures"][0]
                stored = (pathlib.Path(tmp) / entry["bodyPath"]).read_bytes()
            requested = [call.args[0].full_url for call in opener.open.call_args_list]
            return entry, stored, requested

        # Pages are read in order until a short one, and the items concatenate in order.
        entry, stored, requested = capture(
            [[release("8.5.9-2"), release("8.5.9-1")], [release("8.5.9"), release("8.4.26")], [release("8.3.35")]]
        )
        self.assertEqual(200, entry["status"])
        self.assertEqual("first", entry["etag"])
        self.assertEqual(["8.5.9-2", "8.5.9-1", "8.5.9", "8.4.26", "8.3.35"], [item["tag_name"] for item in json.loads(stored)])
        base = "https://api.github.com/repos/bigpixelrocket/php-bin/releases?per_page=2&page="
        self.assertEqual([base + "1", base + "2", base + "3"], requested)
        # A full last page is followed by one empty page, never assumed to be the end.
        _entry, exact, requested = capture([[release("8.5.9"), release("8.4.26")], []])
        self.assertEqual(2, len(requested))
        self.assertEqual(2, len(json.loads(exact)))
        # Page boundaries carry no identity: a token that also sees a draft reads the
        # same releases split differently and digests the same projection.
        with_draft, _stored, _requested = capture(
            [[release("8.5.10", draft=True), release("8.5.9")], [release("8.4.26")]]
        )
        without_draft, _stored, _requested = capture([[release("8.5.9"), release("8.4.26")], []])
        self.assertEqual(without_draft["digest"], with_draft["digest"])
        # A first page that is not a list is kept as it came, so the classifier blocks
        # on the unexpected shape instead of the capture guessing.
        entry, stored, requested = capture([b'{"message": "moved"}'])
        self.assertEqual((200, b'{"message": "moved"}', 1), (entry["status"], stored, len(requested)))
        # A later page that is not a list, or a list still full at the page limit,
        # fails the capture rather than truncating it.
        broken, _stored, _requested = capture([[release("8.5.9"), release("8.4.26")], b"{}"])
        self.assertEqual((0, "ControlError"), (broken["status"], broken["error"]))
        endless, _stored, requested = capture(
            [[release("8.5.9"), release("8.4.26")], [release("8.3.35"), release("8.2.34")]], max_pages=2
        )
        self.assertEqual((0, "ControlError", 2), (endless["status"], endless["error"], len(requested)))
        # Both releases lists are paginated; the php-src tags list, which no rule
        # reads, stays one page.
        registry = {source.capture_id: source for source in EVIDENCE_SOURCES}
        self.assertTrue(registry["php_bin_releases"].paginate)
        self.assertTrue(registry["mise_php_releases"].paginate)
        self.assertFalse(registry["php_source_tags"].paginate)

    def test_capture_fails_when_the_edge_serves_a_bypassing_fetch_from_cache(self):
        # A unique key cannot be a genuine hit, so a HIT means the CDN now ignores the
        # parameter; the capture must fail loudly rather than go stale silently.
        def capture(source, cache_status):
            headers = http.client.HTTPMessage()
            if cache_status is not None:
                headers["cdn-cache"] = cache_status
            response = mock.Mock(status=200, headers=headers)
            response.read.return_value = b'{"version": "8.3.35"}'
            opener = mock.MagicMock()
            opener.open.return_value.__enter__.return_value = response
            with tempfile.TemporaryDirectory() as tmp, mock.patch(
                "autorelease._evidence.urllib.request.build_opener", return_value=opener
            ), mock.patch("autorelease._evidence.time.sleep"):
                manifest = capture_evidence(pathlib.Path(tmp), [source])
            return manifest["captures"][0], opener.open.call_count

        canonical = "https://www.php.net/releases/index.php?json&version=8.3"
        bypassing = EvidenceSource("php_release_feed_8.3", canonical, 1_000_000, bypass_edge_cache=True)
        plain = EvidenceSource("php_release_feed_8.3", canonical, 1_000_000)
        failed, attempts = capture(bypassing, "HIT")
        self.assertEqual((0, "EdgeCacheHit", sha256_bytes(b"")), (failed["status"], failed["error"], failed["digest"]))
        # A HIT on a fresh key is configuration, not a transient failure: no retry.
        self.assertEqual(1, attempts)
        for source, cache_status in ((bypassing, "MISS"), (bypassing, None), (plain, "HIT")):
            healthy, _attempts = capture(source, cache_status)
            self.assertEqual(200, healthy["status"], (source.bypass_edge_cache, cache_status))
            self.assertNotIn("error", healthy)
            # The cache result is kept for diagnosis but never enters evidence identity.
            self.assertEqual(cache_status, healthy["edgeCache"])

    def test_supported_versions_date_churn_does_not_change_capture_identity(self):
        adjacent = (
            supported_versions_page("514.34454057606", "15 Aug 2026", ("7 months ago",)),
            supported_versions_page("515.33019384514", "18 Aug 2026", ("7 months, 3 days ago",)),
        )
        self.assertEqual(
            strip_supported_versions_date_presentation(adjacent[0]),
            strip_supported_versions_date_presentation(adjacent[1]),
        )
        self.assertNotEqual(
            strip_supported_versions_date_presentation(adjacent[0]),
            strip_supported_versions_date_presentation(
                adjacent[0].replace(b"31 Dec 2025", b"31 Dec 2026")
            ),
        )
        self.assertNotEqual(
            strip_supported_versions_date_presentation(adjacent[0]),
            strip_supported_versions_date_presentation(
                adjacent[0].replace(b"PHP 8.4", b"PHP 8.5")
            ),
        )
        for body in (b"<html>service unavailable</html>", b'{"message": "API rate limit exceeded"}'):
            self.assertEqual(body, strip_supported_versions_date_presentation(body))

    def test_adjacent_date_captures_keep_the_watcher_quiet(self):
        def capture(body):
            response = mock.Mock(status=200, headers={})
            response.read.return_value = body
            opener = mock.MagicMock()
            opener.open.return_value.__enter__.return_value = response
            source = EvidenceSource(
                "php_supported_versions",
                "https://www.php.net/supported-versions.php",
                1_000_000,
                normalize=strip_supported_versions_date_presentation,
            )
            with tempfile.TemporaryDirectory() as tmp:
                with mock.patch("autorelease._evidence.urllib.request.build_opener", return_value=opener):
                    return capture_evidence(pathlib.Path(tmp), [source])

        yesterday = capture(supported_versions_page("514.34454057606", "15 Aug 2026", ("7 months ago",)))
        today = capture(supported_versions_page("515.33019384514", "18 Aug 2026", ("7 months, 3 days ago",)))
        self.assertEqual(yesterday["manifestDigest"], today["manifestDigest"])
        decision = watch_decision(today, yesterday, [], {"healthy": True})
        self.assertEqual("quiet", decision["trigger"])
        self.assertFalse(decision["classify"])

    def test_capture_digests_the_projected_body_and_retains_unprojected_bytes(self):
        body = json.dumps(
            [{"tag_name": "8.5.9", "assets": [{"name": "a.tar.gz", "download_count": 20}]}]
        ).encode()
        response = mock.Mock(status=200, headers={})
        response.read.return_value = body
        opener = mock.MagicMock()
        opener.open.return_value.__enter__.return_value = response
        source = EvidenceSource(
            "php_bin_releases",
            "https://api.github.com/repos/bigpixelrocket/php-bin/releases?per_page=100",
            1_000_000,
            normalize=project_release_identity,
        )
        with tempfile.TemporaryDirectory() as tmp:
            output = pathlib.Path(tmp)
            with mock.patch("autorelease._evidence.urllib.request.build_opener", return_value=opener):
                manifest = capture_evidence(output, [source])
            capture = manifest["captures"][0]
            stored = (output / capture["bodyPath"]).read_bytes()
            self.assertEqual(sha256_bytes(stored), capture["digest"])
            self.assertNotIn(b"download_count", stored)
            self.assertEqual(body, (output / "raw/php_bin_releases.body.raw").read_bytes())
            response.read.return_value = stored
            with mock.patch("autorelease._evidence.urllib.request.build_opener", return_value=opener):
                capture_evidence(output, [source])
            self.assertFalse((output / "raw/php_bin_releases.body.raw").exists())

    def test_no_change_plan_cannot_authorize_edits_paths_or_releases(self):
        plan = full_plan(
            editsRequired=True,
            allowedPaths={"php-bin": ["autorelease-state/last-evidence.json"], "mise-php": []},
        )
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = pathlib.Path(tmp) / "evidence-manifest.json"
            manifest_path.write_bytes(canonical_json({"manifestDigest": "sha256:" + "c" * 64}))
            with self.assertRaisesRegex(ControlError, "no-change plan cannot require edits"):
                _validate_plan_shape(plan, manifest_path, set())
            plan["editsRequired"] = False
            with self.assertRaisesRegex(ControlError, "no-change plan cannot allow paths"):
                _validate_plan_shape(plan, manifest_path, set())
            plan["allowedPaths"] = {"php-bin": [], "mise-php": []}
            plan["releaseIntent"] = {"version": "8.5.9", "sourceIdentifier": "php_release_feed"}
            with self.assertRaisesRegex(ControlError, "no-change plan cannot request a release"):
                _validate_plan_shape(plan, manifest_path, set())
            plan["releaseIntent"] = None
            self.assertEqual("no_change:" + "c" * 16, _validate_plan_shape(plan, manifest_path, set()))

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
        self.assertFalse(decision["classify"])

        # A changed snapshot would otherwise select new work; the missing record wins the
        # trigger, but recovery never withholds the classification those paths depend on,
        # so a repair that stays blocked cannot starve them run after run.
        changed = {"manifestDigest": "sha256:" + "c" * 64, "captures": manifest["captures"]}
        moved = watch_decision(changed, manifest, events, {"healthy": True}, releases=releases)
        self.assertEqual("record_completed_event", moved["action"])
        self.assertTrue(moved["classify"])
        incomplete = watch_decision(
            manifest,
            manifest,
            [*events, {"actionKey": "new_patch:8.5.7", "state": "released"}],
            {"healthy": True},
            releases=releases,
        )
        self.assertEqual("record_completed_event", incomplete["action"])
        self.assertTrue(incomplete["classify"])
        self.assertEqual(["new_patch:8.5.7"], incomplete["incompleteActions"])

        rebuild = watch_decision(
            manifest,
            manifest,
            [*events, {"actionKey": "new_patch:8.5.9", "state": "complete"}],
            {"healthy": True},
            releases=[*releases, {"tag_name": "8.5.9-2", "draft": False, "prerelease": False, "immutable": True}],
        )
        self.assertEqual("recipe_rebuild:8.5.9:2", rebuild["actionKey"])
        # A revision makes a zero patch unambiguous; the plain `8.6.0` stays unrecoverable.
        branch_rebuild = watch_decision(
            manifest,
            manifest,
            [*events, {"actionKey": "new_patch:8.5.9", "state": "complete"}],
            {"healthy": True},
            releases=[*releases, {"tag_name": "8.6.0-1", "draft": False, "prerelease": False, "immutable": True}],
        )
        self.assertEqual("recipe_rebuild:8.6.0:1", branch_rebuild["actionKey"])

    @staticmethod
    def _published(tag, identity=None, **fields):
        body = "Autorelease publication." + (f"\n\n{recipe_identity_note(identity)}" if identity else "")
        return {"tag_name": tag, "draft": False, "prerelease": False, "immutable": True, "body": body, **fields}

    def test_recipe_identity_covers_only_committed_recipe_inputs_of_its_branch(self):
        def commit(repo, files, message):
            for name, text in files.items():
                (repo / name).parent.mkdir(parents=True, exist_ok=True)
                (repo / name).write_text(text)
            subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-q", "-m", message], cwd=repo, check=True)
            return git(repo, "rev-parse", "HEAD").stdout.strip()

        with tempfile.TemporaryDirectory() as temporary:
            repo = pathlib.Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Fixture"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "fixture@invalid"], cwd=repo, check=True)
            base = commit(
                repo,
                {
                    "stages/s4.txt": "redis\n",
                    "scripts/build.sh": "build\n",
                    "expected-modules/8.4.txt": "Core\n",
                    "expected-modules/8.5.txt": "Core\n",
                    "NOTICE": "notice\n",
                    "README.md": "readme\n",
                },
                "recipe",
            )
            identity = recipe_identity(repo, base, "8.5")
            # Unrelated paths and uncommitted build output never change the identity.
            docs = commit(repo, {"README.md": "changed\n"}, "docs")
            (repo / "stages/s4.txt").write_text("dirty working tree\n")
            self.assertEqual(identity, recipe_identity(repo, docs, "8.5"))
            subprocess.run(["git", "checkout", "-q", "--", "stages/s4.txt"], cwd=repo, check=True)
            # Another branch's module list, or a new branch, leaves this branch's identity alone.
            other = commit(repo, {"expected-modules/8.4.txt": "Core\nredis\n", "expected-modules/8.6.txt": "Core\n"}, "other branches")
            self.assertEqual(identity, recipe_identity(repo, other, "8.5"))
            self.assertNotEqual(recipe_identity(repo, base, "8.4"), recipe_identity(repo, other, "8.4"))
            own = commit(repo, {"expected-modules/8.5.txt": "Core\nredis\n"}, "own modules")
            self.assertNotEqual(identity, recipe_identity(repo, own, "8.5"))
            # Shared inputs, including the files copied into every archive, change every branch.
            notice = commit(repo, {"NOTICE": "changed notice\n"}, "notice")
            self.assertNotEqual(recipe_identity(repo, own, "8.4"), recipe_identity(repo, notice, "8.4"))
            recipe = commit(repo, {"stages/s4.txt": "redis\nyaml\n"}, "recipe change")
            self.assertNotEqual(recipe_identity(repo, notice, "8.5"), recipe_identity(repo, recipe, "8.5"))
            self.assertEqual(identity, recipe_identity(repo, base, "8.5"))
            with self.assertRaisesRegex(ControlError, "exact commit SHA"):
                recipe_identity(repo, "HEAD", "8.5")
            with self.assertRaisesRegex(ControlError, "recipe branch is invalid"):
                recipe_identity(repo, base, "8.5/../..")
        for path in (".spc-sha256", ".spc-version", "LICENSE", "NOTICE", "stages", "scripts/install-spc.sh"):
            self.assertIn(path, RECIPE_INPUT_PATHS)
        # Each branch covers only its own module list, never the whole directory.
        self.assertNotIn("expected-modules", RECIPE_INPUT_PATHS)

    def test_recipe_identity_note_round_trips_through_release_notes(self):
        identity = "sha256:" + "a" * 64
        notes = "Autorelease publication.\n\n" + recipe_identity_note(identity)
        self.assertEqual(identity, release_recipe_identity({"body": notes}))
        # Notes saved from the GitHub web interface use CRLF line endings.
        self.assertEqual(identity, release_recipe_identity({"body": notes.replace("\n", "\r\n") + "\r\n"}))
        for body in (None, "", "Autorelease publication.", "Recipe identity: sha256:short", 7):
            self.assertIsNone(release_recipe_identity({"body": body}), body)
        with self.assertRaises(ControlError):
            recipe_identity_note("sha256:short")
    def test_publisher_records_the_recipe_identity_on_new_and_resumed_drafts(self):
        namespace = runpy.run_path(
            str(pathlib.Path(__file__).resolve().parents[1] / "scripts/publish-release"),
            run_name="publish_release_fixture",
        )
        github_effect = namespace["github_effect"]
        identity = "sha256:" + "a" * 64
        commit = "c" * 40
        tag_ref = json.dumps({"object": {"type": "commit", "sha": commit}})

        def effect(existing):
            calls = []

            def gh(*arguments, capture=True):
                calls.append(arguments)
                return ""

            def run(argv, **_kwargs):
                if argv[:3] == ["gh", "api", "repos/o/r/git/ref/tags/8.5.9-1"]:
                    return mock.Mock(returncode=0, stdout=tag_ref)
                if existing is None:
                    return mock.Mock(returncode=1, stdout="")
                return mock.Mock(returncode=0, stdout=json.dumps(existing))

            with mock.patch.dict(
                github_effect.__globals__,
                {"gh": gh, "recipe_identity": lambda root, sha, branch: identity if branch == "8.5" else None},
            ), mock.patch.object(github_effect.__globals__["subprocess"], "run", side_effect=run):
                github_effect("draft_created", "o/r", "8.5.9-1", commit, pathlib.Path("assets"), {"SHA256SUMS": identity})
            return calls

        created = effect(None)
        self.assertEqual("create", created[0][1])
        self.assertIn(recipe_identity_note(identity), created[0][created[0].index("--notes") + 1])
        # A draft left by an earlier attempt without the identity gains it before publication.
        edited = effect({"isDraft": True, "body": "Autorelease publication."})
        self.assertEqual(("release", "edit", "8.5.9-1"), edited[0][:3])
        self.assertIn(recipe_identity_note(identity), edited[0][edited[0].index("--notes") + 1])
        self.assertEqual([], effect({"isDraft": True, "body": recipe_identity_note(identity)}))
        # A published release is immutable and is never edited.
        self.assertEqual([], effect({"isDraft": False, "body": "Autorelease publication."}))

    def test_release_is_newest_compares_versions_numerically_with_revisions(self):
        published = [self._published(tag) for tag in ("8.5.11", "8.5.11-2", "8.4.26-1", "8.2.32-2")]
        # A rebuild of the newest version sorts above its plain patch and earlier revisions.
        self.assertTrue(release_is_newest("8.5.11-3", published))
        # Any older version, including a newer revision of an older branch, is not newest.
        for version in ("8.2.32-3", "8.4.26-2", "8.5.10-3", "8.5.11-1", "8.5.11"):
            self.assertFalse(release_is_newest(version, published), version)
        # Components compare as numbers, never as text.
        self.assertTrue(release_is_newest("8.10.0", [self._published("8.9.9-4")]))
        self.assertFalse(release_is_newest("8.9.9-4", [self._published("8.10.0")]))
        self.assertTrue(release_is_newest("8.5.12", [self._published("8.5.9-9")]))
        # Drafts, prereleases, unrelated tags, and the version itself never outrank it.
        ignored = [
            self._published("9.0.0", draft=True),
            self._published("9.0.1", prerelease=True),
            self._published("v99"),
            self._published("8.5.11-3"),
            "not a release",
        ]
        self.assertTrue(release_is_newest("8.5.11-3", ignored))
        self.assertTrue(release_is_newest("8.5.11-3", []))
        with self.assertRaises(ControlError):
            release_is_newest("latest", published)

    def test_publisher_states_whether_the_publication_is_latest(self):
        namespace = runpy.run_path(
            str(pathlib.Path(__file__).resolve().parents[1] / "scripts/publish-release"),
            run_name="publish_release_fixture",
        )
        github_effect = namespace["github_effect"]
        pages = json.dumps([[self._published("8.5.11-2"), self._published("8.4.26-1")], [self._published("8.2.32-2")]])

        def publish(version, is_draft=True):
            calls = []

            def gh(*arguments, capture=True):
                calls.append(arguments)
                if arguments[:2] == ("release", "view"):
                    return json.dumps({"isDraft": is_draft, "databaseId": 42})
                if arguments[:2] == ("api", "repos/o/r/releases?per_page=100"):
                    return pages
                return ""

            with mock.patch.dict(github_effect.__globals__, {"gh": gh}):
                github_effect("published", "o/r", version, "c" * 40, pathlib.Path("assets"), {})
            return [call for call in calls if "PATCH" in call]

        for version, latest in (("8.5.11-3", "true"), ("8.2.32-3", "false"), ("8.4.27", "false"), ("8.6.0", "true")):
            self.assertEqual(
                [("api", "--method", "PATCH", "repos/o/r/releases/42", "-F", "draft=false", "-f", f"make_latest={latest}")],
                publish(version),
                version,
            )
        # A release that is already public is immutable here, and its badge is left alone.
        self.assertEqual([], publish("8.5.11-3", is_draft=False))

    def test_rebuild_selection_is_deterministic_and_covers_every_published_version(self):
        current = "sha256:" + "c" * 64
        # The releases published before recipe identities existed record none.
        releases = [
            self._published(tag)
            for tag in ("8.5.11", "8.5.10", "8.5.9", "8.5.8", "8.4.23", "8.3.32", "8.2.32")
        ]
        maintained = ["8.2", "8.3", "8.4", "8.5"]
        order = []
        while key := pending_recipe_rebuild(releases, dict.fromkeys(maintained, current)):
            order.append(key)
            _prefix, version, revision = key.split(":")
            releases.append(self._published(f"{version}-{revision}", current))
            self.assertLess(len(order), 10, "selection never converged")
        # Each branch's newest version first, since branch shorthand resolves to it.
        self.assertEqual(
            [
                "recipe_rebuild:8.5.11:1",
                "recipe_rebuild:8.4.23:1",
                "recipe_rebuild:8.3.32:1",
                "recipe_rebuild:8.2.32:1",
                "recipe_rebuild:8.5.10:1",
                "recipe_rebuild:8.5.9:1",
                "recipe_rebuild:8.5.8:1",
            ],
            order,
        )
        # A later recipe change makes the newest revision due again, one revision on.
        changed = "sha256:" + "d" * 64
        self.assertEqual("recipe_rebuild:8.5.11:2", pending_recipe_rebuild(releases, dict.fromkeys(maintained, changed)))
        # A change to one branch's recipe rebuilds only that branch.
        self.assertEqual(
            "recipe_rebuild:8.4.23:2",
            pending_recipe_rebuild(releases, {**dict.fromkeys(maintained, current), "8.4": changed}),
        )
        # A patch published by the current recipe needs no rebuild.
        fresh = [self._published("8.4.26", current), self._published("8.4.23")]
        self.assertEqual("recipe_rebuild:8.4.23:1", pending_recipe_rebuild(fresh, {"8.4": current}))
        self.assertIsNone(pending_recipe_rebuild(fresh[:1], {"8.4": current}))
        # Drafts and prereleases never count: a rebuild whose draft a failed transaction
        # left behind is selected again, and the transaction resumes that draft.
        draft = [self._published("8.4.26", current), self._published("8.4.23"), self._published("8.4.23-1", current, draft=True)]
        self.assertEqual("recipe_rebuild:8.4.23:1", pending_recipe_rebuild(draft, {"8.4": current}))
        prerelease = [self._published("8.4.23-1", current, prerelease=True), self._published("8.4.23")]
        self.assertEqual("recipe_rebuild:8.4.23:1", pending_recipe_rebuild(prerelease, {"8.4": current}))
        # An EOL branch keeps its releases exactly as published.
        self.assertIsNone(pending_recipe_rebuild([self._published("8.1.33")], dict.fromkeys(maintained, current)))
        for malformed in ("8.5.9-0", "8.5.9-rc1", "v8.5.9", "8.5"):
            self.assertIsNone(pending_recipe_rebuild([self._published(malformed)], dict.fromkeys(maintained, current)))
        with self.assertRaises(ControlError):
            pending_recipe_rebuild(releases, dict.fromkeys(maintained, "sha256:short"))

    def test_due_rebuild_keeps_the_watcher_awake_until_it_is_published(self):
        manifest = self._releases_manifest()
        current = "sha256:" + "c" * 64
        releases = [self._published("8.5.11"), self._published("8.4.26", current)]
        events = [{"actionKey": "new_patch:8.5.11", "state": "complete"}, {"actionKey": "new_patch:8.4.26", "state": "complete"}]
        decision = watch_decision(
            manifest, manifest, events, {"healthy": True},
            releases=releases, recipe_identities=dict.fromkeys(["8.4", "8.5"], current),
        )
        self.assertEqual("rebuild_due", decision["trigger"])
        self.assertTrue(decision["classify"])
        self.assertEqual("recipe_rebuild:8.5.11:1", decision["rebuildActionKey"])
        self.assertEqual("none", decision["action"])
        # Recording a no_change snapshot is exactly the self-update that would otherwise
        # be quiet; a pending rebuild still wakes the model.
        self_update = watch_decision(
            manifest, manifest, events, {"healthy": True}, self_evidence_update=True,
            releases=releases, recipe_identities=dict.fromkeys(["8.4", "8.5"], current),
        )
        self.assertEqual("rebuild_due", self_update["trigger"])
        # Changed evidence keeps its own trigger and still reports the rebuild.
        moved = watch_decision(
            {**manifest, "manifestDigest": "sha256:" + "e" * 64}, manifest, events, {"healthy": True},
            releases=releases, recipe_identities=dict.fromkeys(["8.4", "8.5"], current),
        )
        self.assertEqual(("evidence_changed", "recipe_rebuild:8.5.11:1"), (moved["trigger"], moved["rebuildActionKey"]))
        published = [*releases, self._published("8.5.11-1", current)]
        quiet = watch_decision(
            manifest, manifest, [*events, {"actionKey": "recipe_rebuild:8.5.11:1", "state": "complete"}],
            {"healthy": True}, releases=published, recipe_identities=dict.fromkeys(["8.4", "8.5"], current),
        )
        self.assertEqual(("quiet", False, ""), (quiet["trigger"], quiet["classify"], quiet["rebuildActionKey"]))
        unhealthy = self._releases_manifest(status=500)
        self.assertEqual(
            "",
            watch_decision(
                unhealthy, unhealthy, events, {"healthy": True},
                releases=releases, recipe_identities={"8.5": current},
            )["rebuildActionKey"],
        )

    def test_rebuild_admission_binds_the_deterministic_selection(self):
        key = "recipe_rebuild:8.5.9:2"
        plan = full_plan(
            action="recipe_rebuild",
            actionKey=key,
            releaseIntent={"version": "8.5.9-2", "sourceIdentifier": "php_bin_releases"},
        )
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = pathlib.Path(tmp) / "evidence-manifest.json"
            manifest_path.write_bytes(canonical_json({"manifestDigest": "sha256:" + "c" * 64}))
            self.assertEqual(key, _validate_plan_shape(plan, manifest_path, set(), key))
            for pending in (None, "recipe_rebuild:8.5.9:3", "recipe_rebuild:8.5.10:1"):
                with self.assertRaisesRegex(ControlError, "not the selected rebuild", msg=pending):
                    _validate_plan_shape(plan, manifest_path, set(), pending)
            for field, value, message in (
                ("editsRequired", True, "cannot require edits"),
                ("allowedPaths", {"php-bin": ["stages/s4.txt"], "mise-php": []}, "cannot allow paths"),
                ("releaseIntent", {"version": "8.5.9", "sourceIdentifier": "x"}, "not the selected revision"),
                ("releaseIntent", None, "not the selected revision"),
            ):
                with self.assertRaisesRegex(ControlError, message, msg=field):
                    _validate_plan_shape({**plan, field: value}, manifest_path, set(), key)
            with self.assertRaisesRegex(ControlError, "already completed"):
                _validate_plan_shape(plan, manifest_path, {key}, key)
            # A pending rebuild can never be silenced by recording the evidence unchanged.
            no_change = full_plan()
            self.assertEqual(no_change["actionKey"], _validate_plan_shape(no_change, manifest_path, set(), None))
            with self.assertRaisesRegex(ControlError, "due rebuild pending"):
                _validate_plan_shape(no_change, manifest_path, set(), key)

    def test_rebuild_cites_the_release_it_supersedes(self):
        validate_recipe_rebuild_evidence(
            "recipe_rebuild", "recipe_rebuild:8.5.9:1", [{"captureId": "php_bin_releases", "value": "8.5.9"}]
        )
        validate_recipe_rebuild_evidence(
            "recipe_rebuild", "recipe_rebuild:8.5.9:3", [{"captureId": "php_bin_releases", "value": "8.5.9-2"}]
        )
        for evidence in (
            [{"captureId": "php_bin_releases", "value": "8.5.9"}],
            [{"captureId": "php_bin_releases", "value": "8.5.9-1"}],
            [{"captureId": "php_release_feed", "value": "8.5.9-2"}],
        ):
            with self.assertRaisesRegex(ControlError, "supersedes", msg=evidence):
                validate_recipe_rebuild_evidence("recipe_rebuild", "recipe_rebuild:8.5.9:3", evidence)
        validate_recipe_rebuild_evidence("new_patch", "new_patch:8.5.9", [])

    def test_admission_re_derives_the_rebuild_from_the_capture_and_recipe_commit(self):
        head = git(ROOT, "rev-parse", "HEAD").stdout.strip()
        branch = json.loads((ROOT / "support-policy.json").read_text())["maintainedBranches"][-1]
        identity = recipe_identity(ROOT, head, branch)
        releases = [self._published(f"{branch}.2", identity), self._published(f"{branch}.1")]
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "raw").mkdir()
            body = canonical_json(releases)
            (root / "raw/php_bin_releases.body").write_bytes(body)
            manifest_path = root / "evidence-manifest.json"
            capture = {"captureId": "php_bin_releases", "status": 200, "digest": sha256_bytes(body), "bodyPath": "raw/php_bin_releases.body"}
            manifest_path.write_bytes(canonical_json({"schemaVersion": 1, "captures": [capture]}))
            self.assertEqual(f"recipe_rebuild:{branch}.1:1", due_recipe_rebuild(manifest_path, ROOT, head))
            manifest_path.write_bytes(canonical_json({"schemaVersion": 1, "captures": [{**capture, "status": 500}]}))
            self.assertIsNone(due_recipe_rebuild(manifest_path, ROOT, head))
            # Like the watcher, admission selects nothing while any other source is unhealthy.
            other = {"captureId": "php_release_feed", "status": 503, "digest": sha256_bytes(b""), "bodyPath": "raw/feed.body"}
            manifest_path.write_bytes(canonical_json({"schemaVersion": 1, "captures": [capture, other]}))
            self.assertIsNone(due_recipe_rebuild(manifest_path, ROOT, head))

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

    def test_plan_shape_is_exact_and_only_lifecycle_plans_edit(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = pathlib.Path(tmp) / "evidence-manifest.json"
            manifest_path.write_bytes(canonical_json({"manifestDigest": "sha256:" + "c" * 64}))
            self.assertEqual("no_change:" + "c" * 16, _validate_plan_shape(full_plan(), manifest_path, set()))
            # Fields the model-era schema carried are unknown now, and none may be missing.
            with self.assertRaisesRegex(ControlError, "fields are unknown or missing"):
                _validate_plan_shape({**full_plan(), "budgets": {}}, manifest_path, set())
            incomplete = full_plan()
            del incomplete["summary"]
            with self.assertRaisesRegex(ControlError, "fields are unknown or missing"):
                _validate_plan_shape(incomplete, manifest_path, set())
            for retired in ("repair", "reconcile_partial"):
                with self.assertRaisesRegex(ControlError, "invalid autorelease action", msg=retired):
                    _validate_plan_shape(full_plan(action=retired), manifest_path, set())
            # A plan that stops the run authorizes nothing.
            for field, value in (
                ("editsRequired", True),
                ("allowedPaths", {"php-bin": ["support-policy.json"], "mise-php": []}),
                ("releaseIntent", {"version": "8.5.9", "sourceIdentifier": "php_release_feed"}),
            ):
                with self.assertRaisesRegex(ControlError, "blocked plan cannot", msg=field):
                    _validate_plan_shape(
                        full_plan(action="blocked", actionKey="source_unhealthy:" + "d" * 16, **{field: value}),
                        manifest_path,
                        set(),
                    )
            with self.assertRaisesRegex(ControlError, "does not match its action"):
                _validate_plan_shape(
                    full_plan(action="new_patch", actionKey="new_branch:8.6"), manifest_path, set()
                )

    def test_admin_evidence_names_each_snapshot_by_its_own_digest(self):
        evidence = json.loads((ROOT / "docs/autorelease-admin-evidence.json").read_text())
        snapshots = [
            entry
            for repository in evidence["repositories"].values()
            for entry in (repository["beforeSnapshot"], repository["afterSnapshot"])
        ]
        self.assertEqual(4, len(snapshots))
        for entry in snapshots:
            self.assertRegex(entry["digest"], r"^sha256:[0-9a-f]{64}$", entry["path"])
            # mise-php's snapshots live in that repository; this one can check its own.
            if entry["path"].startswith("../"):
                continue
            snapshot = json.loads((ROOT / entry["path"]).read_text())
            recorded = snapshot.pop("snapshotDigest")
            self.assertEqual(recorded, sha256_bytes(canonical_json(snapshot)), entry["path"])
            self.assertEqual(recorded, entry["digest"], entry["path"])

    def test_plan_schema_matches_admission(self):
        schema = json.loads((ROOT / "schemas/autorelease-plan.schema.json").read_text())
        self.assertEqual(set(schema["required"]), set(schema["properties"]))
        self.assertEqual(PLAN_FIELDS, set(schema["required"]))
        self.assertEqual(ACTION_KEY_RE.pattern, schema["properties"]["actionKey"]["pattern"])
        self.assertEqual(sorted(PLAN_ACTIONS), sorted(schema["properties"]["action"]["enum"]))
        self.assertEqual(REQUIRED_PLAN_CHECKS, schema["properties"]["requiredChecks"]["items"]["enum"])

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
        # A record carries one feed per branch the policy maintained when it was taken,
        # so records from before and after a branch change both stay readable.
        branch_feeds = [
            {"captureId": f"php_release_feed_{branch}", "digest": "sha256:" + "d" * 64, "status": 200}
            for branch in ("8.4", "8.5")
        ]
        validate_evidence_state_record({**record, "captures": [*record["captures"], *branch_feeds]})
        for unknown in ("php_release_feed_8", "php_release_feed_8.4.1", "php_release_feed_latest"):
            with self.assertRaisesRegex(ControlError, "capture set changed", msg=unknown):
                validate_evidence_state_record(
                    {**record, "captures": [*record["captures"], {**branch_feeds[0], "captureId": unknown}]}
                )
        with self.assertRaisesRegex(ControlError, "duplicate"):
            validate_evidence_state_record(
                {**record, "captures": [*record["captures"], branch_feeds[0], branch_feeds[0]]}
            )
        with self.assertRaisesRegex(ControlError, "capture set changed"):
            validate_evidence_state_record({**record, "captures": [*record["captures"][1:], *branch_feeds]})
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

    def test_older_branch_patch_is_admitted_from_its_own_branch_feed(self):
        # php.net's aggregate feed only ever named 8.5.x for major 8, so 8.4, 8.3, and
        # 8.2 patches could never publish. Each branch feed proves its own branch alone.
        intent = {"version": "8.4.26", "sourceIdentifier": "php_release_feed_8.4"}
        aggregate = {"captureId": "php_release_feed", "value": "8.5.11"}
        with self.assertRaisesRegex(ControlError, "official PHP release feed"):
            validate_stable_release_evidence("new_patch", intent, [aggregate])
        validate_stable_release_evidence(
            "new_patch", intent, [aggregate, {"captureId": "php_release_feed_8.4", "value": "8.4.26"}]
        )
        for wrong in (
            {"captureId": "php_release_feed_8.3", "value": "8.4.26"},
            {"captureId": "php_release_feed_8.4", "value": "8.4.25"},
            {"captureId": "php_source_tags", "value": "8.4.26"},
        ):
            with self.assertRaisesRegex(ControlError, "official PHP release feed", msg=wrong):
                validate_stable_release_evidence("new_patch", intent, [wrong])
        validate_stable_release_evidence(
            "new_branch",
            {"version": "8.6.0", "sourceIdentifier": "php_release_feed"},
            [{"captureId": "php_release_feed", "value": "8.6.0"}],
        )

    def test_superseded_intermediate_patch_is_rejected(self):
        # A stale feed snapshot named 8.2.33 as newest and admission accepted it, so a
        # capture showing any later patch on the branch must stop the plan.
        def admit(version, feeds, action="new_patch", status=200):
            with tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp)
                (root / "raw").mkdir()
                captures = []
                for capture_id, body in feeds.items():
                    (root / "raw" / f"{capture_id}.body").write_bytes(body)
                    captures.append(
                        {
                            "captureId": capture_id,
                            "status": status,
                            "digest": sha256_bytes(body),
                            "bodyPath": f"raw/{capture_id}.body",
                        }
                    )
                manifest_path = root / "evidence-manifest.json"
                manifest_path.write_bytes(canonical_json({"schemaVersion": 1, "captures": captures}))
                validate_release_is_newest_patch(action, {"version": version}, manifest_path)

        def feed(version):
            return canonical_json({"version": version})

        aggregate = canonical_json({"8": {"version": "8.5.11"}, "7": {"version": "7.4.33"}})
        with self.assertRaisesRegex(ControlError, "8.2.33 is superseded by 8.2.34 in php_release_feed_8.2"):
            admit("8.2.33", {"php_release_feed": aggregate, "php_release_feed_8.2": feed("8.2.34")})
        admit("8.2.34", {"php_release_feed": aggregate, "php_release_feed_8.2": feed("8.2.34")})
        # Patches compare as numbers, not strings.
        admit("8.2.10", {"php_release_feed_8.2": feed("8.2.9")})
        with self.assertRaisesRegex(ControlError, "superseded by 8.2.10"):
            admit("8.2.9", {"php_release_feed_8.2": feed("8.2.10")})
        # The aggregate feed supersedes too, even when the branch feed is stale.
        with self.assertRaisesRegex(ControlError, "superseded by 8.5.11 in php_release_feed$"):
            admit("8.5.10", {"php_release_feed": aggregate, "php_release_feed_8.5": feed("8.5.10")})
        with self.assertRaisesRegex(ControlError, "8.6.0 is superseded by 8.6.1"):
            admit("8.6.0", {"php_release_feed": canonical_json({"8": {"version": "8.6.1"}})}, "new_branch")
        # Another branch's newer release, a php-src tag, or an unreadable or unhealthy
        # feed is not evidence that this branch moved on.
        admit("8.4.26", {"php_release_feed": aggregate, "php_release_feed_8.4": feed("8.4.26")})
        admit(
            "8.2.34",
            {
                "php_release_feed_8.2": feed("8.2.34"),
                "php_release_feed_8.3": feed("8.2.99"),
                "php_source_tags": canonical_json([{"name": "php-8.2.35"}]),
            },
        )
        admit("8.2.33", {"php_release_feed_8.2": b"<html>busy</html>"})
        admit("8.2.33", {"php_release_feed_8.2": feed("8.2.34")}, status=503)
        admit("8.2.33", {"php_release_feed_8.2": feed("8.2.34")}, action="recipe_rebuild")

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

        def with_captures(extra):
            items = [*captures, *extra]
            return {
                "schemaVersion": 1,
                "captures": items,
                "manifestDigest": sha256_bytes(
                    canonical_json(
                        [
                            {"captureId": item["captureId"], "status": item["status"], "digest": item["digest"]}
                            for item in items
                        ]
                    )
                ),
            }

        branch_feed = {"captureId": "php_release_feed_8.4", "status": 200, "digest": "sha256:" + "e" * 64}
        with_branch = with_captures([branch_feed])
        branch_plan = {"evidence": [*plan["evidence"], {"captureId": branch_feed["captureId"], "digest": branch_feed["digest"]}]}
        self.assertIn(
            "php_release_feed_8.4",
            validate_recaptured_evidence(branch_plan, with_branch, with_branch)["verifiedCaptureIds"],
        )
        # A policy change between admission and publication changes the branch set.
        with self.assertRaisesRegex(ControlError, "capture set changed"):
            validate_recaptured_evidence(plan, with_branch, manifest)
        with self.assertRaisesRegex(ControlError, "unknown"):
            bad = with_captures([{**branch_feed, "captureId": "php_release_feed_latest"}])
            validate_recaptured_evidence(plan, bad, bad)

    def test_stable_release_recapture_binds_only_the_feeds_that_prove_its_version(self):
        # The model cited every branch feed, so a stale edge on 8.4 stopped an 8.2
        # release. Only a change to what proves the released version may stop it.
        ids = [
            "php_supported_versions",
            "php_release_feed",
            "php_release_feed_8.2",
            "php_release_feed_8.3",
            "php_release_feed_8.4",
            "php_release_feed_8.5",
            "php_source_tags",
            "php_bin_releases",
            "php_bin_state",
            "mise_php_releases",
            "mise_php_state",
        ]
        digests = {capture_id: "sha256:" + f"{index:064x}" for index, capture_id in enumerate(ids, start=1)}
        admitted = evidence_manifest(digests)

        def changed(*capture_ids):
            return evidence_manifest({**digests, **{item: "sha256:" + "f" * 64 for item in capture_ids}})

        def plan(version, *cited, action="new_patch"):
            return {
                "action": action,
                "releaseIntent": {"version": version},
                "evidence": [{"captureId": item, "digest": digests[item]} for item in cited]
                + [{"captureId": "watch_decision", "digest": "sha256:" + "a" * 64}],
            }

        everything = plan("8.2.34", *ids)
        unrelated = changed(
            "php_release_feed",
            "php_release_feed_8.3",
            "php_release_feed_8.4",
            "php_bin_releases",
            "php_bin_state",
            "php_supported_versions",
        )
        self.assertEqual(
            ["php_release_feed_8.2"],
            validate_recaptured_evidence(plan("8.2.34", "php_release_feed_8.2"), admitted, unrelated)[
                "verifiedCaptureIds"
            ],
        )
        # Other branches' feeds, and the aggregate feed beside the cited branch feed,
        # are released; every other cited capture, repository state included, binds.
        other_branches = changed("php_release_feed", "php_release_feed_8.3", "php_release_feed_8.4", "php_release_feed_8.5")
        self.assertEqual(
            [
                "mise_php_releases",
                "mise_php_state",
                "php_bin_releases",
                "php_bin_state",
                "php_release_feed_8.2",
                "php_source_tags",
                "php_supported_versions",
            ],
            validate_recaptured_evidence(everything, admitted, other_branches)["verifiedCaptureIds"],
        )
        for moved in ("php_bin_state", "mise_php_state", "php_bin_releases", "php_supported_versions", "php_source_tags"):
            with self.assertRaisesRegex(ControlError, f"recaptured evidence changed: {moved}$"):
                validate_recaptured_evidence(everything, admitted, changed(moved))
        # A changed feed for the released version still stops publication, cited or not.
        with self.assertRaisesRegex(ControlError, "recaptured evidence changed: php_release_feed_8.2"):
            validate_recaptured_evidence(plan("8.2.34", "php_release_feed_8.2"), admitted, changed("php_release_feed_8.2"))
        with self.assertRaisesRegex(ControlError, "recaptured evidence changed: php_release_feed_8.2"):
            validate_recaptured_evidence(everything, admitted, changed("php_release_feed_8.2"))
        # An aggregate-only proof binds the aggregate feed and the own branch feed.
        aggregate_proof = plan("8.5.11", "php_release_feed")
        self.assertEqual(
            ["php_release_feed", "php_release_feed_8.5"],
            validate_recaptured_evidence(aggregate_proof, admitted, changed("php_release_feed_8.4"))["verifiedCaptureIds"],
        )
        with self.assertRaisesRegex(ControlError, "recaptured evidence changed: php_release_feed$"):
            validate_recaptured_evidence(aggregate_proof, admitted, changed("php_release_feed"))
        with self.assertRaisesRegex(ControlError, "recaptured evidence changed: php_release_feed_8.5"):
            validate_recaptured_evidence(aggregate_proof, admitted, changed("php_release_feed_8.5"))
        # A first branch release has no branch feed yet, so the aggregate proof binds.
        first_release = plan("8.6.0", "php_release_feed", "php_supported_versions", action="new_branch")
        self.assertEqual(
            ["php_release_feed", "php_supported_versions"],
            validate_recaptured_evidence(first_release, admitted, changed("php_release_feed_8.5"))["verifiedCaptureIds"],
        )
        with self.assertRaisesRegex(ControlError, "recaptured evidence changed: php_release_feed$"):
            validate_recaptured_evidence(first_release, admitted, changed("php_release_feed"))
        with self.assertRaisesRegex(ControlError, "cites no release feed that proves its version"):
            validate_recaptured_evidence(plan("8.6.0", "php_bin_releases", action="new_branch"), admitted, admitted)
        # Every cited capture must still be the one admission saw.
        tampered = plan("8.2.34", "php_release_feed_8.2", "php_release_feed_8.4")
        tampered["evidence"][1]["digest"] = "sha256:" + "e" * 64
        with self.assertRaisesRegex(ControlError, "admitted evidence digest mismatch: php_release_feed_8.4"):
            validate_recaptured_evidence(tampered, admitted, admitted)
        # Other releases keep binding everything they cite.
        rebuild = plan("8.5.11-1", "php_bin_releases", "php_bin_state", action="recipe_rebuild")
        with self.assertRaisesRegex(ControlError, "recaptured evidence changed: php_bin_state"):
            validate_recaptured_evidence(rebuild, admitted, changed("php_bin_state"))

    def test_publish_recapture_rechecks_supersession_in_exempt_feeds(self):
        # The aggregate feed is exempt from the digest comparison beside a cited branch
        # feed, but a later patch it names on the same branch must still stop publication.
        def write_manifest(root, bodies):
            (root / "raw").mkdir(parents=True)
            captures = []
            for capture_id in sorted(EVIDENCE_CAPTURE_IDS | set(bodies)):
                body = bodies.get(capture_id, capture_id.encode())
                (root / "raw" / f"{capture_id}.body").write_bytes(body)
                captures.append(
                    {
                        "captureId": capture_id,
                        "status": 200,
                        "digest": sha256_bytes(body),
                        "bodyPath": f"raw/{capture_id}.body",
                    }
                )
            manifest = {"schemaVersion": 1, "captures": captures, "manifestDigest": manifest_digest(captures)}
            (root / "evidence-manifest.json").write_bytes(canonical_json(manifest))
            return root / "evidence-manifest.json", {item["captureId"]: item["digest"] for item in captures}

        def aggregate(version):
            return canonical_json({"8": {"version": version}})

        branch = canonical_json({"version": "8.5.10"})
        admitted_bodies = {
            "php_release_feed": aggregate("8.5.10"),
            "php_release_feed_8.4": canonical_json({"version": "8.4.26"}),
            "php_release_feed_8.5": branch,
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            admitted, digests = write_manifest(root / "admitted", admitted_bodies)
            plan = {
                "action": "new_patch",
                "releaseIntent": {"version": "8.5.10"},
                "evidence": [
                    {"captureId": capture_id, "digest": digests[capture_id]}
                    for capture_id in ("php_release_feed", "php_release_feed_8.5", "php_bin_state")
                ],
            }
            (root / "plan.json").write_bytes(canonical_json(plan))

            def recapture(label, bodies):
                current, _digests = write_manifest(root / label, {**admitted_bodies, **bodies})
                return run_control(
                    "validate-recaptured-evidence",
                    "--plan", str(root / "plan.json"),
                    "--admitted-manifest", str(admitted),
                    "--current-manifest", str(current),
                )

            status, out = recapture("other-branch", {"php_release_feed_8.4": canonical_json({"version": "8.4.27"})})
            self.assertEqual(0, status)
            self.assertEqual(["php_bin_state", "php_release_feed_8.5"], json.loads(out)["verifiedCaptureIds"])
            # A newer major moves the aggregate without superseding this branch.
            self.assertEqual(0, recapture("next-major", {"php_release_feed": canonical_json({"8": {"version": "8.5.10"}, "9": {"version": "9.0.0"}})})[0])
            self.assertEqual(1, recapture("superseded", {"php_release_feed": aggregate("8.5.11")})[0])
            with self.assertRaisesRegex(ControlError, "8.5.10 is superseded by 8.5.11 in php_release_feed$"):
                validate_release_is_newest_patch(
                    "new_patch", plan["releaseIntent"], root / "superseded" / "evidence-manifest.json"
                )

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

    def test_retired_action_key_families_are_rejected(self):
        # Nothing produces or authorizes these families, so no plan or record may carry them.
        for key in ("repair:8.5.9:deadbeef", "auth_failure:deadbeef"):
            self.assertIsNone(ACTION_KEY_RE.fullmatch(key), key)
        for key in ("source_unhealthy:deadbeef", "health_failed:deadbeef", "policy_failure:deadbeef"):
            self.assertIsNotNone(ACTION_KEY_RE.fullmatch(key), key)

    def test_published_asset_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "archive").write_text("staged")
            digests = {"archive": sha256_file(root / "archive")}
            transaction = {
                "state": "publishing",
                "publishedAssets": {"archive": "sha256:" + "0" * 64},
            }
            with self.assertRaisesRegex(ControlError, "published asset inconsistency"):
                release_transition(transaction, "published", root, digests)

    def test_publication_passes_through_a_recorded_publishing_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "archive").write_text("staged")
            digests = {"archive": sha256_file(root / "archive")}
            verified = {"state": "draft_verified", "assetDigests": digests, "history": []}
            # The draft is never published straight from its verification: `publishing`
            # is recorded first, so a run that stops mid-publication is known to have
            # possibly gone live.
            with self.assertRaisesRegex(ControlError, "illegal release transition"):
                release_transition(verified, "published", root, digests)
            publishing = release_transition(verified, "publishing", root, digests)
            self.assertEqual("publishing", publishing["state"])
            self.assertNotIn("publishedAssets", publishing)
            published = release_transition(publishing, "published", root, digests)
            self.assertEqual(digests, published["publishedAssets"])
            # A transaction handed to another job cannot continue with other bytes.
            (root / "other").write_text("rebuilt")
            with self.assertRaisesRegex(ControlError, "asset set changed"):
                release_transition(verified, "publishing", root, {"other": sha256_file(root / "other")})
            # And the recorded bytes are re-read, not trusted.
            (root / "archive").write_text("tampered")
            with self.assertRaisesRegex(ControlError, "digest mismatch"):
                release_transition(verified, "publishing", root, digests)

    def test_email_digest_selects_one_fixed_template_per_outcome(self):
        digest = "sha256:" + "a" * 64
        base = {
            "workflow": "watcher",
            "conclusion": "success",
            "runUrl": "https://github.com/bigpixelrocket/php-bin/actions/runs/1",
            "repository": "bigpixelrocket/php-bin",
        }
        changed = {"classify": True, "manifestDigest": digest}
        cases = (
            ({**base, "conclusion": "failure"}, "watcher_failed", "conclusion 'failure'"),
            (
                {**base, "decision": {"classify": False, "manifestDigest": digest}},
                "quiet_day",
                "nothing needed classifying",
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
                {**base, "decision": changed, "plan": {"action": "recipe_rebuild", "actionKey": "recipe_rebuild:8.5.9:2"}},
                "recipe_rebuild_started",
                "PHP 8.5.9-2 rebuild started",
            ),
            (
                {**base, "workflow": "publish", "transaction": {"released": True, "version": "8.5.9-2"}},
                "rebuild_published",
                "installs of the plain version 8.5.9 now resolve to this revision",
            ),
            (
                {**base, "decision": changed, "plan": {"action": "needs_human", "actionKey": "policy_failure:" + "b" * 8}},
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
                    "transaction": {"released": True, "recorded": True, "version": "8.5.9"},
                },
                "release_complete_run_failed",
                "durable event record was completed",
            ),
            (
                {
                    **base,
                    "workflow": "publish",
                    "conclusion": "failure",
                    "transaction": {"released": True, "recorded": False, "version": "8.5.9"},
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
        changed = {"classify": True, "manifestDigest": digest}
        rejected = (
            {**base, "workflow": "consumer"},
            {**base, "runUrl": "https://example.invalid/run"},
            {**base, "repository": "php-bin"},
            base,
            {**base, "decision": {"classify": False, "manifestDigest": "sha256:short"}},
            {**base, "decision": {"classify": False, "manifestDigest": None}},
            {**base, "decision": {"manifestDigest": "sha256:" + "a" * 64}},
            {**base, "decision": {"classify": 1, "manifestDigest": "sha256:" + "a" * 64}},
            {**base, "decision": changed},
            {**base, "decision": changed, "plan": {"action": "new_patch", "actionKey": "new_patch:8.5.9; rm -rf"}},
            {**base, "decision": changed, "plan": {"action": "new_patch", "actionKey": None}},
            {**base, "decision": changed, "plan": {"action": "new_patch", "actionKey": "repair:8.5.9:deadbeef"}},
            {**base, "decision": changed, "plan": {"action": "recipe_rebuild", "actionKey": "new_patch:8.5.9"}},
            {**base, "decision": changed, "plan": {"action": "publish", "actionKey": "new_patch:8.5.9"}},
            # Retired model-era actions have no template left.
            {**base, "decision": changed, "plan": {"action": "repair", "actionKey": "repair:8.5.9:deadbeef"}},
            {**base, "decision": changed, "plan": {"action": "reconcile_partial", "actionKey": "new_patch:8.5.9"}},
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
            {
                **base,
                "workflow": "publish",
                "conclusion": "failure",
                "transaction": {"released": True, "recorded": "true", "version": "8.5.9"},
            },
            # An event record cannot complete for a release that never went live.
            {
                **base,
                "workflow": "publish",
                "conclusion": "failure",
                "transaction": {"released": False, "recorded": True, "version": "8.5.9"},
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
                json.dumps({"classify": True, "manifestDigest": "sha256:" + "a" * 64})
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

    def test_pause_bounds(self):
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
        # A recovery merge also moves the main a publish or implementation plan was
        # admitted against: the publish recapture binds `php_bin_state` and the
        # implementation seals against the admitted base, so both wait for the next run.
        for deferred in (
            {"action": "new_patch", "actionKey": "new_patch:8.5.10"},
            {"action": "recipe_rebuild", "actionKey": "recipe_rebuild:8.5.9:2"},
            {"action": "new_branch", "actionKey": "new_branch:8.6"},
            {"action": "new_branch", "actionKey": "new_branch:8.6", "editsRequired": True},
        ):
            with self.subTest(deferred=deferred):
                decision = route(recordActionKey="new_patch:8.5.9", recoveryMerged=True, **deferred)
                self.assertEqual("none", decision["route"])
                self.assertEqual("dispatch_deferred_by_recovery", decision["reason"])
                self.assertEqual("recover_record", decision["recoveryRoute"])
        # Without a recovery merge the same plans dispatch as before.
        self.assertEqual("dispatch_publish", route(action="new_patch", recordActionKey="new_patch:8.5.9")["route"])
        # Routes that write nothing still run beside a recovery.
        self.assertEqual("notify_blocked", route(action="blocked", recoveryMerged=True)["route"])
        # A plan for the very release just recovered stays a published release.
        self.assertEqual(
            "release_published_pending_record",
            route(
                action="new_patch", actionKey="new_patch:8.5.9", recordActionKey="new_patch:8.5.9", recoveryMerged=True
            )["reason"],
        )
        # An unroutable edit still fails loudly rather than hiding behind a deferral.
        with self.assertRaises(ControlError):
            route_watch_action({"action": "repair", "editsRequired": True, "recoveryMerged": True})
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
        self.assertEqual("dispatch_implementation", route(action="new_branch", editsRequired=True)["route"])
        self.assertEqual("dispatch_publish", route(action="new_patch")["route"])
        self.assertEqual("dispatch_publish", route(action="new_branch")["route"])
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
        # The retired model-era actions route nowhere.
        for retired in ("repair", "reconcile_partial"):
            with self.assertRaises(ControlError, msg=retired):
                route_watch_action({"action": retired, "editsRequired": True})
        # A rebuild publishes an existing version as a new revision with no edit.
        self.assertEqual(
            "dispatch_publish",
            route(action="recipe_rebuild", actionKey="recipe_rebuild:8.5.9:1")["route"],
        )
        self.assertEqual("none", route(action="recipe_rebuild")["notify"])
        self.assertEqual(
            "release_published_pending_record",
            route(
                action="recipe_rebuild",
                actionKey="recipe_rebuild:8.5.9:1",
                recordActionKey="recipe_rebuild:8.5.9:1",
            )["reason"],
        )
        with self.assertRaises(ControlError):
            route_watch_action({"action": "publish", "editsRequired": False})

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
        self.assertTrue(path_is_protected("autorelease/policy-invariants.json"))
        self.assertTrue(path_is_protected("scripts/classify-autorelease-evidence"))
        self.assertTrue(path_is_protected("scripts/apply-autorelease-plan"))
        self.assertTrue(path_is_protected("autorelease/_classifier.py"))
        self.assertTrue(path_is_protected("scripts/dispatch-pr-checks"))
        self.assertTrue(path_is_protected("scripts/merge-record-pr"))
        self.assertTrue(path_is_protected("autorelease-events/new-branch.json"))
        self.assertTrue(path_is_protected("autorelease-state/last-evidence.json"))
        self.assertFalse(path_is_protected("support-policy.json"))

    def test_gate_harness_paths_are_protected(self):
        for path in ("scripts/test.sh", "scripts/build.sh", "scripts/package.sh",
                     "scripts/compare-modules.sh", "scripts/check-public-language.sh",
                     "tests/test_autorelease.py",
                     # Sourced by the protected gate scripts, so admitted product bash would
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
        # Every single-record PR merges through one gate, which dispatches the checks.
        merger = (root / "scripts/merge-record-pr").read_text()
        self.assertIn('"$script_dir/dispatch-pr-checks"', merger)
        self.assertIn('"$script_dir/assert-admission-checks"', merger)
        self.assertIn(
            'gh pr merge "$pr_number" --repo "$repository" --squash --delete-branch --match-head-commit "$head"',
            merger,
        )
        for workflow, merges in (
            ("autorelease-watch.yml", 3),
            ("autorelease-implement.yml", 1),
            ("autorelease-publish.yml", 1),
        ):
            body = (root / ".github/workflows" / workflow).read_text()
            self.assertEqual(merges, body.count("./scripts/merge-record-pr"), workflow)
            self.assertNotIn("gh pr checks", body)
            self.assertIn("checks: write", body)
            self.assertIn("statuses: write", body)
        # The sealed lifecycle patch is not a single record, so it keeps its own gate.
        implement = (root / ".github/workflows/autorelease-implement.yml").read_text()
        self.assertIn("./scripts/dispatch-pr-checks", implement)

        release = (root / ".github/workflows/autorelease-publish.yml").read_text()
        self.assertIn("validate-recaptured-evidence", release)
        self.assertIn("Notify actionable release failure", release)
        self.assertIn("release-run/failure.json", release)
        self.assertLess(
            release.index("Validate and merge final event record"),
            release.index("Notify owner of completed release"),
        )

    @staticmethod
    def _completed_record(action_key, version, assets, kind="published_release"):
        def step(source, target, evidence):
            return {"from": source, "to": target, "at": "2026-09-29T00:00:00Z", "evidence": evidence}

        return {
            "schemaVersion": 1,
            "actionKey": action_key,
            "state": "complete",
            "history": [
                step("release_requested", "released", [{"kind": kind, "version": version, "assetDigests": assets}]),
                step("released", "public_install_verified", [{"kind": "fresh_public_mise_installs", "version": version}]),
                step("public_install_verified", "complete", [{"kind": "transaction_complete"}]),
            ],
        }

    def test_release_event_recorded_accepts_only_this_release_complete_on_main(self):
        key, version = "recipe_rebuild:8.5.11:3", "8.5.11-3"
        assets = {"SHA256SUMS": "sha256:" + "1" * 64}
        record = self._completed_record(key, version, assets)
        self.assertFalse(release_event_recorded(None, key, version, assets))
        # A new branch's record waits on main short of complete until its release.
        self.assertFalse(release_event_recorded({**record, "state": "mise_ready"}, key, version, assets))
        self.assertTrue(release_event_recorded(record, key, version, assets))
        self.assertTrue(release_event_recorded(record, key, version))
        # The watcher's recovered record names the release through its own evidence kind.
        recovered = self._completed_record(key, version, assets, kind="published_immutable_release")
        self.assertTrue(release_event_recorded(recovered, key, version, assets))
        # A complete record that names anything else contradicts the release.
        for other, other_key, other_version, other_assets in (
            (record, "recipe_rebuild:8.5.11:2", version, assets),
            (record, key, "8.5.11-2", assets),
            (record, key, version, {"SHA256SUMS": "sha256:" + "2" * 64}),
            ({**record, "history": record["history"][1:]}, key, version, assets),
            (self._completed_record(key, version, assets, kind="other"), key, version, assets),
        ):
            with self.assertRaises(ControlError):
                release_event_recorded(other, other_key, other_version, other_assets)
        with self.assertRaises(ControlError):
            release_event_recorded(record, key, "main", assets)

    def test_finalize_reruns_reuse_a_merged_record_and_withdraw_stale_branches(self):
        from autorelease.verify import load_workflow

        root = pathlib.Path(__file__).resolve().parents[1]
        jobs = load_workflow(root / ".github/workflows/autorelease-publish.yml")["jobs"]
        steps = {step.get("name"): step for step in jobs["finalize"]["steps"]}
        commit_step = steps["Commit final event record through a checked PR"]
        merge_step = steps["Validate and merge final event record"]
        state_step = steps["Record whether the event record merged"]
        self.assertEqual("steps.event_pr.outputs.already_recorded == 'false'", merge_step["if"])
        self.assertIn("--require-protected-controls", merge_step["run"])
        self.assertEqual("always()", state_step["if"])
        self.assertEqual("autorelease/event-${{ github.run_id }}", commit_step["env"]["BRANCH"])

        key, version = "recipe_rebuild:8.5.11:3", "8.5.11-3"
        assets = {"SHA256SUMS": "sha256:" + "1" * 64}
        record_path = f"autorelease-events/{action_filename(key)}"
        commit_script = commit_step["run"].replace("${{ github.repository }}", "o/r")
        state_script = state_step["run"]

        def git_in(path, *args):
            return subprocess.run(
                ["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@invalid", *args],
                cwd=path, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            ).stdout.strip()

        def fixture(work, main_record=None, stale_branch=False):
            origin = work / "origin.git"
            git_in(work, "init", "-q", "--bare", "-b", "main", str(origin))
            clone = work / "clone"
            git_in(work, "clone", "-q", str(origin), str(clone))
            git_in(clone, "checkout", "-q", "-b", "main")
            (clone / "autorelease-events").mkdir()
            (clone / "autorelease-events/.keep").write_text("")
            if main_record is not None:
                (clone / record_path).write_text(json.dumps(main_record))
            git_in(clone, "add", "-A")
            git_in(clone, "commit", "-q", "-m", "base")
            git_in(clone, "push", "-q", "origin", "main")
            if stale_branch:
                # An earlier attempt's record commit, which a fresh commit cannot fast-forward.
                git_in(clone, "checkout", "-q", "-b", "earlier-attempt")
                (clone / record_path).write_text("earlier attempt\n")
                git_in(clone, "add", "-A")
                git_in(clone, "commit", "-q", "-m", "earlier attempt")
                git_in(clone, "push", "-q", "origin", "HEAD:refs/heads/autorelease/event-77")
                git_in(clone, "checkout", "-q", "main")
            git_in(clone, "checkout", "-q", "--detach")
            (clone / "autorelease").symlink_to(root / "autorelease")
            (clone / "release-run").mkdir()
            (clone / "release-run/transaction.json").write_text(json.dumps({"state": "complete", "assetDigests": assets}))
            (clone / "release-run/event.json").write_text(json.dumps(self._completed_record(key, version, assets)))
            (work / "bin").mkdir()
            # gh lists the open PRs the case names, closes one by deleting its branch
            # from the origin, and opens PR 9; every call is logged.
            (work / "bin/gh").write_text(
                "#!/usr/bin/env bash\n"
                'echo "$*" >> "$FAKE_LOG"\n'
                'case "$1 $2" in\n'
                '  "pr list") printf "%s\\n" $FAKE_OPEN ;;\n'
                '  "pr close") git -C "$FAKE_ORIGIN" branch -D autorelease/event-77 >/dev/null ;;\n'
                '  "pr create") echo https://github.com/o/r/pull/9 ;;\n'
                '  "auth setup-git") ;;\n'
                "  *) exit 3 ;;\n"
                "esac\n"
            )
            (work / "bin/gh").chmod(0o755)
            return clone, origin

        def run_step(work, clone, origin, script, open_prs="", extra=None):
            output = work / "output.txt"
            output.write_text("")
            env = {
                **os.environ,
                "PATH": f"{work / 'bin'}:{os.environ['PATH']}",
                "ACTION_KEY": key,
                "VERSION": version,
                "BRANCH": "autorelease/event-77",
                "GITHUB_OUTPUT": str(output),
                "RUNNER_TEMP": str(work),
                "FAKE_LOG": str(work / "gh.log"),
                "FAKE_OPEN": open_prs,
                "FAKE_ORIGIN": str(origin),
                "GIT_AUTHOR_NAME": "Fixture",
                "GIT_AUTHOR_EMAIL": "fixture@invalid",
                "GIT_COMMITTER_NAME": "Fixture",
                "GIT_COMMITTER_EMAIL": "fixture@invalid",
                **(extra or {}),
            }
            result = subprocess.run(
                ["bash", "-eo", "pipefail", "-c", script], cwd=clone, env=env, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            outputs = dict(line.split("=", 1) for line in output.read_text().splitlines() if "=" in line)
            calls = (work / "gh.log").read_text() if (work / "gh.log").exists() else ""
            return result, outputs, calls

        # A record an earlier attempt merged ends the step without a second record.
        with tempfile.TemporaryDirectory() as temporary:
            work = pathlib.Path(temporary)
            clone, origin = fixture(work, self._completed_record(key, version, assets))
            result, outputs, calls = run_step(work, clone, origin, commit_script)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("true", outputs["already_recorded"])
            self.assertNotIn("pr create", calls)
            self.assertEqual("", git_in(origin, "branch", "--list", "autorelease/*"))

        # An earlier attempt's open PR and branch are withdrawn and the record filed afresh.
        for open_prs, stale_branch in (("5", True), ("", True), ("", False)):
            with tempfile.TemporaryDirectory() as temporary:
                work = pathlib.Path(temporary)
                clone, origin = fixture(work, stale_branch=stale_branch)
                result, outputs, calls = run_step(work, clone, origin, commit_script, open_prs)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual("false", outputs["already_recorded"])
                self.assertEqual("9", outputs["number"])
                self.assertEqual(("pr close 5" in calls), bool(open_prs), calls)
                head = git_in(origin, "rev-parse", "autorelease/event-77")
                self.assertEqual(outputs["head_sha"], head)
                self.assertEqual(f"{head} {outputs['base_sha']}", git_in(origin, "rev-list", "--parents", "-n", "1", head))
                self.assertEqual(record_path, git_in(origin, "diff", "--name-only", outputs["base_sha"], head))

        # A new branch's incomplete record on main is completed through the PR.
        with tempfile.TemporaryDirectory() as temporary:
            work = pathlib.Path(temporary)
            waiting = {**self._completed_record(key, version, assets), "state": "mise_ready", "history": []}
            clone, origin = fixture(work, waiting)
            result, outputs, _calls = run_step(work, clone, origin, commit_script)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("false", outputs["already_recorded"])

        # A complete record on main for another release stops the step.
        with tempfile.TemporaryDirectory() as temporary:
            work = pathlib.Path(temporary)
            clone, origin = fixture(work, self._completed_record(key, "8.5.11-2", assets))
            result, outputs, calls = run_step(work, clone, origin, commit_script)
            self.assertNotEqual(0, result.returncode)
            self.assertNotIn("already_recorded", outputs)
            self.assertNotIn("pr create", calls)

        # The retained state says recorded exactly when the record is on main.
        for main_record, merge_outcome, already, expected in (
            (None, "success", "false", True),
            (None, "", "true", True),
            (None, "failure", "false", False),
            (None, "", "", False),
            (self._completed_record(key, version, assets), "failure", "false", True),
            (self._completed_record(key, version, assets), "", "", True),
            (self._completed_record(key, "8.5.11-2", assets), "", "", False),
        ):
            with tempfile.TemporaryDirectory() as temporary:
                work = pathlib.Path(temporary)
                clone, origin = fixture(work, main_record)
                result, _outputs, _calls = run_step(
                    work, clone, origin, state_script, extra={"MERGE_OUTCOME": merge_outcome, "ALREADY_RECORDED": already}
                )
                self.assertEqual(0, result.returncode, result.stderr)
                state = json.loads((clone / "release-run/transaction-state.json").read_text())
                self.assertEqual(
                    {"schemaVersion": 1, "released": True, "recorded": expected, "version": version},
                    state,
                    (main_record is not None, merge_outcome, already),
                )

    def test_publish_runs_email_their_own_digest_exactly_once(self):
        from autorelease.verify import load_workflow

        root = pathlib.Path(__file__).resolve().parents[1]
        workflows = root / ".github/workflows"
        email = load_workflow(workflows / "autorelease-email.yml")
        # YAML 1.1 reads the bare `on` key as true.
        triggers = email.get("on") or email["true"]
        # The watcher is started by its schedule or a person, so workflow_run reaches it.
        # GitHub starts no workflow_run for a publish run GITHUB_TOKEN dispatched, and a
        # publish run dispatched any other way must not email twice, so publish is not a
        # workflow_run trigger at all and reaches the digest only by calling it.
        self.assertEqual(["PHP autorelease watcher"], triggers["workflow_run"]["workflows"])
        call = triggers["workflow_call"]
        self.assertEqual({"run_id", "run_attempt", "workflow", "conclusion"}, set(call["inputs"]))
        self.assertTrue(all(spec["required"] and spec["type"] == "string" for spec in call["inputs"].values()))
        self.assertEqual({"RESEND_API_KEY": {"required": False}}, call["secrets"])
        digest = email["jobs"]["digest"]
        self.assertEqual("${{ inputs.run_id || github.event.workflow_run.id }}", digest["env"]["RUN_ID"])
        self.assertEqual("${{ inputs.conclusion || github.event.workflow_run.conclusion }}", digest["env"]["RUN_CONCLUSION"])
        self.assertIn("autorelease-email-${{ inputs.run_id || github.event.workflow_run.id }}", digest["concurrency"]["group"])
        download = next(step for step in digest["steps"] if step.get("name") == "Download the retained run state")
        self.assertIn('if [[ "$CALLED_WORKFLOW" != publish ]]; then', download["run"])
        # An unconfigured repository still skips quietly on both routes.
        gate = next(step for step in digest["steps"] if step.get("name") == "Decide whether delivery is configured")
        self.assertIn('-n "$RESEND_API_KEY"', gate["run"])
        # The secret is scoped to the two steps that read it, never to the whole job.
        self.assertNotIn("RESEND_API_KEY", digest["env"])
        self.assertEqual(
            ["Decide whether delivery is configured", "Send the digest through Resend"],
            [step.get("name") for step in digest["steps"] if "RESEND_API_KEY" in (step.get("env") or {})],
        )
        # Retries reuse one idempotency key per run attempt, so none can send twice.
        send = next(step for step in digest["steps"] if step.get("name") == "Send the digest through Resend")
        self.assertIn("--retry 3", send["run"])
        self.assertIn('--header "Idempotency-Key: php-bin-$WORKFLOW-$RUN_ID-$RUN_ATTEMPT"', send["run"])
        self.assertEqual("${{ steps.state.outputs.workflow }}", send["env"]["WORKFLOW"])

        callers = {
            path.name: [
                name for name, job in (load_workflow(path).get("jobs") or {}).items()
                if job.get("uses") == "./.github/workflows/autorelease-email.yml"
            ]
            for path in workflows.glob("*.yml")
        }
        self.assertEqual({"autorelease-publish.yml": ["email"]}, {name: jobs for name, jobs in callers.items() if jobs})
        jobs = load_workflow(workflows / "autorelease-publish.yml")["jobs"]
        caller = jobs["email"]
        self.assertEqual("always()", caller["if"])
        self.assertEqual(set(jobs) - {"email"}, set(caller["needs"]))
        self.assertEqual({"actions": "read", "contents": "read"}, caller["permissions"])
        self.assertEqual({"RESEND_API_KEY": "${{ secrets.RESEND_API_KEY }}"}, caller["secrets"])
        self.assertEqual(
            {
                "run_id": "${{ github.run_id }}",
                "run_attempt": "${{ github.run_attempt }}",
                "workflow": "publish",
                "conclusion": "${{ contains(needs.*.result, 'failure') && 'failure' || "
                "contains(needs.*.result, 'cancelled') && 'cancelled' || 'success' }}",
            },
            caller["with"],
        )

    def test_automation_pull_requests_are_filed_with_real_newlines_and_exact_leases(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        for path in (root / ".github/workflows").glob("*.yml"):
            body = path.read_text()
            # A double-quoted shell string keeps "\n" as two characters.
            self.assertIsNone(re.search(r'--body "[^"]*\\n', body), path.name)
            # Every lease is taken against a tracking ref fetched with a forced refspec,
            # so it is exactly the branch head the remote reports.
            for match in re.finditer(r"git fetch origin \"([^\"]*)\"", body):
                self.assertTrue(match.group(1).startswith("+refs/heads/"), (path.name, match.group(1)))
            if "--force-with-lease" in body:
                self.assertIn('git fetch origin "+refs/heads/$branch:refs/remotes/origin/$branch"', body, path.name)
            # Every single-record merge also asserts the Protected controls check.
            self.assertEqual(
                body.count("./scripts/merge-record-pr"),
                len(re.findall(r"\./scripts/merge-record-pr[^;]*?--require-protected-controls", body, re.DOTALL)),
                path.name,
            )
        implement = (root / ".github/workflows/autorelease-implement.yml").read_text()
        self.assertIn('printf "Deterministically sealed autorelease patch for \\`%s\\`.\\n\\nValidated commit: \\`%s\\`."', implement)

    def test_release_build_runs_apart_from_the_write_token(self):
        # StaticPHP runs third-party build scripts, so it may only run in a job
        # whose token reads contents, and the write-scoped release job may only
        # consume that job's artifact after checking what the build reported.
        from autorelease.verify import load_workflow, workflow_steps

        root = pathlib.Path(__file__).resolve().parents[1]
        document = load_workflow(root / ".github/workflows/autorelease-publish.yml")
        jobs = document["jobs"]
        steps = workflow_steps(document)
        static_php_jobs = {
            job
            for job, _, step in steps
            if re.search(r"scripts/(build|install-spc|install-build-deps|package)\.sh", step.get("run") or "")
        }
        self.assertEqual({"build"}, static_php_jobs)

        build = jobs["build"]
        self.assertEqual({"contents": "read"}, build["permissions"])
        self.assertNotIn("environment", build)
        self.assertEqual("preflight", build["needs"])
        token_steps = []
        for _, _, step in (entry for entry in steps if entry[0] == "build"):
            self.assertFalse(str(step.get("uses") or "").startswith("jdx/mise-action@"))
            if "github.token" in json.dumps(step):
                token_steps.append(step)
        self.assertNotIn("github.token", json.dumps(build.get("env") or {}))
        self.assertEqual([{"GITHUB_TOKEN": "${{ github.token }}"}], [step.get("env") for step in token_steps])
        self.assertIn("./scripts/build.sh", token_steps[0]["run"])

        for job, _, step in steps:
            if str(step.get("uses") or "").startswith("actions/checkout@"):
                self.assertIs(False, step["with"]["persist-credentials"], job)

        release = jobs["release"]
        self.assertEqual({"preflight", "build"}, set(release["needs"]))
        self.assertEqual("php-autorelease-publish", release["environment"])
        # A failed build must not stop the reconciliation of an existing release.
        self.assertEqual("${{ !cancelled() && needs.preflight.result == 'success' }}", release["if"])
        names = [step.get("name") for step in release["steps"]]
        # The release job runs after a failed build, so this gate alone keeps a
        # fresh release from using an artifact the build did not finish.
        require = release["steps"][names.index("Require the isolated build")]
        self.assertEqual("steps.existing.outputs.reuse != 'true'", require["if"])
        self.assertEqual("${{ needs.build.result }}", require["env"]["BUILD_RESULT"])
        self.assertTrue(require["run"].startswith('test "$BUILD_RESULT" = success\n'))
        download = release["steps"][names.index("Download the isolated build")]
        self.assertEqual(
            {
                "artifact-ids": "${{ needs.build.outputs.artifact_id }}",
                "path": ".artifacts",
                "digest-mismatch": "error",
            },
            download["with"],
        )
        verify = release["steps"][names.index("Verify the staged bytes the build reported")]
        self.assertEqual("${{ needs.build.outputs.archive_digest }}", verify["env"]["ARCHIVE_DIGEST"])
        self.assertEqual("${{ needs.build.outputs.checksums_digest }}", verify["env"]["CHECKSUMS_DIGEST"])
        self.assertIn(
            'test "$(find .artifacts -mindepth 1 -print | LC_ALL=C sort | paste -sd \' \' -)" \\\n'
            '  = ".artifacts/SHA256SUMS .artifacts/$archive"',
            verify["run"],
        )
        self.assertIn('test "sha256:$archive_hex" = "$ARCHIVE_DIGEST"', verify["run"])
        self.assertIn(
            'test "sha256:$(shasum -a 256 .artifacts/SHA256SUMS | awk \'{print $1}\')" = "$CHECKSUMS_DIGEST"',
            verify["run"],
        )
        self.assertIn('grep -Fx "$archive_hex  $archive" .artifacts/SHA256SUMS', verify["run"])
        self.assertIn("validate-autorelease-archive", verify["run"])
        self.assertLess(
            names.index("Reconcile existing immutable release assets"),
            names.index("Require the isolated build"),
        )
        self.assertLess(
            names.index("Require the isolated build"),
            names.index("Download the isolated build"),
        )
        self.assertLess(
            names.index("Verify the staged bytes the build reported"),
            names.index("Initialize release transaction and event"),
        )
        # Any failed job after the build reports, including one that failed after the
        # release went live.
        notify_if = " ".join(jobs["notify-failure"]["if"].split())
        self.assertTrue(notify_if.startswith("always() && needs.preflight.result == 'success' && ("), notify_if)
        for job in ("release", "verify-draft", "publish", "verify-public", "finalize"):
            self.assertIn(f"['{job}'].result == 'failure'" if "-" in job else f".{job}.result == 'failure'", notify_if)
        self.assertEqual(
            {"preflight", "release", "verify-draft", "publish", "verify-public", "finalize"},
            set(jobs["notify-failure"]["needs"]),
        )

        # The built binary runs only in two read-only jobs with no environment, and
        # mise there may not restore a cached binary another job could have saved.
        binary_jobs = {job for job, _, step in steps if "mise exec" in (step.get("run") or "")}
        self.assertEqual({"verify-draft", "verify-public"}, binary_jobs)
        for job in binary_jobs:
            self.assertEqual({"contents": "read"}, jobs[job]["permissions"], job)
            self.assertNotIn("environment", jobs[job], job)
            self.assertEqual("${{ github.token }}", jobs[job]["env"]["GITHUB_TOKEN"], job)
            mise = [step for step in jobs[job]["steps"] if str(step.get("uses") or "").startswith("jdx/mise-action@")]
            self.assertEqual([{"github_token": "${{ github.token }}", "cache": False}], [step.get("with") for step in mise])
        # Every job that holds the publish environment is write-scoped and never
        # installs mise or runs the binary.
        write_jobs = {job for job, body in jobs.items() if "environment" in body}
        self.assertEqual({"release", "publish", "finalize"}, write_jobs)
        for job in write_jobs:
            self.assertEqual("php-autorelease-publish", jobs[job]["environment"])
            self.assertNotIn("permissions", jobs[job], job)
            for step in jobs[job]["steps"]:
                self.assertFalse(str(step.get("uses") or "").startswith("jdx/mise-action@"), job)
                self.assertIsNone(re.search(r"^\s*mise ", step.get("run") or "", re.MULTILINE), job)

        # The jobs run strictly in order, each only after the one before succeeded.
        self.assertEqual({"preflight", "release"}, set(jobs["verify-draft"]["needs"]))
        self.assertEqual("${{ !cancelled() && needs.release.result == 'success' }}", jobs["verify-draft"]["if"])
        self.assertEqual({"preflight", "release", "verify-draft"}, set(jobs["publish"]["needs"]))
        self.assertEqual(
            "${{ !cancelled() && needs.release.result == 'success' && needs['verify-draft'].result == 'success' }}",
            jobs["publish"]["if"],
        )
        self.assertEqual({"preflight", "release", "publish"}, set(jobs["verify-public"]["needs"]))
        self.assertEqual("${{ !cancelled() && needs.publish.result == 'success' }}", jobs["verify-public"]["if"])
        self.assertEqual({"preflight", "publish", "verify-public"}, set(jobs["finalize"]["needs"]))
        self.assertEqual(
            "${{ !cancelled() && needs.publish.result == 'success' && needs['verify-public'].result == 'success' }}",
            jobs["finalize"]["if"],
        )

        # Each handoff is fetched by the ID its producer reported, and every file in it
        # is checked against the digests that producer reported.
        handoffs = {
            ("verify-draft", "Download the draft bytes"): "release",
            ("publish", "Download the verified draft transaction"): "release",
            ("finalize", "Download the published transaction"): "publish",
        }
        for (job, name), producer in handoffs.items():
            names = [step.get("name") for step in jobs[job]["steps"]]
            download = jobs[job]["steps"][names.index(name)]
            self.assertEqual(
                f"${{{{ needs.{producer}.outputs.handoff_artifact_id }}}}", download["with"]["artifact-ids"], job
            )
            self.assertEqual("error", download["with"]["digest-mismatch"], job)
            check = jobs[job]["steps"][names.index(name) + 1]
            self.assertIn("find release-", check["run"], job)
            for value in check["env"].values():
                self.assertTrue(value.startswith(f"${{{{ needs.{producer}.outputs."), job)
        # Publication re-reads the draft once more before the irreversible step.
        publish_names = [step.get("name") for step in jobs["publish"]["steps"]]
        publication = jobs["publish"]["steps"][publish_names.index("Publish unchanged draft and verify public bytes")]
        self.assertIn("for target in publishing published public_verified complete; do", publication["run"])
        # A run that stops mid-publication is a possibly live release, not a failed one.
        live = jobs["publish"]["steps"][publish_names.index("Record whether the immutable release is live")]
        self.assertEqual("always()", live["if"])
        self.assertIn("published|public_verified|complete) released=true ;;", live["run"])
        self.assertIn("publishing)\n", live["run"])
        # A rerun that resumes from the draft handoff still reports a public release as live.
        script = live["run"].replace("${{ github.repository }}", "bigpixelrocket/php-bin")
        with tempfile.TemporaryDirectory() as temporary:
            work = pathlib.Path(temporary)
            (work / "bin").mkdir()
            # gh answers isDraft as the case names (empty is a failed lookup) and serves
            # the state artifacts the case says earlier attempts retained.
            (work / "bin/gh").write_text(
                '#!/usr/bin/env bash\n'
                'case "$1 $2" in\n'
                '  "release view") [[ -n "$FAKE_IS_DRAFT" ]] || exit 1; echo "$FAKE_IS_DRAFT" ;;\n'
                '  "run download")\n'
                '    while (($#)); do case "$1" in --name) name="$2"; shift 2 ;; --dir) dir="$2"; shift 2 ;; *) shift ;; esac; done\n'
                '    source="$FAKE_PRIOR/$name.json"\n'
                '    [[ -f "$source" ]] || exit 1\n'
                '    mkdir -p "$dir" && cp "$source" "$dir/transaction-state.json" ;;\n'
                '  *) exit 3 ;;\n'
                'esac\n'
            )
            (work / "bin/gh").chmod(0o755)
            prior_dir = work / "prior"
            cases = (
                ("complete", "", 1, {}, True),
                ("publishing", "", 1, {}, True),
                ("publishing", "true", 1, {}, False),
                ("publishing", "false", 1, {}, True),
                ("draft_verified", "false", 1, {}, True),
                ("draft_verified", "true", 1, {}, False),
                ("draft_verified", "", 1, {}, False),
                (None, "false", 1, {}, True),
                (None, "", 1, {}, False),
                # A rerun that cannot reach GitHub keeps what an earlier attempt knew.
                ("draft_verified", "", 3, {1: True, 2: False}, True),
                (None, "", 2, {1: True}, True),
                ("draft_verified", "", 2, {1: False}, False),
                ("draft_verified", "true", 2, {}, False),
                # A definite draft answer outranks an earlier attempt's cautious record.
                ("draft_verified", "true", 2, {1: True}, False),
                ("publishing", "true", 2, {1: True}, False),
            )
            for index, (state, is_draft, run_attempt, prior, expected) in enumerate(cases):
                run_dir = work / "release-run"
                shutil.rmtree(run_dir, ignore_errors=True)
                shutil.rmtree(prior_dir, ignore_errors=True)
                prior_dir.mkdir()
                for attempt, released in prior.items():
                    (prior_dir / f"release-transaction-state-77-{attempt}.json").write_text(
                        json.dumps({"schemaVersion": 1, "released": released, "recorded": False, "version": "8.5.9"})
                    )
                if state is not None:
                    run_dir.mkdir()
                    (run_dir / "transaction.json").write_text(json.dumps({"state": state}))
                runner_temp = work / f"runner-temp-{index}"
                runner_temp.mkdir()
                env = {**os.environ, "PATH": f"{work / 'bin'}:{os.environ['PATH']}",
                       "VERSION": "8.5.9", "FAKE_IS_DRAFT": is_draft, "FAKE_PRIOR": str(prior_dir),
                       "RUN_ID": "77", "RUN_ATTEMPT": str(run_attempt), "RUNNER_TEMP": str(runner_temp)}
                subprocess.run(["bash", "-euo", "pipefail", "-c", script], cwd=work, env=env, check=True)
                recorded = json.loads((run_dir / "transaction-state.json").read_text())
                self.assertEqual(expected, recorded["released"], (state, is_draft, run_attempt, prior))
        # A still-draft release is recaptured and revalidated before publication, because
        # a rerun of the failed jobs does not repeat the release job's recapture.
        recapture = jobs["publish"]["steps"][publish_names.index("Re-capture authoritative evidence before publication")]
        self.assertLess(
            publish_names.index("Verify the handed-over transaction"),
            publish_names.index("Re-capture authoritative evidence before publication"),
        )
        self.assertLess(
            publish_names.index("Re-capture authoritative evidence before publication"),
            publish_names.index("Publish unchanged draft and verify public bytes"),
        )
        self.assertIn('if [[ "$is_draft" == "true" ]]; then', recapture["run"])
        self.assertIn("./scripts/capture-autorelease-evidence --output release-run/evidence", recapture["run"])
        self.assertIn("./autorelease/control.py validate-recaptured-evidence", recapture["run"])
        self.assertIn('test "$is_draft" = "false"', recapture["run"])
        # The re-downloaded plan is bound to the dispatched transaction, as in `release`.
        for bound in (
            'test "$(jq -r .actionKey admitted-run/autorelease-plan.json)" = "$ACTION_KEY"',
            'test "$(jq -r .releaseIntent.version admitted-run/autorelease-plan.json)" = "$VERSION"',
            'test "$(jq -r .preconditions.phpBinHead admitted-run/autorelease-plan.json)" = "$EXACT_COMMIT"',
        ):
            self.assertLess(recapture["run"].index(bound), recapture["run"].index("capture-autorelease-evidence"))
        self.assertEqual("${{ needs.preflight.outputs.action_key }}", recapture["env"]["ACTION_KEY"])
        self.assertNotIn("if", recapture)

        # Every artifact a rerun could upload again is named per attempt.
        for job, _, step in steps:
            if str(step.get("uses") or "").startswith("actions/upload-artifact@"):
                self.assertTrue(step["with"]["name"].endswith("-${{ github.run_attempt }}"), step["with"]["name"])
        # The state artifact is replaced within an attempt: the record job refines it.
        state_uploads = [
            (job, step)
            for job, _, step in steps
            if str(step.get("with", {}).get("name", "")).startswith("release-transaction-state-")
        ]
        self.assertEqual(["publish", "finalize"], [job for job, _ in state_uploads])
        for _, step in state_uploads:
            self.assertIs(True, step["with"]["overwrite"])

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
        self.assertEqual(1, len(calls))
        for call in calls:
            self.assertIn('--repo "${{ github.repository }}"', call)
        # The merge itself goes through the shared gate, which always names the repository.
        self.assertIn("./scripts/merge-record-pr", recovery)
        merger = (root / "scripts/merge-record-pr").read_text()
        self.assertEqual(1, len(re.findall(r"gh pr merge ", merger)))
        self.assertIn('gh pr merge "$pr_number" --repo "$repository"', merger)
        # A published release downgrades the publish alarm from critical to warning.
        self.assertIn('--name "release-transaction-state-${{ github.run_id }}-$attempt"', release)
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

    def test_merge_record_pr_merges_only_the_checked_record(self):
        source = pathlib.Path(__file__).resolve().parents[1] / "scripts"
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            scripts = root / "scripts"
            scripts.mkdir()
            for name in ("merge-record-pr", "assert-admission-checks"):
                (scripts / name).write_bytes((source / name).read_bytes())
                (scripts / name).chmod(0o755)
            # The dispatcher reports the checks the case names; gh reports the pull
            # request head the case names and logs every merge it is asked for.
            (scripts / "dispatch-pr-checks").write_text(
                '#!/usr/bin/env bash\nset -euo pipefail\n'
                'while (($#)); do case "$1" in --output) out="$2"; shift 2 ;; *) shift ;; esac; done\n'
                'printf "%s" "$FAKE_CHECKS" > "$out"\n'
            )
            (scripts / "dispatch-pr-checks").chmod(0o755)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            (bin_dir / "gh").write_text(
                '#!/usr/bin/env bash\nset -euo pipefail\n'
                'case "$1 $2" in\n'
                '  "pr view") echo "$FAKE_PR_HEAD" ;;\n'
                '  "pr merge") printf "%s\\n" "$*" >> "$FAKE_MERGE_LOG" ;;\n'
                '  *) exit 3 ;;\n'
                'esac\n'
            )
            (bin_dir / "gh").chmod(0o755)
            origin = root / "origin.git"
            subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True)
            repo = root / "repo"
            subprocess.run(["git", "clone", "-q", str(origin), str(repo)], check=True, capture_output=True)

            def git(*args: str) -> str:
                return subprocess.run(
                    ["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@invalid", *args],
                    cwd=repo, check=True, text=True, stdout=subprocess.PIPE,
                ).stdout.strip()

            (repo / "autorelease-events").mkdir()
            (repo / "autorelease-events/other.json").write_text("{}\n")
            git("add", ".")
            git("commit", "-q", "-m", "base")
            git("push", "-q", "origin", "HEAD:main")
            base = git("rev-parse", "HEAD")
            record = "autorelease-events/new_patch-8.5.9.json"
            (repo / record).write_text('{"state":"complete"}\n')
            git("add", record)
            git("commit", "-q", "-m", "record")
            head = git("rev-parse", "HEAD")
            digest = "sha256:" + hashlib.sha256((repo / record).read_bytes()).hexdigest()
            both = json.dumps([{"name": "Script checks", "bucket": "pass"},
                               {"name": "Protected controls", "bucket": "pass"}])
            merge_log = root / "merges.log"

            def merge(*, pr_head: str = head, checks: str = both, record_digest: str = digest,
                      protected: bool = True) -> subprocess.CompletedProcess:
                merge_log.write_text("")
                args = [str(scripts / "merge-record-pr"), "--pr", "7", "--base", base, "--head", head,
                        "--record", record, "--digest", record_digest,
                        "--checks-output", str(root / "checks.json")]
                if protected:
                    args.append("--require-protected-controls")
                env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}",
                       "GITHUB_REPOSITORY": "bigpixelrocket/php-bin", "FAKE_CHECKS": checks,
                       "FAKE_PR_HEAD": pr_head, "FAKE_MERGE_LOG": str(merge_log)}
                return subprocess.run(args, cwd=repo, env=env, capture_output=True, text=True)

            result = merge()
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(
                f"pr merge 7 --repo bigpixelrocket/php-bin --squash --delete-branch --match-head-commit {head}\n",
                merge_log.read_text(),
            )
            # Only callers that require it assert the Protected controls check.
            only_script = json.dumps([{"name": "Script checks", "bucket": "pass"}])
            self.assertEqual(0, merge(checks=only_script, protected=False).returncode)
            # assert-admission-checks is byte-identical in mise-php and fails silently, so
            # a missing Protected controls check shows as the absent success line.
            unprotected = merge(checks=only_script)
            self.assertNotEqual(0, unprotected.returncode)
            self.assertNotIn("Admission checks passed", unprotected.stdout)
            self.assertEqual("", merge_log.read_text())
            refusals = (
                (merge(pr_head="f" * 40), "is not the committed record"),
                (merge(record_digest="sha256:" + "0" * 64), "does not hold the committed bytes"),
            )
            for result, reason in refusals:
                self.assertNotEqual(0, result.returncode)
                self.assertIn(reason, result.stderr)
                self.assertEqual("", merge_log.read_text())
            # A record commit that is not a single child of the current main is refused.
            (repo / "autorelease-events/other.json").write_text('{"moved":true}\n')
            git("commit", "-q", "-am", "moved main")
            git("push", "-q", "origin", "HEAD:main")
            moved = merge()
            self.assertNotEqual(0, moved.returncode)
            self.assertIn("main moved away from", moved.stderr)
            self.assertEqual("", merge_log.read_text())

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
            plan = {"actionKey": "new_branch:8.6", "allowedPaths": {"php-bin": ["allowed.txt"]}}
            sealed = pathlib.Path(temporary) / "sealed"
            manifest = seal_patch(repo, base, plan, sealed)
            subprocess.run(["git", "add", "allowed.txt"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "validated"], cwd=repo, check=True)
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=repo, check=True, text=True, stdout=subprocess.PIPE
            ).stdout.strip()
            admitted = verify_merge(repo, head, manifest, {"Script checks": "success"}, {}, {})
            self.assertEqual(head, admitted["headSha"])
            with self.assertRaisesRegex(ControlError, "exact commit SHA"):
                seal_patch(repo, "--help", plan, sealed)
            with self.assertRaisesRegex(ControlError, "exact commit SHA"):
                verify_merge(repo, "--help", manifest, {"Script checks": "success"}, {}, {})
            # Passing checks prove nothing when the required one was never reported.
            for checks in ({"Other check": "success"}, {"Script checks": "failure"}, {}):
                with self.subTest(checks=checks), self.assertRaises(ControlError):
                    verify_merge(repo, head, manifest, checks, {}, {})

    def test_sealed_patch_keeps_the_exact_bytes_git_wrote(self):
        def git_in(repo, *arguments):
            return subprocess.run(
                ["git", *arguments], cwd=repo, check=True, text=True, stdout=subprocess.PIPE
            ).stdout.strip()

        with tempfile.TemporaryDirectory() as temporary:
            repo = pathlib.Path(temporary) / "repo"
            repo.mkdir()
            git_in(repo, "init", "-q")
            git_in(repo, "config", "user.name", "Fixture")
            git_in(repo, "config", "user.email", "fixture@invalid")
            git_in(repo, "config", "core.autocrlf", "false")
            (repo / "allowed.txt").write_bytes(b"line one\r\nline two\r\n")
            git_in(repo, "add", "allowed.txt")
            git_in(repo, "commit", "-q", "-m", "baseline")
            base = git_in(repo, "rev-parse", "HEAD")
            (repo / "allowed.txt").write_bytes(b"line one\r\nline 2\r\n")
            (repo / "added.txt").write_bytes("caf\u00e9\n".encode())
            plan = {"actionKey": "new_branch:8.6", "allowedPaths": {"php-bin": ["allowed.txt", "added.txt"]}}
            sealed = pathlib.Path(temporary) / "sealed"
            manifest = seal_patch(repo, base, plan, sealed)
            patch = (sealed / "sealed.patch").read_bytes()
            self.assertEqual(manifest["patchDigest"], sha256_bytes(patch))
            # Text decoding would have folded these carriage returns into newlines.
            self.assertIn(b"+line 2\r\n", patch)
            self.assertIn("+caf\u00e9\n".encode(), patch)
            clean = pathlib.Path(temporary) / "clean"
            subprocess.run(["git", "clone", "-q", str(repo), str(clean)], check=True)
            git_in(clean, "config", "core.autocrlf", "false")
            git_in(clean, "checkout", "-q", base)
            subprocess.run(["git", "apply", "--index", str(sealed / "sealed.patch")], cwd=clean, check=True)
            for entry in manifest["files"]:
                self.assertEqual(entry["digest"], sha256_file(clean / entry["path"]), entry["path"])


if __name__ == "__main__":
    unittest.main()
