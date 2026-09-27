import contextlib
import http.client
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
    release_recipe_identity,
    validate_recipe_rebuild_evidence,
    email_digest,
    email_fallback,
    evidence_sources,
    fetch_url,
    load_plan_evidence,
    main as control_main,
    manifest_digest,
    mutation_allowed,
    route_watch_action,
    notification_decision,
    retained_notification_issue,
    release_transition,
    retry_decision,
    seal_patch,
    sha256_bytes,
    sha256_file,
    project_release_identity,
    strip_supported_versions_date_presentation,
    transition_event,
    validate_archive,
    validate_completion_assessment,
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
        self.assertFalse(decision["modelCall"])

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
        plan = {
            "schemaVersion": 1,
            "action": "no_change",
            "actionKey": "no_change:" + "c" * 16,
            "editsRequired": True,
            "allowedPaths": {"php-bin": ["autorelease-state/last-evidence.json"], "mise-php": []},
            "releaseIntent": None,
        }
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
        self.assertTrue(decision["modelCall"])
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
        self.assertEqual(("quiet", False, ""), (quiet["trigger"], quiet["modelCall"], quiet["rebuildActionKey"]))
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
        plan = {
            "schemaVersion": 1,
            "action": "recipe_rebuild",
            "actionKey": key,
            "editsRequired": False,
            "allowedPaths": {"php-bin": [], "mise-php": []},
            "releaseIntent": {"version": "8.5.9-2", "sourceIdentifier": "php_bin_releases"},
        }
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
            no_change = {
                "schemaVersion": 1,
                "action": "no_change",
                "actionKey": "no_change:" + "c" * 16,
                "editsRequired": False,
                "allowedPaths": {"php-bin": [], "mise-php": []},
                "releaseIntent": None,
            }
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
            {**base, "decision": changed, "plan": {"action": "recipe_rebuild", "actionKey": "new_patch:8.5.9"}},
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
        self.assertIn('test "sha256:$archive_hex" = "$ARCHIVE_DIGEST"', verify["run"])
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
        self.assertEqual(
            "always() && needs.preflight.result == 'success' && needs.release.result == 'failure'",
            jobs["notify-failure"]["if"],
        )

        # The release job still runs the built binary to verify installs, so
        # those steps and mise itself may hold no token, and mise may not
        # restore a cached binary another job could have saved.
        mise = [step for step in release["steps"] if str(step.get("uses") or "").startswith("jdx/mise-action@")]
        self.assertEqual([{"github_token": "", "cache": False}], [step.get("with") for step in mise])
        mise_index = release["steps"].index(mise[0])
        self.assertEqual(
            'test -z "${MISE_GITHUB_TOKEN:-}"',
            release["steps"][mise_index + 1]["run"],
        )
        self.assertNotIn("github.token", json.dumps(release.get("env") or {}))
        binary_steps = [step for step in release["steps"] if "mise exec" in (step.get("run") or "")]
        self.assertEqual(2, len(binary_steps))
        for step in binary_steps:
            self.assertNotIn("github.token", json.dumps(step))
            self.assertTrue(
                step["run"].startswith('test -z "${GH_TOKEN:-}${GITHUB_TOKEN:-}${MISE_GITHUB_TOKEN:-}"\n'),
                step["name"],
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
