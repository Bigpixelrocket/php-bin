"""The release transaction's GitHub effects, run as the workflow runs them.

Each test drives `scripts/publish-release` as a separate process against a fake
`gh` that keeps a small GitHub release and tag state on disk, so the script's
argument handling, its API calls, and their order are all what is under test.
"""

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest

from autorelease.control import ROOT, recipe_identity, recipe_identity_note
from test_autorelease import release_directory

SCRIPT = ROOT / "scripts/publish-release"
REPO = "o/r"
VERSION = "8.5.12-2"
OLD_COMMIT = "a" * 40

# A stateful stand-in for the `gh` calls publish-release makes. Every call is
# logged; a call it does not know fails, so an unexpected API use fails the test.
FAKE_GH = textwrap.dedent(
    """
    import hashlib, json, os, pathlib, sys

    state_path = pathlib.Path(os.environ["FAKE_GH_STATE"])
    state = json.loads(state_path.read_text())
    args = sys.argv[1:]
    state["log"].append(args)
    repo = "repos/o/r/"

    def save():
        state_path.write_text(json.dumps(state))

    def reply(body):
        save()
        print(json.dumps(body))
        sys.exit(0)

    def fail(message):
        save()
        print(message, file=sys.stderr)
        sys.exit(1)

    def option(name):
        return args[args.index(name) + 1]

    def fields():
        return dict(args[index + 1].split("=", 1) for index, arg in enumerate(args) if arg == "-f")

    def release_named(tag):
        return next((release for release in state["releases"] if release["tag_name"] == tag), None)

    if args[0] == "api":
        method = option("--method") if "--method" in args else "GET"
        path = next(arg for arg in args[1:] if arg.startswith(repo))[len(repo):]
        if method == "GET" and path == "releases?per_page=100":
            reply([[{key: value for key, value in release.items() if key != "assets"}
                    for release in state["releases"]]])
        if method == "GET" and path.startswith("git/matching-refs/tags/"):
            prefix = path[len("git/matching-refs/tags/"):]
            reply([{"ref": f"refs/tags/{name}", "object": target}
                   for name, target in sorted(state["refs"].items()) if name.startswith(prefix)])
        if method == "GET" and path.startswith("git/tags/"):
            reply({"object": {"type": "commit", "sha": state["tagObjects"][path[len("git/tags/"):]]}})
        if method == "GET" and path.startswith("releases/"):
            release_id = int(path[len("releases/"):])
            release = state.get("flipOnRead", {}).get(str(release_id)) or next(
                (item for item in state["releases"] if item["id"] == release_id), None)
            reply({key: value for key, value in release.items() if key != "assets"}) if release else fail("HTTP 404")
        if method == "POST" and path == "git/tags":
            body = json.loads(pathlib.Path(option("--input")).read_text())
            sha = hashlib.sha1(json.dumps(body, sort_keys=True).encode()).hexdigest()
            state["tagObjects"][sha] = body["object"]
            reply({"sha": sha})
        if method == "POST" and path == "git/refs":
            name = fields()["ref"].removeprefix("refs/tags/")
            if name in state["refs"]:
                fail("HTTP 422: Reference already exists")
            state["refs"][name] = {"type": "tag", "sha": fields()["sha"]}
            reply({})
        if method == "DELETE" and path.startswith("git/refs/tags/"):
            name = path[len("git/refs/tags/"):]
            published = release_named(name)
            if published and not published["draft"]:
                fail("HTTP 422: Cannot delete a tag of an immutable release")
            state["refs"].pop(name)
            reply({})
        if method == "DELETE" and path.startswith("releases/"):
            release_id = int(path[len("releases/"):])
            state["releases"] = [item for item in state["releases"] if item["id"] != release_id]
            reply({})
    if args[:2] == ["release", "view"]:
        release = release_named(args[2])
        if release is None:
            fail("release not found")
        reply({"isDraft": release["draft"], "tagName": release["tag_name"], "body": release["body"]})
    if args[:2] == ["release", "create"]:
        if args[2] not in state["refs"]:
            fail("tag does not exist")
        files = [arg for arg in args[3:args.index("--repo")]]
        state["releases"].append({
            "id": 1 + max([item["id"] for item in state["releases"]] or [0]),
            "tag_name": args[2],
            "draft": True,
            "body": option("--notes"),
            "assets": {pathlib.Path(name).name: "sha256:" + hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()
                       for name in files},
        })
        reply({})
    if args[:2] == ["release", "edit"]:
        release_named(args[2])["body"] = option("--notes")
        reply({})
    fail(f"unexpected gh call: {args}")
    """
)


def tagged(commit: str) -> dict:
    """Return fake state pieces for an annotated tag object pointing at `commit`."""
    return {"type": "tag", "sha": "1" * 40}, {"1" * 40: commit}


class StaleDraftRecoveryTests(unittest.TestCase):
    """An unpublished draft left before main moved is replaced; nothing public is touched."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = pathlib.Path(temporary.name)
        bin_dir = self.work / "bin"
        bin_dir.mkdir()
        fake = bin_dir / "gh"
        fake.write_text(f"#!{sys.executable}\n{FAKE_GH}")
        fake.chmod(0o755)
        self.state_path = self.work / "state.json"
        self.env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
                    "FAKE_GH_STATE": str(self.state_path)}
        # The admitted commit must be real: the publisher reads its recipe identity.
        self.commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True
        ).stdout.strip()
        self.identity = recipe_identity(ROOT, self.commit, "8.5")

    def given(self, releases=(), refs=None, tag_objects=None, **extra):
        self.state_path.write_text(json.dumps({
            "releases": list(releases), "refs": refs or {}, "tagObjects": tag_objects or {}, "log": [], **extra,
        }))

    def state(self) -> dict:
        return json.loads(self.state_path.read_text())

    def mutations(self) -> list[list[str]]:
        return [call for call in self.state()["log"]
                if ("--method" in call and call[call.index("--method") + 1] != "GET")
                or call[:2] in (["release", "create"], ["release", "edit"])]

    def publish(self, *argv: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--version", VERSION, "--repo", REPO, *argv],
            capture_output=True, text=True, env=self.env, timeout=60,
        )

    def discard(self, commit: str | None = None) -> subprocess.CompletedProcess:
        return self.publish("--discard-stale-draft", "--commit", commit or self.commit)

    def create_draft(self) -> subprocess.CompletedProcess:
        assets = release_directory(self.work / "assets", VERSION)
        transaction = self.work / "transaction.json"
        transaction.write_text(json.dumps({"schemaVersion": 1, "state": "built", "history": []}))
        return self.publish(
            "--target", "draft_created", "--commit", self.commit, "--backend", "github",
            "--transaction", str(transaction), "--assets", str(assets), "--output", str(self.work / "next.json"),
        )

    def draft(self, commit_note: str = "sha256:" + "d" * 64, draft: bool = True) -> dict:
        return {"id": 7, "tag_name": VERSION, "draft": draft,
                "body": recipe_identity_note(commit_note), "assets": {"SHA256SUMS": "sha256:" + "e" * 64}}

    def test_a_draft_tagged_before_main_moved_is_replaced_by_this_commit_s_build(self):
        ref, objects = tagged(OLD_COMMIT)
        self.given([self.draft()], {VERSION: ref}, objects)
        discarded = self.discard()
        self.assertEqual(0, discarded.returncode, discarded.stderr)
        self.assertEqual({"version": VERSION, "discardedStaleDraft": True}, json.loads(discarded.stdout))
        self.assertEqual({"releases": [], "refs": {}}, {key: self.state()[key] for key in ("releases", "refs")})
        # The tag goes before the draft, so a stop in between leaves a recoverable draft.
        self.assertEqual(
            [["api", "--method", "DELETE", f"repos/{REPO}/git/refs/tags/{VERSION}"],
             ["api", "--method", "DELETE", f"repos/{REPO}/releases/7"]],
            self.mutations(),
        )
        # The transaction then creates the tag and draft afresh, bound to the admitted commit.
        created = self.create_draft()
        self.assertEqual(0, created.returncode, created.stderr)
        state = self.state()
        tag_object = state["refs"][VERSION]["sha"]
        self.assertEqual(self.commit, state["tagObjects"][tag_object])
        (release,) = state["releases"]
        self.assertTrue(release["draft"])
        self.assertIn(recipe_identity_note(self.identity), release["body"])
        self.assertEqual(json.loads((self.work / "next.json").read_text())["assetDigests"], release["assets"])

    def test_a_draft_whose_tag_was_already_deleted_is_finished_off(self):
        # An earlier discard that stopped between its two deletions.
        self.given([self.draft()])
        discarded = self.discard()
        self.assertEqual(0, discarded.returncode, discarded.stderr)
        self.assertEqual([], self.state()["releases"])
        self.assertEqual([["api", "--method", "DELETE", f"repos/{REPO}/releases/7"]], self.mutations())

    def test_a_published_release_with_a_mismatched_tag_is_never_touched_and_still_fails(self):
        ref, objects = tagged(OLD_COMMIT)
        self.given([self.draft(draft=False)], {VERSION: ref}, objects)
        discarded = self.discard()
        self.assertEqual(0, discarded.returncode, discarded.stderr)
        self.assertFalse(json.loads(discarded.stdout)["discardedStaleDraft"])
        created = self.create_draft()
        self.assertEqual(1, created.returncode)
        self.assertIn("existing tag does not point to the admitted commit", created.stderr)
        self.assertEqual([], self.mutations())
        self.assertFalse(self.state()["releases"][0]["draft"])

    def test_a_draft_at_the_admitted_commit_is_resumed_not_replaced(self):
        ref, objects = tagged(self.commit)
        self.given([self.draft(self.identity)], {VERSION: ref}, objects)
        discarded = self.discard()
        self.assertEqual(0, discarded.returncode, discarded.stderr)
        self.assertFalse(json.loads(discarded.stdout)["discardedStaleDraft"])
        created = self.create_draft()
        self.assertEqual(0, created.returncode, created.stderr)
        self.assertEqual([], self.mutations())
        self.assertEqual(1, len(self.state()["releases"]))

    def test_a_stray_tag_without_a_release_is_left_for_a_human(self):
        ref, objects = tagged(OLD_COMMIT)
        self.given([], {VERSION: ref}, objects)
        discarded = self.discard()
        self.assertEqual(0, discarded.returncode, discarded.stderr)
        self.assertFalse(json.loads(discarded.stdout)["discardedStaleDraft"])
        created = self.create_draft()
        self.assertEqual(1, created.returncode)
        self.assertIn("existing tag does not point to the admitted commit", created.stderr)
        self.assertEqual([], self.mutations())

    def test_a_similarly_named_tag_is_not_mistaken_for_the_release_tag(self):
        # matching-refs is a prefix match: 8.5.12-2 also matches 8.5.12-20.
        ref, objects = tagged(OLD_COMMIT)
        self.given([self.draft(self.identity)], {VERSION + "0": ref}, objects)
        discarded = self.discard()
        self.assertEqual(0, discarded.returncode, discarded.stderr)
        self.assertEqual({VERSION + "0": ref}, self.state()["refs"])
        self.assertEqual([["api", "--method", "DELETE", f"repos/{REPO}/releases/7"]], self.mutations())

    def test_a_draft_published_while_it_is_discarded_is_left_alone(self):
        ref, objects = tagged(OLD_COMMIT)
        self.given([self.draft()], {VERSION: ref}, objects, flipOnRead={"7": self.draft(draft=False)})
        discarded = self.discard()
        self.assertEqual(1, discarded.returncode)
        self.assertIn("stopped being an unpublished draft", discarded.stderr)
        self.assertEqual([], self.mutations())

    def test_ambiguous_or_malformed_requests_fail_closed_without_effect(self):
        ref, objects = tagged(OLD_COMMIT)
        self.given([self.draft(), {**self.draft(), "id": 8}], {VERSION: ref}, objects)
        twice = self.discard()
        self.assertEqual(1, twice.returncode)
        self.assertIn("more than one release names tag", twice.stderr)
        self.given([self.draft()], {VERSION: ref}, objects)
        self.assertIn("not an exact commit SHA", self.discard("HEAD").stderr)
        self.assertEqual([], self.mutations())
        # Without the discard flag, a transition still needs its full arguments.
        incomplete = self.publish("--commit", self.commit, "--target", "built")
        self.assertEqual(2, incomplete.returncode)
        self.assertIn("--transaction", incomplete.stderr)


class ReleaseJobWiringTests(unittest.TestCase):
    """The release job discards a stale draft before it decides whether to reuse one."""

    def test_the_stale_draft_is_discarded_behind_the_live_operator_gate_before_reconciling(self):
        from autorelease.verify import load_workflow

        steps = load_workflow(ROOT / ".github/workflows/autorelease-publish.yml")["jobs"]["release"]["steps"]
        run = next(step["run"] for step in steps if step.get("name") == "Reconcile existing immutable release assets")
        gate = run.index("operator-gate --operator-file release-run/current-operator.json --require-enabled")
        discard = run.index('./scripts/publish-release --discard-stale-draft \\\n'
                            '  --version "$VERSION" --commit "$EXACT_COMMIT" --repo "${{ github.repository }}"')
        reconcile = run.index('if gh release view "$VERSION"')
        self.assertLess(gate, discard)
        self.assertLess(discard, reconcile)


if __name__ == "__main__":
    unittest.main()
