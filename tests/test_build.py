"""Behavior of scripts/build.sh around StaticPHP, and of the upstream canary."""

import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Records every call, lays php-src out on extract like an upstream tarball would
# (FAKE_EXT_DIRS lists `<dir>:<file>` entries), and stops at the build step after
# recording which ext directories were left. FAKE_FAIL names a call that fails.
FAKE_SPC = textwrap.dedent(
    """\
    #!/usr/bin/env bash
    set -euo pipefail
    echo "$*" >> "$SPC_CALLS"
    if [[ "$*" == "${FAKE_FAIL:-}" ]]; then exit 1; fi
    if [[ "$1" == "extract" ]]; then
      mkdir -p source/php-src/sapi/micro/patches
      printf 'new\n' > source/php-src/target.txt
      if [[ -n "${FAKE_PATCH_DIR:-}" ]]; then cp "$FAKE_PATCH_DIR"/* source/php-src/sapi/micro/patches/; fi
      for entry in $FAKE_EXT_DIRS; do
        mkdir -p "source/php-src/ext/${entry%%:*}"
        touch "source/php-src/ext/${entry%%:*}/${entry#*:}"
      done
    fi
    if [[ "$1 ${2:-}" == "craft craft-build.yml" ]]; then
      echo "left: $(cd source/php-src/ext && echo *)" >> "$SPC_CALLS"
      echo "micro: ${SPC_MICRO_PATCHES-unset}" >> "$SPC_CALLS"
      exit 1
    fi
    """
)

FAKE_UNAME = textwrap.dedent(
    """\
    #!/usr/bin/env bash
    case "$1" in -s) echo Darwin ;; -m) echo arm64 ;; *) echo Darwin ;; esac
    """
)

UPSTREAM_LAYOUT = "standard:config.m4 date:config0.m4 imap/tests:x.phpt com_dotnet:config.w32 skeleton:README"


class BuildScriptTests(unittest.TestCase):
    def setUp(self):
        self.scratch = pathlib.Path(tempfile.mkdtemp(prefix="php-bin-build-test."))
        self.addCleanup(shutil.rmtree, self.scratch)
        # A copy of the recipe, so the build folder never lands in the checkout.
        self.root = self.scratch / "php-bin"
        for name in ("scripts", "stages", "expected-modules"):
            shutil.copytree(ROOT / name, self.root / name)
        bin_dir = self.scratch / "bin"
        bin_dir.mkdir()
        for name, body in (("spc", FAKE_SPC), ("uname", FAKE_UNAME)):
            path = bin_dir / name
            path.write_text(body)
            path.chmod(0o755)
        self.calls = self.scratch / "calls.txt"
        self.env = {
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "SPC_BIN": str(bin_dir / "spc"),
            "SPC_CALLS": str(self.calls),
            "FAKE_EXT_DIRS": UPSTREAM_LAYOUT,
        }

    def build(self, version, **env):
        return subprocess.run(
            [str(self.root / "scripts/build.sh"), version, "s4"],
            env={**self.env, **env},
            capture_output=True,
            text=True,
            check=False,
        )

    def test_ext_directories_without_a_build_config_are_removed_before_the_build(self):
        result = self.build("8.4.27")
        self.assertNotEqual(0, result.returncode)
        self.assertEqual(
            [
                "doctor", "craft craft-download.yml", "extract php-src,micro", "craft craft-build.yml",
                "left: date standard", "micro: ",
            ],
            self.calls.read_text().splitlines(),
        )
        self.assertIn("Removing source/php-src/ext/imap: it holds no config*.m4.", result.stdout)

    def test_a_bundled_extension_is_kept(self):
        self.build("8.3.36", FAKE_EXT_DIRS=f"{UPSTREAM_LAYOUT} imap:config.m4")
        self.assertIn("left: date imap standard", self.calls.read_text().splitlines())

    def test_a_failed_step_stops_the_build(self):
        for failing, expected in (
            ("craft craft-download.yml", ["doctor", "craft craft-download.yml"]),
            ("extract php-src,micro", ["doctor", "craft craft-download.yml", "extract php-src,micro"]),
        ):
            with self.subTest(failing=failing):
                self.calls.unlink(missing_ok=True)
                result = self.build("8.4.27", FAKE_FAIL=failing)
                self.assertNotEqual(0, result.returncode)
                self.assertEqual(expected, self.calls.read_text().splitlines())

    def patch(self, name, before):
        """A micro patch that applies only to a target.txt holding `before`."""
        (self.patches / name).write_text(
            f"--- a/target.txt\n+++ b/target.txt\n@@ -1 +1 @@\n-{before}\n+patched\n"
        )

    def test_each_micro_patch_resolves_to_its_newest_file_that_applies_to_the_branch(self):
        self.patches = self.scratch / "patches"
        self.patches.mkdir()
        self.patch("macos_iconv_80.patch", "old")
        self.patch("macos_iconv_84.patch", "new")
        self.patch("macos_iconv_86.patch", "new")
        self.patch("macos_iconv_extra_85.patch", "new")
        self.patch("cli_checks_80.patch", "old")
        env = {"FAKE_PATCH_DIR": str(self.patches)}
        for version, expected in (("8.5.12", "macos_iconv_84"), ("8.6.0", "macos_iconv_86"), ("9.0.0", "macos_iconv_86")):
            with self.subTest(version=version):
                self.calls.unlink(missing_ok=True)
                result = self.build(version, **env)
                self.assertEqual(f"micro: {expected}", self.calls.read_text().splitlines()[-1])
                self.assertIn("Skipping micro patch cli_checks: no version of it applies", result.stderr)
        self.calls.unlink()
        self.build("8.2.35", **env)
        self.assertEqual("micro: ", self.calls.read_text().splitlines()[-1])
        self.calls.unlink()
        self.build("8.5.12", SPC_MICRO_PATCHES="cli_checks_80", **env)
        self.assertEqual("micro: ", self.calls.read_text().splitlines()[-1])

    def test_only_the_download_craft_downloads_and_only_the_build_craft_builds(self):
        self.build("8.4.27")
        build_dir = self.root / ".build/8.4.27/s4"
        download = (build_dir / "craft-download.yml").read_text()
        build = (build_dir / "craft-build.yml").read_text()
        self.assertIn('php-version: "8.4.27"\n', download)
        self.assertIn("craft-options:\n  download: true\n  build: false\n", download)
        self.assertIn("craft-options:\n  download: false\n  build: true\n", build)
        self.assertNotIn("php-src:", download)

    def test_a_tag_build_pins_php_src_to_the_exact_tag(self):
        for version, numeric in (("8.5.12", "8.5.12"), ("8.6.0RC4", "8.6.0"), ("9.0.0alpha1", "9.0.0")):
            with self.subTest(version=version):
                self.build(version, PHP_SOURCE="tag")
                download = (self.root / f".build/{version}/s4/craft-download.yml").read_text()
                self.assertIn(f'php-version: "{numeric}"\n', download)
                self.assertIn(
                    f'    - "php-src:https://github.com/php/php-src/archive/refs/tags/php-{version}.tar.gz"\n',
                    download,
                )

    def test_a_tag_build_needs_an_exact_tag_and_a_known_source(self):
        for version, source, message in (
            ("8.5", "tag", "PHP_SOURCE=tag needs an exact php-src tag version"),
            ("8.6.0-dev", "tag", "PHP_SOURCE=tag needs an exact php-src tag version"),
            ("8.5.12", "git", "PHP_SOURCE must be release or tag"),
        ):
            with self.subTest(source=source, version=version):
                result = self.build(version, PHP_SOURCE=source)
                self.assertNotEqual(0, result.returncode)
                self.assertIn(message, result.stderr)
                self.assertFalse(self.calls.exists())


class CanarySelectionTests(unittest.TestCase):
    def select(self, maintained, tags, releases, lists):
        with tempfile.TemporaryDirectory() as scratch:
            scratch = pathlib.Path(scratch)
            (scratch / "policy.json").write_text(json.dumps({"maintainedBranches": maintained}))
            (scratch / "tags.txt").write_text("\n".join(tags))
            (scratch / "releases.txt").write_text("\n".join(releases))
            modules = scratch / "expected-modules"
            modules.mkdir()
            for branch in lists:
                (modules / f"{branch}.txt").write_text("core\n")
            result = subprocess.run(
                [
                    str(ROOT / "scripts/select-canary-builds"),
                    "--policy", str(scratch / "policy.json"),
                    "--tags", str(scratch / "tags.txt"),
                    "--releases", str(scratch / "releases.txt"),
                    "--modules-dir", str(modules),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
        if result.returncode:
            return result.stderr
        return [(item["version"], item["branch"], item["modules"]) for item in json.loads(result.stdout)]

    def test_unpublished_patches_and_the_next_branch_are_built(self):
        self.assertEqual(
            [("8.4.27", "8.4", "8.4"), ("8.5.12", "8.5", "8.5"), ("8.6.0RC4", "8.6", "8.5")],
            self.select(
                ["8.4", "8.5"],
                ["8.4.26", "8.4.27", "8.5.11", "8.5.12", "8.6.0alpha1", "8.6.0beta3", "8.6.0RC4", "8.6.0RC10x",
                 "8.3.99", "7.4.33", "php_8_6_0RC4"],
                ["8.4.26-2", "8.4.26", "8.5.11-3"],
                ["8.4", "8.5"],
            ),
        )

    def test_published_branches_build_nothing_and_a_stable_tag_outranks_its_candidates(self):
        self.assertEqual([], self.select(["8.5"], ["8.5.12", "8.5.12RC1"], ["8.5.12"], ["8.5"]))
        self.assertEqual(
            [("9.0.0", "9.0", "8.6")],
            self.select(["8.6"], ["8.6.3", "9.0.0RC2", "9.0.0", "9.0.0RC9"], ["8.6.3"], ["8.6"]),
        )

    def test_a_maintained_branch_with_no_release_builds_its_newest_tag(self):
        self.assertEqual(
            [("8.6.0", "8.6", "8.6")],
            self.select(["8.5", "8.6"], ["8.5.12", "8.6.0RC4", "8.6.0"], ["8.5.12"], ["8.5", "8.6"]),
        )

    def test_selection_rejects_inputs_it_cannot_trust(self):
        self.assertIn("maintains no branch", self.select([], ["8.5.1"], [], ["8.5"]))
        self.assertIn("no module list", self.select(["8.5"], ["8.5.1"], [], []))
        self.assertIn("not a major.minor branch", self.select(["8"], ["8.5.1"], [], ["8.5"]))


class UpstreamCanaryWorkflowTests(unittest.TestCase):
    def setUp(self):
        from autorelease.verify import load_workflow

        self.document = load_workflow(ROOT / ".github/workflows/upstream-canary.yml")
        self.jobs = self.document["jobs"]

    def test_the_canary_builds_tags_read_only_and_only_reports_with_issue_access(self):
        self.assertEqual({"contents": "read"}, self.document["permissions"])
        canary = self.jobs["canary"]
        self.assertNotIn("permissions", canary)
        self.assertEqual("tag", canary["env"]["PHP_SOURCE"])
        self.assertEqual('scripts/build.sh "$VERSION" s4', canary["steps"][-1]["run"])
        self.assertFalse(any("upload" in str(step.get("uses", "")) for step in canary["steps"]))
        report = self.jobs["report"]
        self.assertEqual({"issues": "write"}, report["permissions"])
        self.assertFalse(any("uses" in step for step in report["steps"]))

    def test_nothing_in_the_canary_starts_or_publishes_a_release(self):
        text = (ROOT / ".github/workflows/upstream-canary.yml").read_text()
        for forbidden in ("gh workflow run", "gh release", "contents: write", "actions: write"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
