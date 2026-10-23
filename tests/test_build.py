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
# recording which ext directories were left. FAKE_FAIL names a call that fails, and
# FAKE_BREAK an extension whose source the failed build logs a compiler error in
# while the build still tries it.
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
      echo "static: $(sed -n 's/^extensions: //p' craft-build.yml)" >> "$SPC_CALLS"
      echo "shared: $(sed -n 's/^shared-extensions: //p' craft-build.yml)" >> "$SPC_CALLS"
      mkdir -p log buildroot/lib
      : > log/spc.shell.log
      # Like StaticPHP, resolve one library per shared extension tried, and keep
      # libraries already installed.
      echo "[00:00:00] [I] Libraries (1):         $(sed -n 's/^shared-extensions: //p' craft-build.yml)" > log/spc.output.log
      if [[ ! -f buildroot/lib/built-for ]]; then
        sed -n 's/^shared-extensions: //p' craft-build.yml > buildroot/lib/built-for
      fi
      echo "libraries built for: $(cat buildroot/lib/built-for)" >> "$SPC_CALLS"
      for name in ${FAKE_BREAK:-}; do
        if grep -Eq "^(shared-)?extensions: (.*,)?$name(,|$)" craft-build.yml; then
          echo "$PWD/source/php-src/ext/$name/$name.c:1:1: error: broken" >> log/spc.shell.log
        fi
      done
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
            self.calls.read_text().splitlines()[:6],
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
                self.assertEqual([expected], self.calls_with("micro: "))
                self.assertIn("Skipping micro patch cli_checks: no version of it applies", result.stderr)
        self.calls.unlink()
        self.build("8.2.35", **env)
        self.assertEqual([""], self.calls_with("micro: "))
        self.calls.unlink()
        self.build("8.5.12", SPC_MICRO_PATCHES="cli_checks_80", **env)
        self.assertEqual([""], self.calls_with("micro: "))

    def calls_with(self, prefix):
        return [line[len(prefix):] for line in self.calls.read_text().splitlines() if line.startswith(prefix)]

    def write_list(self, branch, text):
        (self.root / f"expected-modules/{branch}.txt").write_text(text)

    def test_a_branch_builds_nothing_its_module_list_leaves_out(self):
        self.write_list("8.6", "core\n!imap\n!igbinary\n!memcached\n!redis\n!xdebug\n")
        self.build("8.6.0", PHP_SOURCE="tag")
        static, shared = self.calls_with("static: ")[0].split(","), self.calls_with("shared: ")[0].split(",")
        self.assertNotIn("imap", static)
        self.assertIn("intl", static)
        for name in ("igbinary", "redis", "xdebug"):
            self.assertNotIn(name, shared)
        self.assertIn("imagick", shared)
        listed = (self.root / ".build/8.6.0/s4/shared-extensions.txt").read_text()
        self.assertNotIn("xdebug", listed)
        self.assertIn("imagick", listed)

    def test_leaving_out_a_requirement_without_its_dependent_fails_the_build(self):
        self.write_list("8.6", "core\n!igbinary\n")
        result = self.build("8.6.0", PHP_SOURCE="tag")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("redis requires unlisted extension igbinary", result.stderr)
        self.assertFalse(self.calls.exists())

    def test_a_release_build_never_leaves_out_what_fails(self):
        result = self.build("8.4.27", FAKE_BREAK="imap")
        self.assertNotEqual(0, result.returncode)
        self.assertEqual(1, len(self.calls_with("static: ")))
        self.assertNotIn("Leaving out", result.stdout)

    def test_discovery_leaves_out_what_does_not_compile_and_everything_that_needs_it(self):
        # The list's own exclusions are ignored: discovery tries every stage extension.
        self.write_list("8.6", "core\n!intl\n")
        result = self.build(
            "8.6.0RC4", PHP_SOURCE="tag", FAKE_BREAK="imap igbinary",
            DISCOVER_MODULE_LIST=str(self.scratch / "discovered.txt"),
        )
        self.assertNotEqual(0, result.returncode)
        static, shared = self.calls_with("static: "), self.calls_with("shared: ")
        # The third attempt retries the same set after rebuilding the libraries.
        self.assertEqual(3, len(static))
        self.assertEqual((static[1], shared[1]), (static[2], shared[2]))
        self.assertIn("intl", static[0].split(","))
        self.assertIn("imap", static[0].split(","))
        self.assertNotIn("imap", static[1].split(","))
        self.assertNotIn("igbinary", shared[1].split(","))
        self.assertNotIn("redis", shared[1].split(","))
        self.assertNotIn("memcached", shared[1].split(","))
        self.assertIn("imagick", shared[1].split(","))
        self.assertIn("Attempt 1: leaving out igbinary,imap: it does not compile on PHP 8.6.0RC4. Retrying.", result.stdout)
        # The retries name nothing, so discovery stops instead of guessing.
        self.assertIn("no compiler error names an extension it could leave out", result.stderr)
        self.assertFalse((self.scratch / "discovered.txt").exists())

    def test_discovery_rebuilds_libraries_once_when_their_set_changed(self):
        # Attempt 1 leaves out igbinary; attempt 2 fails with nothing to blame while the
        # installed libraries were built for the larger set, so they are rebuilt once.
        result = self.build(
            "8.6.0", PHP_SOURCE="tag", FAKE_BREAK="igbinary",
            DISCOVER_MODULE_LIST=str(self.scratch / "discovered.txt"),
        )
        self.assertNotEqual(0, result.returncode)
        built_for = self.calls_with("libraries built for: ")
        self.assertEqual(3, len(built_for))
        self.assertIn("igbinary", built_for[0])
        self.assertEqual(built_for[0], built_for[1])
        self.assertNotIn("igbinary", built_for[2])
        self.assertIn("Attempt 2: no extension to leave out, and the libraries were built for another library set.",
                      result.stdout)
        self.assertIn("no compiler error names an extension it could leave out", result.stderr)

    def test_a_discovery_pass_stops_at_its_deadline_and_the_next_resumes(self):
        listed = self.scratch / "discovered.txt"
        result = self.build(
            "8.6.0", PHP_SOURCE="tag", FAKE_BREAK="imap igbinary",
            DISCOVER_MODULE_LIST=str(listed), DISCOVER_DEADLINE="1",
        )
        self.assertEqual(75, result.returncode, result.stderr)
        self.assertEqual(1, len(self.calls_with("static: ")))
        pending = pathlib.Path(f"{listed}.pending")
        self.assertEqual("igbinary\nimap\nmemcached\nredis\n", pending.read_text())
        self.calls.unlink()
        self.build("8.6.0", PHP_SOURCE="tag", DISCOVER_MODULE_LIST=str(listed), DISCOVER_RESUME=str(pending))
        static, shared = self.calls_with("static: ")[0].split(","), self.calls_with("shared: ")[0].split(",")
        self.assertNotIn("imap", static)
        for name in ("igbinary", "redis", "memcached"):
            self.assertNotIn(name, shared)

    def test_resume_and_deadline_only_apply_to_a_discovery_and_must_be_valid(self):
        bad = self.scratch / "bad.txt"
        bad.write_text("imap\nNot-An-Extension\n")
        for env, message in (
            ({"DISCOVER_DEADLINE": "1"}, "only apply with DISCOVER_MODULE_LIST"),
            ({"DISCOVER_MODULE_LIST": str(self.scratch / "x"), "DISCOVER_DEADLINE": "soon"}, "must be epoch seconds"),
            ({"DISCOVER_MODULE_LIST": str(self.scratch / "x"), "DISCOVER_RESUME": str(bad)}, "names an invalid extension"),
        ):
            with self.subTest(env=env):
                result = self.build("8.6.0", PHP_SOURCE="tag", **env)
                self.assertNotEqual(0, result.returncode)
                self.assertIn(message, result.stderr)

    def test_the_module_comparison_ignores_left_out_lines(self):
        modules = self.scratch / "modules.txt"
        modules.write_text("Core\nZend OPcache\n")
        expected = self.scratch / "expected.txt"
        expected.write_text("core\nopcache\n!imap\n# comment\n")
        result = subprocess.run(
            [str(ROOT / "scripts/compare-modules.sh"), str(modules), str(expected), "exact"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        expected.write_text("core\nopcache\n!bad name\n")
        self.assertEqual(0, subprocess.run(
            [str(ROOT / "scripts/compare-modules.sh"), str(modules), str(expected), "exact"],
            capture_output=True, check=False).returncode)

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


# `spc dev:extensions pdo_sqlsrv,redis,curl` as StaticPHP 2.8.5 prints it, colors included.
DEPENDENCY_TABLE = (
    " ┌────────────┬──────────────┬──────────────┬─────────────┬────────────────┬───────────┐\n"
    " │\x1b[2m name       \x1b[22m│\x1b[2m lib-depends  \x1b[22m│\x1b[2m lib-suggests \x1b[22m│\x1b[2m ext-depends \x1b[22m"
    "│\x1b[2m ext-suggests   \x1b[22m│\x1b[2m unix-only \x1b[22m│\n"
    " ├────────────┼──────────────┼──────────────┼─────────────┼────────────────┼───────────┤\n"
    " │ pdo_sqlsrv │ php          │              │ pdo,sqlsrv  │                │ false     │\n"
    " │ redis      │ php          │ zstd, liblz4 │             │ session, igbinary │ false  │\n"
    " │ curl       │ curl         │              │             │                │ false     │\n"
    " └────────────┴──────────────┴──────────────┴─────────────┴────────────────┴───────────┘\n"
)


class AttributionTests(unittest.TestCase):
    def attribute(self, lines, extensions="imap,igbinary,xhprof,zip,xdebug,redis", extra=(), table=True):
        with tempfile.TemporaryDirectory() as scratch:
            build = pathlib.Path(scratch).resolve() / "build"
            (build / "log").mkdir(parents=True)
            text = "\n".join(line.replace("BUILD", str(build)) for line in lines) + "\n"
            (build / "log/spc.shell.log").write_text(text)
            (build / "dependencies.txt").write_text(DEPENDENCY_TABLE)
            dependencies = ("--dependencies", str(build / "dependencies.txt")) if table else ()
            result = subprocess.run(
                [str(ROOT / "scripts/attribute-build-failure"), "--log-dir", str(build / "log"), "--extensions", extensions,
                 *dependencies, *extra],
                capture_output=True, text=True, check=False,
            )
        self.assertEqual(0, result.returncode, result.stderr)
        return result.stdout.split()

    def test_compiler_errors_and_failed_targets_name_their_extension(self):
        # Lines as StaticPHP 2.8.5 logged the PHP 8.6.0RC4 imap failure.
        self.assertEqual(["imap"], self.attribute([
            "clang: error: unsupported option '-print-multi-os-directory'",
            "BUILD/source/php-src/ext/imap/php_imap.c:463:32: error: use of undeclared identifier 'XtOffsetOf'",
            "make: *** [ext/imap/php_imap.lo] Error 1",
        ]))
        self.assertEqual(["igbinary", "xdebug", "xhprof", "zip"], self.attribute([
            "BUILD/source/xdebug/src/base/base.c:9: error: x",
            "BUILD/source/php-src/ext/xhprof-src/extension/xhprof.c:1:2: fatal error: 'x.h' file not found",
            "BUILD/source/ext-zip/php_zip.c:3:4: error: x",
            "make: *** [ext/igbinary/igbinary.lo] Error 1",
        ]))

    def test_an_error_in_a_shared_header_belongs_to_the_extension_that_included_it(self):
        # Lines as StaticPHP 2.8.5 logged the PHP 8.6.0RC4 mongodb failure.
        self.assertEqual(["mongodb"], self.attribute([
            "In file included from BUILD/source/php-src/ext/mongodb/src/phongo_bson.c:20:",
            "BUILD/buildroot/include/php/Zend/zend_enum.h:39:9: error: unknown type name 'typeof'",
            "BUILD/buildroot/include/php/Zend/zend_portability.h:409:9: note: expanded from macro",
            "make: *** [src/phongo_bson.lo] Error 1",
        ], extensions="mongodb,redis"))
        # A chain applies only to the diagnostic right after it.
        self.assertEqual([], self.attribute([
            "In file included from BUILD/source/php-src/ext/mongodb/src/phongo_bson.c:20:",
            "BUILD/buildroot/include/php/Zend/zend_enum.h:39:9: warning: harmless",
            "BUILD/source/php-src/Zend/zend.c:1:1: error: core",
        ], extensions="mongodb"))

    def test_a_left_out_extension_built_again_as_a_dependency_leaves_out_what_needs_it(self):
        # pdo_sqlsrv depends on sqlsrv in StaticPHP's own table, which php-bin never repeats.
        self.assertEqual(["pdo_sqlsrv"], self.attribute(
            ["BUILD/source/php-src/ext/sqlsrv/shared/core_stream.cpp:280:9: error: no matching function"],
            extensions="pdo_sqlsrv,redis,xdebug", extra=("--unbuilt", "sqlsrv,imap"),
        ))
        # Without the table nothing is guessed.
        self.assertEqual([], self.attribute(
            ["BUILD/source/php-src/ext/sqlsrv/init.cpp:1:1: error: x"],
            extensions="redis", extra=("--unbuilt", "sqlsrv"),
        ))

    def test_a_failed_configure_belongs_to_the_one_extension_it_builds(self):
        # Lines as StaticPHP 2.8.5 logged xdebug refusing PHP 8.6.0RC4.
        self.assertEqual(["xdebug"], self.attribute([
            "> Executing command: BUILD/buildroot/bin/phpize",
            "> Executing command: ./configure --enable-xdebug=shared --with-php-config=BUILD/buildroot/bin/php-config"
            " --enable-shared --disable-static",
            "checking for supported PHP version... configure: error: not supported. Need a PHP version >= 8.0.0"
            " and < 8.6.0 (found 8.6.0RC4)",
        ]))
        # PHP's own configure builds many extensions, so its errors name none.
        self.assertEqual([], self.attribute([
            "> Executing command: ./configure --enable-redis=shared --enable-xhprof=shared --enable-cli",
            "configure: error: something in core",
        ]))

    def test_an_error_in_a_library_named_like_an_extension_names_nothing(self):
        # StaticPHP extracts libzstd and libcurl to source/zstd and source/curl, beside
        # extension sources such as source/xdebug; its table says which are libraries.
        self.assertEqual([], self.attribute([
            "BUILD/source/zstd/lib/compress/zstd_compress.c:1:1: error: library",
            "BUILD/source/curl/lib/url.c:1:1: error: library",
        ], extensions="zstd,curl,redis"))
        # Without the table no directory outside php-src is known to be an extension's.
        self.assertEqual([], self.attribute(
            ["BUILD/source/xdebug/src/base/base.c:9: error: x"], table=False,
        ))

    def test_errors_outside_an_extension_name_nothing(self):
        self.assertEqual([], self.attribute([
            "BUILD/source/php-src/Zend/zend.c:1:1: error: core",
            "BUILD/source/php-src/main/main.c:1:1: error: core",
            "BUILD/source/libheif/heif.c:1:1: error: library",
            "/elsewhere/source/php-src/ext/imap/php_imap.c:1:1: error: another tree",
            "BUILD/source/php-src/ext/sodium/x.c:1:1: error: not tried",
            "make: *** [all] Error 2",
        ]))


class CanarySelectionTests(unittest.TestCase):
    def select(self, maintained, tags, releases, lists):
        """`lists` maps each branch with a module list to that list's text."""
        with tempfile.TemporaryDirectory() as scratch:
            scratch = pathlib.Path(scratch)
            (scratch / "policy.json").write_text(json.dumps({"maintainedBranches": maintained}))
            (scratch / "tags.txt").write_text("\n".join(tags))
            (scratch / "releases.txt").write_text("\n".join(releases))
            modules = scratch / "expected-modules"
            modules.mkdir()
            for branch, text in lists.items():
                (modules / f"{branch}.txt").write_text(text)
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
        return [(item["version"], item["branch"], item["mode"]) for item in json.loads(result.stdout)]

    def test_unpublished_patches_are_built_as_released_and_the_next_branch_is_discovered(self):
        self.assertEqual(
            [("8.4.27", "8.4", "release"), ("8.5.12", "8.5", "release"), ("8.6.0RC4", "8.6", "discover")],
            self.select(
                ["8.4", "8.5"],
                ["8.4.26", "8.4.27", "8.5.11", "8.5.12", "8.6.0alpha1", "8.6.0beta3", "8.6.0RC4", "8.6.0RC10x",
                 "8.3.99", "7.4.33", "php_8_6_0RC4"],
                ["8.4.26-2", "8.4.26", "8.5.11-3"],
                {"8.4": "core\n", "8.5": "core\n"},
            ),
        )

    def test_published_branches_build_nothing_and_a_stable_tag_outranks_its_candidates(self):
        self.assertEqual([], self.select(["8.5"], ["8.5.12", "8.5.12RC1"], ["8.5.12"], {"8.5": "core\n"}))
        self.assertEqual(
            [("9.0.0", "9.0", "discover")],
            self.select(["8.6"], ["8.6.3", "9.0.0RC2", "9.0.0", "9.0.0RC9"], ["8.6.3"], {"8.6": "core\n"}),
        )

    def test_a_branch_that_leaves_extensions_out_is_rechecked_at_its_newest_stable_tag(self):
        self.assertEqual(
            [("8.6.2", "8.6", "release"), ("8.6.2", "8.6", "recheck")],
            self.select(["8.6"], ["8.6.1", "8.6.2"], ["8.6.1"], {"8.6": "core\n!imap\n"}),
        )
        self.assertEqual(
            [("8.6.1", "8.6", "recheck")],
            self.select(["8.6"], ["8.6.1"], ["8.6.1-2"], {"8.6": "core\n!imap\n"}),
        )

    def test_a_maintained_branch_with_its_first_release_in_flight_builds_its_newest_stable_tag(self):
        self.assertEqual(
            [("8.6.0", "8.6", "release")],
            self.select(["8.5", "8.6"], ["8.5.12", "8.6.0RC4", "8.6.0"], ["8.5.12"], {"8.5": "core\n", "8.6": "core\n"}),
        )

    def test_selection_rejects_inputs_it_cannot_trust(self):
        self.assertIn("maintains no branch", self.select([], ["8.5.1"], [], {"8.5": "core\n"}))
        self.assertIn("not a major.minor branch", self.select(["8"], ["8.5.1"], [], {"8.5": "core\n"}))


class NewBranchDiscoveryWorkflowTests(unittest.TestCase):
    def setUp(self):
        from autorelease.verify import load_workflow

        self.jobs = load_workflow(ROOT / ".github/workflows/autorelease-implement.yml")["jobs"]
        self.discover = load_workflow(ROOT / ".github/workflows/autorelease-discover.yml")["jobs"]["discover"]

    def step(self, job, name):
        return next(item for item in job["steps"] if item.get("name") == name)

    def test_discovery_runs_in_three_resumable_passes_that_always_run(self):
        passes = [self.jobs[f"discover-{number}"] for number in (1, 2, 3)]
        for number, job in enumerate(passes, start=1):
            # A skipped job would skip every later job, even through the ones that ran.
            self.assertNotIn("if", job)
            self.assertEqual("./.github/workflows/autorelease-discover.yml", job["uses"])
            self.assertEqual({"contents": "read"}, job["permissions"])
            self.assertEqual(str(number), job["with"]["pass"])
            self.assertIs(number == 3, job["with"]["final"])
        self.assertEqual("${{ needs.discovery-scope.outputs.discover == 'true' }}", passes[0]["with"]["needed"])
        self.assertEqual("${{ needs.discover-1.outputs.pending == 'true' }}", passes[1]["with"]["needed"])
        self.assertEqual("${{ needs.discover-2.outputs.pending == 'true' }}", passes[2]["with"]["needed"])
        decide = self.step(self.jobs["discovery-scope"], "Decide")["run"]
        self.assertIn('if [[ ! -e "expected-modules/${version%.*}.txt" ]]; then', decide)
        self.assertNotIn("if", self.jobs["implement"])

    def test_a_pass_builds_read_only_and_hands_over_what_it_left_out(self):
        self.assertNotIn("if", self.discover)
        self.assertEqual({"contents": "read"}, self.discover["permissions"])
        self.assertIn("'macos-26' || 'ubuntu-latest'", self.discover["runs-on"])
        build = self.step(self.discover, "Build, leaving out extensions that do not compile")
        self.assertEqual("inputs.needed", build["if"])
        self.assertIn('DISCOVER_MODULE_LIST="$PWD/discovered/modules.txt"', build["run"])
        self.assertIn('DISCOVER_DEADLINE="$(( $(date +%s) + 290 * 60 ))"', build["run"])
        self.assertIn('if [[ "$status" == "75" && "$FINAL" != "true" ]]; then', build["run"])
        handover = self.step(self.discover, "Hand what this pass left out to the next pass")
        resume = self.step(self.discover, "Download what the previous pass left out")
        self.assertEqual(
            "discovery-pending-${{ github.run_id }}-${{ inputs.pass == '1' && '2' || '3' }}", handover["with"]["name"]
        )
        self.assertEqual("discovery-pending-${{ github.run_id }}-${{ inputs.pass }}", resume["with"]["name"])

    def test_only_a_discovered_list_reaches_the_edit_and_a_failed_pass_is_reported(self):
        apply = self.step(self.jobs["implement"], "Apply the admitted lifecycle edit")
        self.assertEqual("${{ needs.discovery-scope.outputs.discover }}", apply["env"]["DISCOVERED"])
        self.assertIn('module_list=(--module-list "$RUNNER_TEMP/discovered/modules.txt")', apply["run"])
        notify = self.jobs["notify-failure"]
        for number in (1, 2, 3):
            self.assertIn(f"discover-{number}", notify["needs"])
            self.assertIn(f"needs['discover-{number}'].result == 'failure'", notify["if"])


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
        build = next(step for step in canary["steps"] if step.get("name") == "Build and verify")["run"]
        # Only a release-mode build is strict; discover and recheck find what compiles.
        self.assertIn('if [[ "$MODE" == "release" ]]; then\n  scripts/build.sh "$VERSION" s4\n', build)
        self.assertIn('DISCOVER_MODULE_LIST="$PWD/canary/modules.txt" \\\n  DISCOVER_DEADLINE=', build)
        uploads = [step["with"]["path"] for step in canary["steps"] if "upload-artifact" in str(step.get("uses", ""))]
        self.assertEqual(["canary/incomplete-*.txt", "canary/compiles-again-*.txt"], uploads)
        report = self.jobs["report"]
        self.assertEqual({"issues": "write"}, report["permissions"])
        used = [step["uses"].split("@")[0] for step in report["steps"] if "uses" in step]
        self.assertEqual(["actions/download-artifact", "actions/download-artifact"], used)

    def test_an_unfinished_discovery_resumes_and_never_closes_the_canary_issue(self):
        steps = {step.get("name"): step for step in self.jobs["canary"]["steps"]}
        restore = steps["Restore an unfinished discovery"]
        save = steps["Save the discovery state for the next run"]
        # One cache per mode and exact tag; the newest saved state is the one resumed.
        self.assertEqual(restore["with"]["path"], save["with"]["path"])
        self.assertEqual(restore["with"]["key"], save["with"]["key"])
        self.assertTrue(restore["with"]["key"].startswith(restore["with"]["restore-keys"]))
        self.assertIn("${{ matrix.build.version }}", restore["with"]["restore-keys"])
        build = steps["Build and verify"]["run"]
        self.assertIn('export DISCOVER_RESUME="$PWD/canary/resume/pending.txt"', build)
        self.assertIn("cp canary/modules.txt.pending canary/resume/pending.txt", build)
        # A finished discovery saves an empty state, so the next run tries everything again.
        self.assertIn(": > canary/resume/pending.txt", build)
        report = next(step for step in self.jobs["report"]["steps"]
                      if step.get("name") == "File, update, or close the canary issue")["run"]
        self.assertLess(report.index('if [[ -n "$unfinished" ]]'), report.index("gh issue close"))

    def test_a_recheck_names_the_exact_list_edit_for_extensions_that_compile_again(self):
        step = next(step for step in self.jobs["canary"]["steps"]
                    if step.get("name") == "Find left-out extensions that compile again")
        with tempfile.TemporaryDirectory() as scratch:
            scratch = pathlib.Path(scratch)
            (scratch / "scripts").mkdir()
            shutil.copy(ROOT / "scripts/lib.sh", scratch / "scripts/lib.sh")
            (scratch / "expected-modules").mkdir()
            (scratch / "expected-modules/8.6.txt").write_text("core\nphar\n!imap\n!igbinary\n!redis\n!xdebug\n")
            (scratch / "canary").mkdir()
            # imap is static and xdebug off by default; igbinary and redis still fail.
            (scratch / "canary/modules.txt").write_text("core\nimap\nphar\n!igbinary\n!redis\n")
            result = subprocess.run(["bash", "-eo", "pipefail", "-c", step["run"]], cwd=scratch,
                                    env={**os.environ, "BRANCH": "8.6"}, capture_output=True, text=True, check=False)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(
                "expected-modules/8.6.txt: remove !imap, !xdebug; add imap\n",
                (scratch / "canary/compiles-again-8.6.txt").read_text(),
            )

    def test_nothing_in_the_canary_starts_or_publishes_a_release(self):
        text = (ROOT / ".github/workflows/upstream-canary.yml").read_text()
        for forbidden in ("gh workflow run", "gh release", "contents: write", "actions: write"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
