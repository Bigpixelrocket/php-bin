"""Behavior of scripts/build.sh around StaticPHP, and of the upstream canary."""

import base64
import hashlib
import json
import os
import re
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
      printf '%s\n' "${FAKE_TARGET:-new}" > source/php-src/target.txt
      if [[ -n "${FAKE_PATCH_DIR:-}" ]]; then cp "$FAKE_PATCH_DIR"/* source/php-src/sapi/micro/patches/; fi
      for entry in $FAKE_EXT_DIRS; do
        mkdir -p "source/php-src/ext/${entry%%:*}"
        touch "source/php-src/ext/${entry%%:*}/${entry#*:}"
      done
    fi
    if [[ "$1 ${2:-}" == "craft craft-build.yml" ]]; then
      echo "left: $(cd source/php-src/ext && echo *)" >> "$SPC_CALLS"
      echo "micro: ${SPC_MICRO_PATCHES-unset}" >> "$SPC_CALLS"
      echo "target: $(cat source/php-src/target.txt)" >> "$SPC_CALLS"
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

# Records each download as `<url> <headers read from -H files>` and writes
# FAKE_CURL_BODY to the -o file, or fails when FAKE_CURL_FAIL is set.
FAKE_CURL = textwrap.dedent(
    """\
    #!/usr/bin/env bash
    out="" headers="" url=""
    while (($#)); do
      case "$1" in
        -o) out="$2"; shift ;;
        -H) if [[ "$2" == @* ]]; then headers+="$(cat "${2#@}")"; else headers+="$2"; fi; shift ;;
        --proto | --retry | --connect-timeout) shift ;;
        -*) ;;
        *) url="$1" ;;
      esac
      shift
    done
    echo "$url ${headers:-no-headers}" >> "$CURL_CALLS"
    if [[ -n "${FAKE_CURL_FAIL:-}" ]]; then exit 22; fi
    printf '%s' "${FAKE_CURL_BODY:-pinned archive}" > "$out"
    """
)
PINNED_BODY_DIGEST = hashlib.sha256(b"pinned archive").hexdigest()

UPSTREAM_LAYOUT = "standard:config.m4 date:config0.m4 imap/tests:x.phpt com_dotnet:config.w32 skeleton:README"


class BuildScriptTests(unittest.TestCase):
    def setUp(self):
        self.scratch = pathlib.Path(tempfile.mkdtemp(prefix="php-bin-build-test."))
        self.addCleanup(shutil.rmtree, self.scratch)
        # A copy of the recipe, so the build folder never lands in the checkout.
        self.root = self.scratch / "php-bin"
        for name in ("scripts", "stages", "expected-modules"):
            shutil.copytree(ROOT / name, self.root / name)
        # Every pinned digest names the fake download, so no test reaches the network.
        self.shared_list = self.root / "stages/s4-shared.txt"
        self.shared_list.write_text(
            re.sub(r"sha256=[0-9a-f]{64}", f"sha256={PINNED_BODY_DIGEST}", self.shared_list.read_text())
        )
        bin_dir = self.scratch / "bin"
        bin_dir.mkdir()
        for name, body in (("spc", FAKE_SPC), ("uname", FAKE_UNAME), ("curl", FAKE_CURL)):
            path = bin_dir / name
            path.write_text(body)
            path.chmod(0o755)
        self.calls = self.scratch / "calls.txt"
        self.env = {
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "SPC_BIN": str(bin_dir / "spc"),
            "SPC_CALLS": str(self.calls),
            "CURL_CALLS": str(self.scratch / "curl.txt"),
            "FAKE_EXT_DIRS": UPSTREAM_LAYOUT,
        }
        self.env.pop("GITHUB_TOKEN", None)

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

    def test_a_branch_applies_its_own_php_src_patches_before_the_build(self):
        branch_patches = self.root / "patches/php-src/8.3"
        branch_patches.mkdir(parents=True)
        (branch_patches / "0001-backport.patch").write_text(
            "--- a/target.txt\n+++ b/target.txt\n@@ -1 +1 @@\n-new\n+patched\n"
        )
        result = self.build("8.3.36")
        self.assertEqual(["patched"], self.calls_with("target: "))
        self.assertIn("Applied php-src patch patches/php-src/8.3/0001-backport.patch.", result.stdout)
        # Another branch has no directory and builds its source unchanged.
        self.calls.unlink()
        self.build("8.4.27")
        self.assertEqual(["new"], self.calls_with("target: "))
        # A source that already carries the patch, as a reused extracted tree does, keeps it.
        self.calls.unlink()
        result = self.build("8.3.36", FAKE_TARGET="patched")
        self.assertEqual(["patched"], self.calls_with("target: "))
        self.assertIn("patches/php-src/8.3/0001-backport.patch is already applied.", result.stdout)
        # A patch that does not apply stops the build before StaticPHP builds anything.
        self.calls.unlink()
        result = self.build("8.3.36", FAKE_TARGET="other")
        self.assertNotEqual(0, result.returncode)
        self.assertEqual(["doctor", "craft craft-download.yml", "extract php-src,micro"], self.calls.read_text().splitlines())
        self.assertIn("patches/php-src/8.3/0001-backport.patch does not apply to PHP 8.3.36.", result.stderr)

    def test_the_php_src_backports_apply_only_to_their_branch(self):
        directories = sorted(path.name for path in (ROOT / "patches/php-src").iterdir())
        self.assertEqual(["8.3"], directories)
        backport = (ROOT / "patches/php-src/8.3/0001-autotools-refactor-avx-512-checks.patch").read_text()
        self.assertIn("d7ddf83dde6bd0829d991a6c45aa8baa85705ff9", backport)
        self.assertIn("+[php_cv_have_avx512],", backport)
        self.assertIn("+[php_cv_have_avx512vbmi],", backport)

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

    def curl_calls(self):
        return (self.scratch / "curl.txt").read_text().splitlines()

    def test_a_github_pin_downloads_with_the_read_only_token_and_builds_the_verified_file(self):
        spx = "https://api.github.com/repos/NoiseByNorthwest/php-spx/tarball/refs/tags/v0.4.22"
        self.build("8.4.27", GITHUB_TOKEN="read-only-token")
        self.assertEqual([f"{spx} Authorization: Bearer read-only-token"], self.curl_calls())
        build_dir = self.root / ".build/8.4.27/s4"
        self.assertEqual("pinned archive", (build_dir / "pinned/spx.tar.gz").read_text())
        download = (build_dir / "craft-download.yml").read_text()
        self.assertIn(f'    - "spx:file://{build_dir}/pinned/spx.tar.gz"\n', download)
        self.assertNotIn("php-spx", download)
        # Every other pin is still StaticPHP's to download, and the token never leaves GitHub.
        self.assertIn('    - "xdebug:https://pecl.php.net/get/xdebug-3.5.3.tgz"\n', download)
        # A retry keeps the verified archive instead of downloading it again.
        self.calls.unlink()
        self.build("8.4.27", GITHUB_TOKEN="read-only-token")
        self.assertEqual(1, len(self.curl_calls()))

    def test_a_pin_download_without_a_token_or_off_github_sends_no_credentials(self):
        self.shared_list.write_text(self.shared_list.read_text().replace(
            "pin=xdebug:https://pecl.php.net/get/xdebug-3.5.3.tgz",
            f"pin=xdebug:https://pecl.php.net/get/xdebug-3.5.3.tgz sha256={PINNED_BODY_DIGEST}",
        ))
        self.build("8.4.27", GITHUB_TOKEN="read-only-token")
        self.assertIn("https://pecl.php.net/get/xdebug-3.5.3.tgz no-headers", self.curl_calls())
        download = (self.root / ".build/8.4.27/s4/craft-download.yml").read_text()
        self.assertIn("xdebug:file://", download)
        (self.scratch / "curl.txt").unlink()
        (self.root / ".build/8.4.27/s4/pinned/spx.tar.gz").unlink()
        self.build("8.4.27")
        self.assertIn(
            "https://api.github.com/repos/NoiseByNorthwest/php-spx/tarball/refs/tags/v0.4.22 no-headers",
            self.curl_calls(),
        )

    def test_a_pin_whose_bytes_differ_from_its_digest_stops_the_build_before_staticphp(self):
        for env, message in (
            ({"FAKE_CURL_BODY": "tampered"}, f"not its pinned {PINNED_BODY_DIGEST}"),
            ({"FAKE_CURL_FAIL": "1"}, ""),
        ):
            with self.subTest(env=env):
                result = self.build("8.4.27", GITHUB_TOKEN="read-only-token", **env)
                self.assertNotEqual(0, result.returncode)
                self.assertIn(message, result.stderr)
                self.assertFalse(self.calls.exists())
                self.assertEqual([], list((self.root / ".build/8.4.27/s4/pinned").iterdir()))

    def test_git_clones_authenticate_to_github_only_with_a_token(self):
        def git_config(**env):
            self.calls.unlink(missing_ok=True)
            spc = self.scratch / "bin/spc"
            spc.write_text(FAKE_SPC.replace(
                'echo "$*" >> "$SPC_CALLS"',
                'echo "$*" >> "$SPC_CALLS"; env | grep "^GIT_CONFIG_" | sort >> "$SPC_CALLS"', 1,
            ))
            self.build("8.4.27", **env)
            return sorted({line for line in self.calls.read_text().splitlines() if line.startswith("GIT_CONFIG_")})

        token = base64.b64encode(b"x-access-token:read-only-token").decode()
        self.assertEqual([
            "GIT_CONFIG_COUNT=1",
            "GIT_CONFIG_KEY_0=http.https://github.com/.extraheader",
            f"GIT_CONFIG_VALUE_0=AUTHORIZATION: basic {token}",
        ], git_config(GITHUB_TOKEN="read-only-token"))
        # An existing environment configuration is kept, and the header added after it.
        self.assertIn(
            "GIT_CONFIG_KEY_1=http.https://github.com/.extraheader",
            git_config(GITHUB_TOKEN="read-only-token", GIT_CONFIG_COUNT="1",
                       GIT_CONFIG_KEY_0="core.autocrlf", GIT_CONFIG_VALUE_0="false"),
        )
        self.assertEqual([], git_config())

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


# Dynamic symbol tables as binutils' readelf prints them for zig-linked files, whose
# ELF OS/ABI stays System V: an ifunc's type, and a STB_GNU_UNIQUE binding, is then
# "<OS specific>: 10". The unique-ifunc, other-bits and variant-pcs tables are
# binutils 2.47's output for a g++ shared object whose st_info and st_other bytes were
# patched to those values (the last with e_machine set to AArch64). readelf
# translates those labels; a Spanish locale prints its catalog's, as binutils 2.47 does.
FAKE_READELF = textwrap.dedent(
    """\
    #!/usr/bin/env bash
    locale="${LC_ALL:-${LC_MESSAGES:-${LANG:-C}}}"
    translate() {
      if [[ "$locale" == es_* ]]; then
        sed 's/<OS specific>/<específico del SO>/g'
      else
        cat
      fi
    }
    case "$3" in
      *php)
        translate <<'TABLE'

    Symbol table '.dynsym' contains 5 entries:
       Num:    Value          Size Type    Bind   Vis      Ndx Name
         0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
         1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND memcpy@GLIBC_2.14 (3)
         2: 00000000017a0b30   581 FUNC    GLOBAL DEFAULT   15 zend_hash_find
      8809: 0000000003b502b0    13 <OS specific>: 10 GLOBAL DEFAULT   15 php_base64_encode
     25993: 0000000003b50523    13 <OS specific>: 10 GLOBAL DEFAULT   15 php_base64_decode_ex
         5: 0000000004a00000     8 OBJECT  GLOBAL DEFAULT   24 executor_globals
    TABLE
        ;;
      *mongodb.so)
        translate <<'TABLE'

    Symbol table '.dynsym' contains 6 entries:
       Num:    Value          Size Type    Bind   Vis      Ndx Name
         0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
         1: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND php_base64_encode
         2: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND php_base64_decode_ex
         3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND memcpy@GLIBC_2.14 (3)
         4: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
         5: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND getrandom
         6: 00000000000a1000    42 FUNC    GLOBAL DEFAULT   12 get_module
    TABLE
        ;;
      *unique-ifunc.so)
        translate <<'TABLE'

    Symbol table '.dynsym' contains 10 entries:
       Num:    Value          Size Type    Bind   Vis      Ndx Name
         0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
         1: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND __cxa_finalize@GLIBC_2.2.5 (2)
         2: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterTMCloneTable
         3: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
         4: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMCloneTable
         5: 000000000000110e     8 FUNC    GLOBAL DEFAULT    9 copy
         6: 000000000000400c     4 OBJECT  <OS specific>: 10 DEFAULT   20 _ZN6holderIiE5valueE
         7: 0000000000004010     4 OBJECT  <OS specific>: 10 DEFAULT   20 _ZZ14shared_countervE7counter
         8: 00000000000010f7    23 FUNC    GLOBAL DEFAULT    9 _Z5touchv
         9: 00000000000010ef     8 <OS specific>: 10 <OS specific>: 10 DEFAULT    9 php_base64_encode
    TABLE
        ;;
      *other-bits.so)
        translate <<'TABLE'

    Symbol table '.dynsym' contains 4 entries:
       Num:    Value          Size Type    Bind   Vis      Ndx Name
         0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
         1: 0000000000000000     0 FUNC    GLOBAL DEFAULT [<other>: 80]   UND zend_vector_kernel
         2: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterTMCloneTable
         3: 000000000000110e     8 FUNC    GLOBAL DEFAULT [<other>: 80]     9 copy
    TABLE
        ;;
      *variant-pcs.so)
        translate <<'TABLE'

    Symbol table '.dynsym' contains 5 entries:
       Num:    Value          Size Type    Bind   Vis      Ndx Name
         0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
         1: 0000000000000000     0 FUNC    GLOBAL DEFAULT [VARIANT_PCS]   UND zend_vector_kernel
         2: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterTMCloneTable
         3: 000000000000110e     8 FUNC    GLOBAL DEFAULT [VARIANT_PCS]     9 copy
         4: 00000000000010ef     8 <OS specific>: 10 GLOBAL DEFAULT    9 php_base64_encode
    TABLE
        ;;
    esac
    """
)


class ElfSymbolTests(unittest.TestCase):
    def symbols(self, function, file, **env):
        with tempfile.TemporaryDirectory() as scratch:
            readelf = pathlib.Path(scratch) / "readelf"
            readelf.write_text(FAKE_READELF)
            readelf.chmod(0o755)
            result = subprocess.run(
                ["bash", "-c", f'source "$1" && {function} "$2"', "-", str(ROOT / "scripts/lib.sh"), file],
                env={**os.environ, "PATH": f"{scratch}:{os.environ['PATH']}", **env},
                capture_output=True, text=True, check=True,
            )
        return set(result.stdout.split())

    def test_an_ifunc_bin_php_exports_counts_as_defined(self):
        defined = self.symbols("elf_defined_symbols", "buildroot/bin/php")
        self.assertLessEqual(
            {"zend_hash_find", "php_base64_encode", "php_base64_decode_ex", "executor_globals"}, defined
        )
        self.assertNotIn("memcpy", defined)
        self.assertNotIn("DEFAULT", defined)

    def test_an_extension_needs_its_unversioned_strong_references(self):
        self.assertEqual(
            {"php_base64_encode", "php_base64_decode_ex", "getrandom"},
            self.symbols("elf_required_symbols", "buildroot/modules/mongodb.so"),
        )
        # With bin/php's ifuncs counted, only the glibc call newer than the baseline is left.
        self.assertEqual(
            {"getrandom"},
            self.symbols("elf_required_symbols", "modules/mongodb.so")
            - self.symbols("elf_defined_symbols", "bin/php"),
        )

    def test_a_row_with_an_os_specific_type_and_binding_keeps_its_name(self):
        self.assertEqual(
            {"copy", "_ZN6holderIiE5valueE", "_ZZ14shared_countervE7counter", "_Z5touchv", "php_base64_encode"},
            self.symbols("elf_defined_symbols", "lib-unique-ifunc.so"),
        )

    def test_a_note_after_the_visibility_leaves_the_columns_in_place(self):
        for file in ("lib-other-bits.so", "lib-variant-pcs.so"):
            with self.subTest(file=file):
                self.assertEqual({"zend_vector_kernel"}, self.symbols("elf_required_symbols", file))
                self.assertLessEqual({"copy"}, self.symbols("elf_defined_symbols", file))
        self.assertIn("php_base64_encode", self.symbols("elf_defined_symbols", "lib-variant-pcs.so"))

    def test_a_translated_locale_reads_the_same_symbols(self):
        for locale in ({"LANG": "es_ES.UTF-8"}, {"LC_ALL": "es_ES.UTF-8"}):
            with self.subTest(locale=locale):
                env = {"LC_ALL": "", "LC_MESSAGES": "", **locale}
                self.assertEqual(
                    self.symbols("elf_defined_symbols", "bin/php", LC_ALL="C"),
                    self.symbols("elf_defined_symbols", "bin/php", **env),
                )
                self.assertEqual(
                    {"getrandom"},
                    self.symbols("elf_required_symbols", "modules/mongodb.so", **env)
                    - self.symbols("elf_defined_symbols", "bin/php", **env),
                )

    def test_every_readelf_call_runs_in_the_c_locale(self):
        for script in ("scripts/lib.sh", "scripts/build.sh"):
            for number, line in enumerate((ROOT / script).read_text().splitlines(), 1):
                code = line.split("#", 1)[0]
                if "readelf " in code:
                    with self.subTest(script=script, line=number):
                        self.assertIn("LC_ALL=C readelf ", code)


# A Linux build machine for smoke-test-linux.sh: FAKE_ARCH names the architecture,
# docker fails each image's first FAKE_PULL_FAILURES pulls and reports a module
# list of `core` for every run, and sleep only records its delay.
FAKE_SMOKE_TOOLS = {
    "uname": '#!/usr/bin/env bash\ncase "$1" in -s) echo Linux ;; -m) echo "$FAKE_ARCH" ;; *) echo Linux ;; esac\n',
    "getconf": "#!/usr/bin/env bash\necho 'glibc 2.39'\n",
    "sleep": '#!/usr/bin/env bash\necho "sleep $1" >> "$DOCKER_CALLS"\n',
    "docker": textwrap.dedent(
        """\
        #!/usr/bin/env bash
        echo "$*" >> "$DOCKER_CALLS"
        case "$1" in
          pull)
            tries="$(grep -cxF "pull -q $3" "$DOCKER_CALLS")"
            (( tries > ${FAKE_PULL_FAILURES:-0} )) || exit 1
            ;;
          run) printf -- '--- modules\\ncore\\n--- end\\n' ;;
        esac
        """
    ),
}


class SmokeTestImageTests(unittest.TestCase):
    def smoke(self, arch="x86_64", failures=0):
        with tempfile.TemporaryDirectory() as scratch:
            scratch = pathlib.Path(scratch)
            bin_dir = scratch / "bin"
            bin_dir.mkdir()
            for name, body in FAKE_SMOKE_TOOLS.items():
                (bin_dir / name).write_text(body)
                (bin_dir / name).chmod(0o755)
            (scratch / "php/share/php-bin").mkdir(parents=True)
            (scratch / "php/share/php-bin/manifest.json").write_text('{"extensions": []}')
            subprocess.run(["tar", "-czf", str(scratch / "php.tar.gz"), "-C", str(scratch / "php"), "."], check=True)
            (scratch / "expected.txt").write_text("core\n")
            calls = scratch / "docker.txt"
            calls.touch()
            result = subprocess.run(
                [str(ROOT / "scripts/smoke-test-linux.sh"), str(scratch / "php.tar.gz"), str(scratch / "expected.txt")],
                env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "DOCKER_CALLS": str(calls),
                     "FAKE_ARCH": arch, "FAKE_PULL_FAILURES": str(failures), "TMPDIR": str(scratch)},
                capture_output=True, text=True, check=False,
            )
            return result, calls.read_text().splitlines()

    def test_every_image_is_pinned_by_digest_beside_its_tag(self):
        text = (ROOT / "scripts/smoke-test-linux.sh").read_text()
        pinned = re.findall(r"([a-z0-9/._-]+)@sha256:[0-9a-f]{64} # ([a-z0-9/._-]+):\S+", text)
        self.assertEqual(
            ["debian", "fedora", "ubuntu", "ubuntu", "gentoo/stage3", "archlinux"], [name for name, _ in pinned]
        )
        self.assertEqual([name for name, _ in pinned], [tag for _, tag in pinned])
        # A tag appears only in the comment beside its digest, never as a reference.
        for line in text.splitlines():
            if not line.lstrip().startswith("#"):
                self.assertNotRegex(line.split(" # ")[0], r"\b(fedora|ubuntu|debian|archlinux|gentoo/stage3):")

    def test_each_pinned_image_runs_by_digest_and_arch_only_on_x86_64(self):
        for arch, images in (("x86_64", 6), ("aarch64", 5)):
            with self.subTest(arch=arch):
                result, calls = self.smoke(arch)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                pulls = [call.split()[2] for call in calls if call.startswith("pull ")]
                self.assertEqual(images + 1, len(pulls))
                self.assertTrue(all(re.fullmatch(r"[a-z0-9/._-]+@sha256:[0-9a-f]{64}", image) for image in pulls))
                self.assertEqual(arch == "x86_64", any(image.startswith("archlinux@") for image in pulls))
                # The baseline-CPU run reuses the pinned Debian image under QEMU.
                qemu = [call for call in calls if call.startswith("run ") and "QEMU=qemu-" in call]
                self.assertEqual(1, len(qemu))
                self.assertIn(pulls[3], qemu[0])

    def test_a_failed_pull_is_retried_with_backoff(self):
        result, calls = self.smoke(failures=2)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        first = calls[: calls.index(next(call for call in calls if call.startswith("run ")))]
        self.assertEqual(
            ["pull", "sleep 15", "pull", "sleep 30", "pull"],
            [call.split()[0] if call.startswith("pull") else call for call in first],
        )
        self.assertIn("(attempt 1 of 4); retrying in 15s.", result.stderr)

    def test_an_image_that_never_pulls_fails_after_four_tries(self):
        result, calls = self.smoke(failures=99)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("FAIL could not pull", result.stdout)
        self.assertEqual(["sleep 15", "sleep 30", "sleep 60"], [call for call in calls if call.startswith("sleep")][:3])
        self.assertEqual(4 * 7, len([call for call in calls if call.startswith("pull ")]))


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
        self.discover_jobs = load_workflow(ROOT / ".github/workflows/autorelease-discover.yml")["jobs"]
        self.discover = self.discover_jobs["discover"]

    def step(self, job, name):
        return next(item for item in job["steps"] if item.get("name") == name)

    PLATFORMS = ("macos-aarch64", "linux-x86_64", "linux-aarch64")

    def run_step(self, job, name, cwd, env):
        script = self.step(job, name)["run"].replace("${{ github.run_id }}", "77")
        return subprocess.run(["bash", "-eo", "pipefail", "-c", script], cwd=cwd,
                              env={**os.environ, **env}, capture_output=True, text=True, check=False)

    def test_discovery_runs_on_every_platform_in_three_resumable_passes_that_always_run(self):
        passes = [self.jobs[f"discover-{number}"] for number in (1, 2, 3)] + [self.jobs["discover-reconcile"]]
        for number, job in enumerate(passes, start=1):
            # A skipped job would skip every later job, even through the ones that ran.
            self.assertNotIn("if", job)
            self.assertEqual("./.github/workflows/autorelease-discover.yml", job["uses"])
            self.assertEqual({"contents": "read"}, job["permissions"])
            self.assertEqual(str(number) if number < 4 else "reconcile", job["with"]["pass"])
            self.assertIs(number >= 3, job["with"]["final"])
        self.assertEqual("${{ needs.discovery-scope.outputs.platforms }}", passes[0]["with"]["platforms"])
        self.assertEqual("${{ needs.discover-1.outputs.pending }}", passes[1]["with"]["platforms"])
        self.assertEqual("${{ needs.discover-2.outputs.pending }}", passes[2]["with"]["platforms"])
        self.assertEqual("${{ needs.discovery-union.outputs.reconcile }}", passes[3]["with"]["platforms"])
        for name in ("discovery-union", "discovery-final"):
            self.assertNotIn("if", self.jobs[name])
            self.assertEqual({"contents": "read"}, self.jobs[name]["permissions"])
        decide = self.step(self.jobs["discovery-scope"], "Decide")["run"]
        self.assertIn('if [[ ! -e "expected-modules/${version%.*}.txt" ]]; then', decide)
        self.assertIn("platforms='[\"macos-aarch64\",\"linux-x86_64\",\"linux-aarch64\"]'", decide)
        self.assertNotIn("if", self.jobs["implement"])
        self.assertIn("discovery-final", self.jobs["implement"]["needs"])

    def test_a_pass_builds_read_only_per_platform_and_hands_over_what_it_left_out(self):
        self.assertNotIn("if", self.discover)
        self.assertEqual({"contents": "read"}, self.discover["permissions"])
        self.assertEqual(
            {"macos-aarch64": "macos-26", "linux-x86_64": "ubuntu-latest", "linux-aarch64": "ubuntu-24.04-arm"},
            {leg["platform"]: leg["runner"] for leg in self.discover["strategy"]["matrix"]["include"]},
        )
        self.assertEqual(
            "${{ contains(fromJSON(inputs.platforms), matrix.platform) && matrix.runner || 'ubuntu-latest' }}",
            self.discover["runs-on"],
        )
        build = self.step(self.discover, "Build, leaving out extensions that do not compile")
        self.assertEqual("env.NEEDED == 'true'", build["if"])
        self.assertIn('DISCOVER_MODULE_LIST="$PWD/discovered/modules.txt"', build["run"])
        self.assertIn('DISCOVER_DEADLINE="$(( $(date +%s) + 290 * 60 ))"', build["run"])
        self.assertIn('if [[ "$status" == "75" && "$FINAL" != "true" ]]; then', build["run"])
        handover = self.step(self.discover, "Hand what this pass left out to the next pass")
        resume = self.step(self.discover, "Download what the previous pass left out")
        union = self.step(self.discover, "Download what any platform left out")
        self.assertEqual(
            "discovery-pending-${{ github.run_id }}-${{ inputs.pass == '1' && '2' || '3' }}-${{ matrix.platform }}",
            handover["with"]["name"],
        )
        self.assertEqual(
            "discovery-pending-${{ github.run_id }}-${{ inputs.pass }}-${{ matrix.platform }}", resume["with"]["name"]
        )
        self.assertEqual("discovery-union-${{ github.run_id }}", union["with"]["name"])
        retained = self.step(self.discover, "Retain the discovered module list")
        self.assertEqual(
            "${{ inputs.pass == 'reconcile' && 'reconciled' || 'discovered' }}-modules-${{ github.run_id }}-${{ matrix.platform }}",
            retained["with"]["name"],
        )

    def test_the_pending_platforms_become_the_next_pass_input(self):
        collect = self.step(self.discover_jobs["collect"], "Collect pending platforms")
        for flags, expected in (({}, []), ({"LINUX_X86_64": "true"}, ["linux-x86_64"]),
                                ({"MACOS_AARCH64": "true", "LINUX_AARCH64": "true"}, ["macos-aarch64", "linux-aarch64"])):
            with tempfile.TemporaryDirectory() as scratch:
                output = pathlib.Path(scratch) / "output"
                result = subprocess.run(["bash", "-eo", "pipefail", "-c", collect["run"]],
                                        env={**os.environ, "GITHUB_OUTPUT": str(output), **flags},
                                        capture_output=True, text=True, check=False)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(f"pending={json.dumps(expected, separators=(',', ':'))}\n", output.read_text())

    def unite(self, lists):
        """Run the union step over each platform's discovered list; return (result, reconcile, union)."""
        scratch = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, scratch)
        (scratch / "scripts").mkdir()
        shutil.copy(ROOT / "scripts/lib.sh", scratch / "scripts/lib.sh")
        for platform, body in lists.items():
            directory = scratch / "temp/discovered" / f"discovered-modules-77-{platform}"
            directory.mkdir(parents=True)
            (directory / "modules.txt").write_text(body)
        output = scratch / "output"
        result = self.run_step(self.jobs["discovery-union"], "Unite the left-out extensions", scratch,
                               {"DISCOVER": "true", "RUN_ID": "77", "RUNNER_TEMP": str(scratch / "temp"),
                                "GITHUB_OUTPUT": str(output)})
        reconcile = None
        if output.exists():
            reconcile = json.loads(output.read_text().removeprefix("reconcile="))
        union = (scratch / "union/pending.txt").read_text() if (scratch / "union/pending.txt").exists() else None
        return result, reconcile, union

    def test_an_extension_left_out_anywhere_is_left_out_everywhere(self):
        same = "core\nphar\n!imap\n"
        result, reconcile, union = self.unite({platform: same for platform in self.PLATFORMS})
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual([], reconcile)
        self.assertEqual("imap\n", union)
        # Linux x86_64 also left out redis; the other two platforms rebuild without it.
        result, reconcile, union = self.unite({
            "macos-aarch64": same, "linux-x86_64": "core\nphar\n!imap\n!redis\n", "linux-aarch64": same,
        })
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(["macos-aarch64", "linux-aarch64"], reconcile)
        self.assertEqual("imap\nredis\n", union)
        # A platform whose list is missing stops the union rather than shrinking it.
        result, _, _ = self.unite({"macos-aarch64": same, "linux-x86_64": same})
        self.assertNotEqual(0, result.returncode)

    def compare(self, lists, reconcile):
        scratch = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, scratch)
        for name, body in lists.items():
            directory = scratch / "temp/lists" / name
            directory.mkdir(parents=True)
            (directory / "modules.txt").write_text(body)
        result = self.run_step(self.jobs["discovery-final"], "Compare the platforms' lists", scratch,
                               {"RECONCILE": json.dumps(reconcile), "RUN_ID": "77",
                                "RUNNER_TEMP": str(scratch / "temp")})
        final = scratch / "final/modules.txt"
        return result, final.read_text() if final.exists() else None

    def test_the_new_branch_gets_one_list_only_when_every_platform_reports_it(self):
        listed = "core\nphar\n!imap\n!redis\n"
        # Reconciled platforms are read from the reconcile pass, the rest from their own.
        result, final = self.compare({
            "discovered-modules-77-macos-aarch64": "core\nphar\nredis\n!imap\n",
            "reconciled-modules-77-macos-aarch64": listed,
            "discovered-modules-77-linux-x86_64": listed,
            "reconciled-modules-77-linux-aarch64": listed,
        }, ["macos-aarch64", "linux-aarch64"])
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(listed, final)
        # A module one platform alone reports cannot be published from one list.
        result, _ = self.compare({
            "discovered-modules-77-macos-aarch64": listed,
            "discovered-modules-77-linux-x86_64": listed,
            "discovered-modules-77-linux-aarch64": "core\nphar\nposix\n!imap\n!redis\n",
        }, [])
        self.assertNotEqual(0, result.returncode)
        self.assertIn("The linux-aarch64 module list differs from the others", result.stderr)

    def test_the_new_branch_must_build_on_every_platform_before_it_merges(self):
        build = self.jobs["build-new-branch"]
        self.assertEqual(
            {"macos-aarch64": "macos-26", "linux-x86_64": "ubuntu-latest", "linux-aarch64": "ubuntu-24.04-arm"},
            {leg["platform"]: leg["runner"] for leg in build["strategy"]["matrix"]["include"]},
        )
        self.assertEqual({"contents": "read"}, build["permissions"])
        # Each Linux leg runs the publish smoke test before the edit can merge.
        smoke = self.step(build, "Package and smoke test on Linux distributions")
        self.assertEqual("startsWith(matrix.platform, 'linux-')", smoke["if"])
        self.assertNotIn("github.token", json.dumps(smoke))
        self.assertIn('./scripts/smoke-test-linux.sh "$archive" "expected-modules/${VERSION%.*}.txt"', smoke["run"])
        names = [step.get("name") for step in build["steps"]]
        self.assertLess(names.index("Build and compare modules exactly"), names.index("Package and smoke test on Linux distributions"))
        retained = self.step(build, "Retain the module comparison")
        self.assertEqual("new-branch-build-${{ github.run_id }}-${{ matrix.platform }}", retained["with"]["name"])
        combine = self.step(self.jobs["notify-failure"], "Combine the platforms' module comparisons")
        with tempfile.TemporaryDirectory() as scratch:
            scratch = pathlib.Path(scratch)
            for platform, diff in (("linux-x86_64", "Missing modules:\n  - imap\n"), ("macos-aarch64", "")):
                directory = scratch / "new-branch-build" / f"new-branch-build-77-{platform}"
                directory.mkdir(parents=True)
                (directory / "module-diff.txt").write_text(diff)
            script = combine["run"].replace("${{ github.run_id }}", "77")
            subprocess.run(["bash", "-eo", "pipefail", "-c", script], cwd=scratch, check=True)
            self.assertEqual("linux-x86_64:\nMissing modules:\n  - imap\n",
                             (scratch / "new-branch-build/module-diff.txt").read_text())

    def test_only_a_discovered_list_reaches_the_edit_and_a_failed_pass_is_reported(self):
        apply = self.step(self.jobs["implement"], "Apply the admitted lifecycle edit")
        self.assertEqual("${{ needs.discovery-scope.outputs.discover }}", apply["env"]["DISCOVERED"])
        self.assertIn('module_list=(--module-list "$RUNNER_TEMP/discovered/modules.txt")', apply["run"])
        notify = self.jobs["notify-failure"]
        for job in ("discover-1", "discover-2", "discover-3", "discovery-union", "discover-reconcile", "discovery-final"):
            self.assertIn(job, notify["needs"])
            self.assertIn(f"needs['{job}'].result == 'failure'", notify["if"])


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
        steps = {step.get("name"): step for step in self.jobs["report"]["steps"]}
        # A marker that cannot be downloaded fails the report rather than closing the issue.
        self.assertNotIn("continue-on-error", steps["Download unfinished discoveries"])
        report = steps["File, update, or close the canary issue"]["run"]
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
                                    env={**os.environ, "BRANCH": "8.6", "PLATFORM": "linux-x86_64"},
                                    capture_output=True, text=True, check=False)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(
                "expected-modules/8.6.txt: remove !imap, !xdebug; add imap\n",
                (scratch / "canary/compiles-again-8.6-linux-x86_64.txt").read_text(),
            )

    def test_a_list_change_is_offered_as_one_line_only_when_every_platform_reports_it(self):
        step = next(step for step in self.jobs["report"]["steps"]
                    if step.get("name") == "Report left-out extensions that compile again")
        # Stop the script where it reaches GitHub: the test reads what it found.
        script = step["run"].split('number="$(gh issue list')[0] + 'printf "%s" "$found" > found.txt\n'
        line = "expected-modules/8.6.txt: remove !imap; add imap"
        cases = (
            ({"macos-aarch64": line, "linux-x86_64": line, "linux-aarch64": line}, line),
            ({"macos-aarch64": line, "linux-x86_64": line},
             f"linux-x86_64 reports: {line}\nmacos-aarch64 reports: {line}"),
        )
        for reports, expected in cases:
            with self.subTest(reports=sorted(reports)), tempfile.TemporaryDirectory() as scratch:
                scratch = pathlib.Path(scratch)
                (scratch / "compiles-again").mkdir()
                for platform, text in reports.items():
                    (scratch / f"compiles-again/compiles-again-8.6-{platform}.txt").write_text(text + "\n")
                subprocess.run(["bash", "-eo", "pipefail", "-c", script], cwd=scratch, check=True)
                self.assertEqual(expected, (scratch / "found.txt").read_text())

    def test_the_canary_builds_every_platform_and_smoke_tests_linux_releases(self):
        canary = self.jobs["canary"]
        platforms = canary["strategy"]["matrix"]["platform"]
        self.assertEqual(
            {"macos-aarch64": "macos-26", "linux-x86_64": "ubuntu-latest", "linux-aarch64": "ubuntu-24.04-arm"},
            {platform["name"]: platform["runner"] for platform in platforms},
        )
        self.assertEqual("${{ matrix.platform.runner }}", canary["runs-on"])
        smoke = next(step for step in canary["steps"] if step.get("name") == "Smoke test on Linux distributions")
        self.assertEqual("matrix.build.mode == 'release' && startsWith(matrix.platform.name, 'linux-')", smoke["if"])
        self.assertIn("scripts/smoke-test-linux.sh", smoke["run"])

    def test_nothing_in_the_canary_starts_or_publishes_a_release(self):
        text = (ROOT / ".github/workflows/upstream-canary.yml").read_text()
        for forbidden in ("gh workflow run", "gh release", "contents: write", "actions: write"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
