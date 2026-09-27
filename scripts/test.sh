#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

"$SCRIPT_DIR/check-public-language.sh"
"$SCRIPT_DIR/validate-codex-action-inputs"
"$SCRIPT_DIR/validate-structured-output-schemas"
"$PROJECT_ROOT/autorelease/control.py" validate-policy
"$SCRIPT_DIR/compare-modules.sh" \
  "$PROJECT_ROOT/tests/fixtures/modules.txt" \
  "$PROJECT_ROOT/tests/fixtures/expected-exact.txt" \
  exact
"$SCRIPT_DIR/compare-modules.sh" \
  "$PROJECT_ROOT/tests/fixtures/modules.txt" \
  "$PROJECT_ROOT/tests/fixtures/expected-subset.txt" \
  subset

if "$SCRIPT_DIR/compare-modules.sh" \
  "$PROJECT_ROOT/tests/fixtures/modules.txt" \
  "$PROJECT_ROOT/tests/fixtures/expected-missing.txt" \
  subset; then
  echo "Expected a missing-module failure." >&2
  exit 1
fi

# The packaging check runs inside checkouts that autorelease then inspects for
# an exact tree, so its output goes to scratch space instead of the working
# tree, where a leftover file would read as an unsealed edit.
SCRATCH_DIR="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/php-bin-test.XXXXXX")"
# The build writes normalized paths into the kit; so must the fixture.
SCRATCH_DIR="$(cd "$SCRATCH_DIR" && pwd -P)"
ARTIFACT_DIR="$SCRATCH_DIR/artifacts"
export ARTIFACT_DIR
trap 'rm -rf "$SCRATCH_DIR"' EXIT

# A build tree shaped like build.sh leaves it: the build kit still holding this
# machine's paths, two shared extensions, and the verified extension list.
FIXTURE_BUILD="$SCRATCH_DIR/build"
FIXTURE_ROOT="$FIXTURE_BUILD/buildroot"
mkdir -p "$FIXTURE_ROOT/bin" "$FIXTURE_ROOT/modules" \
  "$FIXTURE_ROOT/include/php/main" "$FIXTURE_ROOT/lib/php/build"
cp "$PROJECT_ROOT/tests/fixtures/php" "$FIXTURE_ROOT/bin/php"
cat > "$FIXTURE_ROOT/bin/php-config" <<EOF
#! /bin/sh
SED="/opt/homebrew/bin/gsed"
prefix="$FIXTURE_ROOT"
datarootdir="/php"
include_dir="\${prefix}/include/php"
ldflags=" -L$FIXTURE_ROOT/lib"
libs="-lz -liconv"
extension_dir="$FIXTURE_ROOT/lib/php/extensions/no-debug-non-zts-20240924"
program_prefix="$FIXTURE_ROOT/bin/"
configure_options=" '--with-bz2=$FIXTURE_ROOT' 'PKG_CONFIG=$FIXTURE_BUILD/pkgroot/aarch64-darwin/bin/pkg-config'"
ini_path="/usr/local/etc/php"
EOF
cat > "$FIXTURE_ROOT/bin/phpize" <<EOF
#!/bin/sh
prefix='$FIXTURE_ROOT'
datarootdir='/php'
SED="/opt/homebrew/bin/gsed"
EOF
printf '#define CONFIGURE_COMMAND " '"'"'--with-bz2=%s'"'"'"\n' "$FIXTURE_ROOT" \
  > "$FIXTURE_ROOT/include/php/main/build-defs.h"
printf '#define PHP_OS "Darwin"\n' > "$FIXTURE_ROOT/include/php/main/php_config.h"
printf 'dnl fixture\n' > "$FIXTURE_ROOT/lib/php/build/phpize.m4"
printf 'fixture\n' > "$FIXTURE_ROOT/modules/demo_on.so"
printf 'fixture\n' > "$FIXTURE_ROOT/modules/demo_off.so"
printf 'demo_on on\ndemo_off off zend requires=demo_on\n' > "$FIXTURE_BUILD/shared-extensions.txt"

"$SCRIPT_DIR/package.sh" "$FIXTURE_ROOT/bin/php" 8.4.99-1
ARCHIVE="$ARTIFACT_DIR/php-8.4.99-1-cli-macos-aarch64.tar.gz"
grep -Fq 'php-8.4.99-1-cli-macos-aarch64.tar.gz' "$ARTIFACT_DIR/SHA256SUMS"
tar -tzf "$ARCHIVE" | LC_ALL=C sort > "$SCRATCH_DIR/members.txt"
for member in \
  ./bin/php ./bin/php-config ./bin/phpize \
  ./include/php/main/build-defs.h ./include/php/main/php_config.h \
  ./lib/php/build/phpize.m4 \
  ./lib/php/extensions/demo_off.so ./lib/php/extensions/demo_on.so \
  ./share/php-bin/manifest.json ./LICENSE ./NOTICE
do
  grep -Fqx "$member" "$SCRATCH_DIR/members.txt"
done
if grep -F 'modules' "$SCRATCH_DIR/members.txt"; then
  echo "The build tree's modules folder leaked into the archive." >&2
  exit 1
fi

mkdir "$SCRATCH_DIR/unpacked"
tar -xzf "$ARCHIVE" -C "$SCRATCH_DIR/unpacked"
if grep -rF "$FIXTURE_BUILD" "$SCRATCH_DIR/unpacked"; then
  echo "A build-host path survived packaging." >&2
  exit 1
fi
# The ${prefix} reference is literal php-config text, not shell expansion.
# shellcheck disable=SC2016
for line in \
  'SED="/usr/bin/sed"' \
  'prefix="@PHP_BIN_PREFIX@"' \
  'datarootdir="@PHP_BIN_PREFIX@/share"' \
  'include_dir="${prefix}/include/php"' \
  'ldflags=""' \
  'libs=""' \
  'extension_dir="@PHP_BIN_PREFIX@/lib/php/extensions"' \
  'program_prefix=""' \
  'ini_path="@PHP_BIN_PREFIX@/bin"'
do
  grep -Fqx "$line" "$SCRATCH_DIR/unpacked/bin/php-config"
done
grep -Fqx "prefix='@PHP_BIN_PREFIX@'" "$SCRATCH_DIR/unpacked/bin/phpize"
grep -Fqx 'SED="/usr/bin/sed"' "$SCRATCH_DIR/unpacked/bin/phpize"
python3 - "$SCRATCH_DIR/unpacked/share/php-bin/manifest.json" <<'PY'
import json
import sys

actual = json.load(open(sys.argv[1]))
expected = {
    "schemaVersion": 1,
    "release": "8.4.99-1",
    "phpVersion": "8.4.99",
    "extensions": [
        {"name": "demo_on", "zend": False, "default": True, "requires": []},
        {"name": "demo_off", "zend": True, "default": False, "requires": ["demo_on"]},
    ],
}
if actual != expected:
    sys.exit(f"Unexpected manifest: {actual}")
PY

# Packaging refuses any build-host path it does not know how to relocate.
printf '#define PHP_ICONV_H_PATH <%s/include/iconv.h>\n' "$FIXTURE_ROOT" \
  >> "$FIXTURE_ROOT/include/php/main/php_config.h"
if "$SCRIPT_DIR/package.sh" "$FIXTURE_ROOT/bin/php" 8.4.99 2> "$SCRATCH_DIR/leftover.log"; then
  echo "Expected packaging to reject a leftover build-host path." >&2
  exit 1
fi
grep -Fq 'include/php/main/php_config.h' "$SCRATCH_DIR/leftover.log"
printf '#define PHP_OS "Darwin"\n' > "$FIXTURE_ROOT/include/php/main/php_config.h"

# And any shared extension the verified list does not name.
printf 'fixture\n' > "$FIXTURE_ROOT/modules/stray.so"
if "$SCRIPT_DIR/package.sh" "$FIXTURE_ROOT/bin/php" 8.4.99 2>/dev/null; then
  echo "Expected packaging to reject an unlisted shared extension." >&2
  exit 1
fi

# shellcheck source=scripts/lib.sh
source "$SCRIPT_DIR/lib.sh"

# build.sh receives the publisher's full release tag; a rebuild revision builds
# the same PHP patch.
test "$(php_source_version 8.4)" = 8.4
test "$(php_source_version 8.4.5)" = 8.4.5
test "$(php_source_version 8.4.5-12)" = 8.4.5
for target in 8 8.4.5-0 8.4.5-x 8.4.5-1-2; do
  if php_source_version "$target" > /dev/null 2>&1; then
    echo "Expected $target to be rejected as a build target." >&2
    exit 1
  fi
done

# The shipped list parses, and a requirement listed after the extension that
# needs it is rejected, since php.ini lines load in list order.
read_shared_extensions "$PROJECT_ROOT/stages/s4-shared.txt" > /dev/null
printf 'demo_off off requires=demo_on\ndemo_on on\n' > "$SCRATCH_DIR/misordered.txt"
if read_shared_extensions "$SCRATCH_DIR/misordered.txt" > /dev/null 2>&1; then
  echo "Expected a requirement listed after its dependent to be rejected." >&2
  exit 1
fi

(
  cd "$PROJECT_ROOT"
  python3 -m unittest discover -s tests -p 'test_*.py'
)

echo "All script tests passed."
