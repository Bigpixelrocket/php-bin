#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

require_macos_arm64

PHP_VERSION="${1:-8.4}"
STAGE="${2:-s4}"
STAGE_FILE="$PROJECT_ROOT/stages/$STAGE.txt"
SPC_BIN="${SPC_BIN:-$PROJECT_ROOT/.spc/spc}"
BUILD_DIR="$PROJECT_ROOT/.build/$PHP_VERSION/$STAGE"

if [[ ! "$PHP_VERSION" =~ ^8\.[2-5](\.[0-9]+)?$ ]]; then
  echo "PHP version must be a currently supported 8.2 through 8.5 minor or patch version." >&2
  exit 1
fi

require_file "$STAGE_FILE"
if [[ ! -x "$SPC_BIN" ]]; then
  echo "StaticPHP is not installed at $SPC_BIN." >&2
  echo "Run scripts/install-spc.sh or set SPC_BIN." >&2
  exit 1
fi

EXTENSIONS="$(grep -Ev '^[[:space:]]*(#|$)' "$STAGE_FILE" | paste -sd, -)"
mkdir -p "$BUILD_DIR"

print_failure_logs() {
  local log_file

  for log_file in \
    "$BUILD_DIR/log/spc.output.log" \
    "$BUILD_DIR/log/spc.shell.log"
  do
    if [[ -f "$log_file" ]]; then
      echo "Sanitized tail of ${log_file#"$PROJECT_ROOT/"}:" >&2
      tail -n 300 "$log_file" \
        | sed -E \
          -e 's/(Authorization:[[:space:]]*Bearer[[:space:]]+)[^"[:space:]]+/\1[REDACTED]/g' \
          -e 's/gh[a-zA-Z]_[A-Za-z0-9_]+/[REDACTED]/g' \
          -e 's/github_pat_[A-Za-z0-9_]+/[REDACTED]/g' >&2
    fi
  done
}

cat > "$BUILD_DIR/craft.yml" <<EOF
php-version: "$PHP_VERSION"
extensions: $EXTENSIONS
sapi: cli
debug: false
build-options:
  with-clean: false
  with-suggested-libs: false
  with-suggested-exts: false
  no-strip: false
download-options:
  retry: 5
extra-env:
  MACOSX_DEPLOYMENT_TARGET: "26.0"
  ac_cv_func_memset_s: "no"
EOF

if ! (
  cd "$BUILD_DIR"
  "$SPC_BIN" doctor
  "$SPC_BIN" craft
); then
  print_failure_logs
  exit 1
fi

PHP_BIN="$BUILD_DIR/buildroot/bin/php"
if [[ ! -x "$PHP_BIN" ]]; then
  echo "Build completed without the expected executable: $PHP_BIN" >&2
  exit 1
fi

"$PHP_BIN" -v

MINIMUM_MACOS_VERSION="$(vtool -show-build "$PHP_BIN" | awk '$1 == "minos" { print $2; exit }')"
if [[ "$MINIMUM_MACOS_VERSION" != "26.0" ]]; then
  echo "Expected a macOS 26.0 minimum, got: ${MINIMUM_MACOS_VERSION:-unknown}" >&2
  exit 1
fi
echo "Verified macOS minimum: $MINIMUM_MACOS_VERSION"

if [[ "$STAGE" == "s4" ]]; then
  PHP_MINOR="${PHP_VERSION%.*}"
  if [[ "$PHP_VERSION" =~ ^8\.[2-5]$ ]]; then
    PHP_MINOR="$PHP_VERSION"
  fi
  "$SCRIPT_DIR/compare-modules.sh" \
    "$PHP_BIN" \
    "$PROJECT_ROOT/expected-modules/$PHP_MINOR.txt" \
    exact
else
  "$SCRIPT_DIR/compare-modules.sh" "$PHP_BIN" "$STAGE_FILE" subset
fi

echo "Stage $STAGE passed: $PHP_BIN"
