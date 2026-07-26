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

if [[ ! "$PHP_VERSION" =~ ^8\.[0-5](\.[0-9]+)?$ ]]; then
  echo "PHP version must be an 8.0 through 8.5 minor or patch version." >&2
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
EOF

(
  cd "$BUILD_DIR"
  "$SPC_BIN" doctor
  "$SPC_BIN" craft -v
)

PHP_BIN="$BUILD_DIR/buildroot/bin/php"
if [[ ! -x "$PHP_BIN" ]]; then
  echo "Build completed without the expected executable: $PHP_BIN" >&2
  exit 1
fi

"$PHP_BIN" -v

if [[ "$STAGE" == "s4" ]]; then
  PHP_MINOR="${PHP_VERSION%.*}"
  if [[ "$PHP_VERSION" =~ ^8\.[0-5]$ ]]; then
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
