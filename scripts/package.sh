#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <php-binary> <release-tag>" >&2
  exit 2
fi

PHP_BIN="$1"
RELEASE_TAG="$2"

if [[ ! "$RELEASE_TAG" =~ ^8\.[2-5]\.[0-9]+(-[1-9][0-9]*)?$ ]]; then
  echo "Release tag must look like 8.4.5 or 8.4.5-1." >&2
  exit 2
fi

if [[ ! -x "$PHP_BIN" ]]; then
  echo "PHP executable not found: $PHP_BIN" >&2
  exit 2
fi

PHP_PATCH_VERSION="${RELEASE_TAG%%-*}"
ACTUAL_VERSION="$("$PHP_BIN" -r 'echo PHP_VERSION;')"
if [[ "$ACTUAL_VERSION" != "$PHP_PATCH_VERSION" ]]; then
  echo "Binary reports PHP $ACTUAL_VERSION, but release tag is $RELEASE_TAG." >&2
  exit 1
fi

ARTIFACT_DIR="$PROJECT_ROOT/.artifacts"
ARTIFACT_NAME="php-${RELEASE_TAG}-cli-macos-aarch64.tar.gz"
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/php-bin-package.XXXXXX")"
trap 'rm -rf "$TEMP_DIR"' EXIT

mkdir -p "$ARTIFACT_DIR" "$TEMP_DIR/package/bin"
install -m 0755 "$PHP_BIN" "$TEMP_DIR/package/bin/php"
install -m 0644 "$PROJECT_ROOT/LICENSE" "$TEMP_DIR/package/LICENSE"
install -m 0644 "$PROJECT_ROOT/NOTICE" "$TEMP_DIR/package/NOTICE"

COPYFILE_DISABLE=1 tar -czf "$ARTIFACT_DIR/$ARTIFACT_NAME" -C "$TEMP_DIR/package" .
(
  cd "$ARTIFACT_DIR"
  shasum -a 256 "$ARTIFACT_NAME" > SHA256SUMS
)

tar -tzf "$ARTIFACT_DIR/$ARTIFACT_NAME" | grep -Eq '^\./bin/php$'
echo "Created $ARTIFACT_DIR/$ARTIFACT_NAME"
echo "Created $ARTIFACT_DIR/SHA256SUMS"
