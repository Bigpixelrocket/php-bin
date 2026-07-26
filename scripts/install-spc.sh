#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

require_macos_arm64
require_file "$PROJECT_ROOT/.spc-version"
require_file "$PROJECT_ROOT/.spc-sha256"

SPC_VERSION="$(tr -d '[:space:]' < "$PROJECT_ROOT/.spc-version")"
EXPECTED_SHA256="$(tr -d '[:space:]' < "$PROJECT_ROOT/.spc-sha256")"
INSTALL_DIR="$PROJECT_ROOT/.spc"
SPC_BIN="$INSTALL_DIR/spc"
DOWNLOAD_URL="https://github.com/crazywhalecc/static-php-cli/releases/download/${SPC_VERSION}/spc-macos-aarch64.tar.gz"
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/php-bin-spc.XXXXXX")"
trap 'rm -rf "$TEMP_DIR"' EXIT

mkdir -p "$INSTALL_DIR"
curl --fail --location --retry 3 --output "$TEMP_DIR/spc.tar.gz" "$DOWNLOAD_URL"

ACTUAL_SHA256="$(shasum -a 256 "$TEMP_DIR/spc.tar.gz" | awk '{print $1}')"
if [[ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]]; then
  echo "StaticPHP checksum mismatch." >&2
  echo "Expected: $EXPECTED_SHA256" >&2
  echo "Actual:   $ACTUAL_SHA256" >&2
  exit 1
fi

tar -xzf "$TEMP_DIR/spc.tar.gz" -C "$TEMP_DIR"
if [[ ! -f "$TEMP_DIR/spc" ]]; then
  echo "The StaticPHP archive did not contain the expected spc executable." >&2
  exit 1
fi

install -m 0755 "$TEMP_DIR/spc" "$SPC_BIN"
"$SPC_BIN" --version
