#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

PLATFORM="$(build_platform)"
require_file "$PROJECT_ROOT/.spc-version"

SPC_VERSION="$(tr -d '[:space:]' < "$PROJECT_ROOT/.spc-version")"
INSTALL_DIR="$PROJECT_ROOT/.spc"
SPC_BIN="$INSTALL_DIR/spc"
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/php-bin-spc.XXXXXX")"
trap 'rm -rf "$TEMP_DIR"' EXIT

# Download a pinned file from .spc-sha256 to a path, failing unless its digest
# matches the pin. Any further arguments go to curl.
fetch_pinned() {
  local url="$1" expected="$2" output="$3" actual

  shift 3
  # GitHub release downloads fail in bursts with 504s and dropped connections.
  curl --fail --location --retry 5 --retry-delay 15 --retry-all-errors \
    "$@" --output "$output" "$url" || return 1
  actual="$(sha256_of "$output")"
  if [[ "$actual" != "$expected" ]]; then
    echo "Checksum mismatch for $url." >&2
    echo "Expected: $expected" >&2
    echo "Actual:   $actual" >&2
    return 1
  fi
}

mkdir -p "$INSTALL_DIR"
SPC_PIN="$(pinned_download "spc-$PLATFORM\\.tar\\.gz")"
IFS=$'\t' read -r SPC_ARCHIVE SPC_SHA256 <<< "$SPC_PIN"
if ! fetch_pinned "https://github.com/crazywhalecc/static-php-cli/releases/download/${SPC_VERSION}/$SPC_ARCHIVE" \
  "$SPC_SHA256" "$TEMP_DIR/spc.tar.gz"; then
  # The API serves the same release asset when the download host is failing. It
  # needs a token beyond a few anonymous calls an hour; curl does not forward
  # the token when the API redirects to the storage host.
  echo "The release download host failed; fetching $SPC_ARCHIVE through the GitHub API." >&2
  RELEASES_API="https://api.github.com/repos/crazywhalecc/static-php-cli/releases"
  AUTH=()
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    AUTH=(--header "Authorization: Bearer $GITHUB_TOKEN")
  fi
  ASSET_ID="$(curl --fail --silent --show-error --retry 5 --retry-delay 15 --retry-all-errors \
    ${AUTH[@]+"${AUTH[@]}"} "$RELEASES_API/tags/$SPC_VERSION" \
    | python3 -I -c '
import json, sys
print(next(a["id"] for a in json.load(sys.stdin)["assets"] if a["name"] == sys.argv[1]))
' "$SPC_ARCHIVE")"
  fetch_pinned "$RELEASES_API/assets/$ASSET_ID" "$SPC_SHA256" "$TEMP_DIR/spc.tar.gz" \
    ${AUTH[@]+"${AUTH[@]}"} --header "Accept: application/octet-stream"
fi

tar -xzf "$TEMP_DIR/spc.tar.gz" -C "$TEMP_DIR"
if [[ ! -f "$TEMP_DIR/spc" ]]; then
  echo "The StaticPHP archive did not contain the expected spc executable." >&2
  exit 1
fi

install -m 0755 "$TEMP_DIR/spc" "$SPC_BIN"
"$SPC_BIN" --version

# On Linux, StaticPHP compiles with zig, and left alone it installs whichever zig
# release is newest on the day of the build. build.sh installs this pinned
# archive into each build instead, so every build uses the same compiler.
if [[ "$PLATFORM" == linux-* ]]; then
  ZIG_PIN="$(pinned_download "zig-${PLATFORM#linux-}-linux-[0-9.]+\\.tar\\.xz")"
  IFS=$'\t' read -r ZIG_ARCHIVE ZIG_SHA256 <<< "$ZIG_PIN"
  ZIG_VERSION="${ZIG_ARCHIVE##*-linux-}"
  ZIG_VERSION="${ZIG_VERSION%.tar.xz}"
  # ziglang.org asks automated downloads to fall back to its community mirrors,
  # and the pinned digest makes every mirror as trustworthy as the origin.
  for ZIG_URL in \
    "https://ziglang.org/download/$ZIG_VERSION/$ZIG_ARCHIVE" \
    "https://ziglang.freetls.fastly.net/$ZIG_ARCHIVE" \
    "https://pkg.machengine.org/zig/$ZIG_ARCHIVE"
  do
    if fetch_pinned "$ZIG_URL" "$ZIG_SHA256" "$TEMP_DIR/$ZIG_ARCHIVE"; then
      break
    fi
    rm -f "$TEMP_DIR/$ZIG_ARCHIVE"
  done
  require_file "$TEMP_DIR/$ZIG_ARCHIVE"
  install -m 0644 "$TEMP_DIR/$ZIG_ARCHIVE" "$INSTALL_DIR/$ZIG_ARCHIVE"
  echo "Pinned zig $ZIG_VERSION: $INSTALL_DIR/$ZIG_ARCHIVE"
fi
