#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: $0 <php-binary-or-modules-file> <expected-file> [subset|exact]" >&2
  exit 2
fi

ACTUAL_SOURCE="$1"
EXPECTED_SOURCE="$2"
MODE="${3:-exact}"

if [[ "$MODE" != "subset" && "$MODE" != "exact" ]]; then
  echo "Comparison mode must be subset or exact." >&2
  exit 2
fi

if [[ ! -e "$ACTUAL_SOURCE" ]]; then
  echo "Actual module source not found: $ACTUAL_SOURCE" >&2
  exit 2
fi

if [[ ! -f "$EXPECTED_SOURCE" ]]; then
  echo "Expected module file not found: $EXPECTED_SOURCE" >&2
  exit 2
fi

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/php-bin-modules.XXXXXX")"
trap 'rm -rf "$TEMP_DIR"' EXIT

normalize_modules() {
  awk '
    NF && $0 !~ /^\[/ {
      value = tolower($0)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      if (value == "zend opcache") value = "opcache"
      if (value != "") print value
    }
  ' | LC_ALL=C sort -u
}

if [[ -x "$ACTUAL_SOURCE" ]]; then
  "$ACTUAL_SOURCE" -m | normalize_modules > "$TEMP_DIR/actual.txt"
else
  normalize_modules < "$ACTUAL_SOURCE" > "$TEMP_DIR/actual.txt"
fi

grep -Ev '^[[:space:]]*(#|$)' "$EXPECTED_SOURCE" \
  | normalize_modules > "$TEMP_DIR/expected.txt"

comm -23 "$TEMP_DIR/expected.txt" "$TEMP_DIR/actual.txt" > "$TEMP_DIR/missing.txt"
comm -13 "$TEMP_DIR/expected.txt" "$TEMP_DIR/actual.txt" > "$TEMP_DIR/extra.txt"

FAILED=0
if [[ -s "$TEMP_DIR/missing.txt" ]]; then
  echo "Missing modules:" >&2
  sed 's/^/  - /' "$TEMP_DIR/missing.txt" >&2
  FAILED=1
fi

if [[ "$MODE" == "exact" && -s "$TEMP_DIR/extra.txt" ]]; then
  echo "Unexpected modules:" >&2
  sed 's/^/  + /' "$TEMP_DIR/extra.txt" >&2
  FAILED=1
fi

if [[ "$FAILED" -ne 0 ]]; then
  exit 1
fi

echo "Module comparison passed ($MODE)."

