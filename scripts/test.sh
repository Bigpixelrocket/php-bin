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
ARTIFACT_DIR="${RUNNER_TEMP:-$(mktemp -d)}/php-bin-test-artifacts"
export ARTIFACT_DIR
trap 'rm -rf "$ARTIFACT_DIR"' EXIT

"$SCRIPT_DIR/package.sh" "$PROJECT_ROOT/tests/fixtures/php" 8.4.99
tar -tzf "$ARTIFACT_DIR/php-8.4.99-cli-macos-aarch64.tar.gz" \
  | grep -Eq '^\./bin/php$'
grep -Fq 'php-8.4.99-cli-macos-aarch64.tar.gz' "$ARTIFACT_DIR/SHA256SUMS"

(
  cd "$PROJECT_ROOT"
  python3 -m unittest discover -s tests -p 'test_*.py'
)

echo "All script tests passed."
