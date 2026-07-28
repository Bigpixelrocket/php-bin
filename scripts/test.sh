#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

"$SCRIPT_DIR/check-public-language.sh"
"$SCRIPT_DIR/validate-codex-action-inputs"
"$SCRIPT_DIR/validate-structured-output-schemas"
"$PROJECT_ROOT/maintenance/control.py" validate-policy
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

"$SCRIPT_DIR/package.sh" "$PROJECT_ROOT/tests/fixtures/php" 8.4.99
tar -tzf "$PROJECT_ROOT/.artifacts/php-8.4.99-cli-macos-aarch64.tar.gz" \
  | grep -Eq '^\./bin/php$'
grep -Fq 'php-8.4.99-cli-macos-aarch64.tar.gz' \
  "$PROJECT_ROOT/.artifacts/SHA256SUMS"
rm -f \
  "$PROJECT_ROOT/.artifacts/php-8.4.99-cli-macos-aarch64.tar.gz" \
  "$PROJECT_ROOT/.artifacts/SHA256SUMS"
rmdir "$PROJECT_ROOT/.artifacts" 2>/dev/null || true

(
  cd "$PROJECT_ROOT"
  python3 -m unittest discover -s tests -p 'test_*.py'
)

echo "All script tests passed."
