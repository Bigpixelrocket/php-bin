#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REJECTED_TERM="$(printf '\150\145\162\144')"

if command -v rg >/dev/null 2>&1; then
  if rg --hidden --ignore-case --glob '!.git/**' "$REJECTED_TERM" "$PROJECT_ROOT"; then
    echo "Public-language check failed." >&2
    exit 1
  fi
else
  if grep -Rni --exclude-dir=.git "$REJECTED_TERM" "$PROJECT_ROOT"; then
    echo "Public-language check failed." >&2
    exit 1
  fi
fi

echo "Public-language check passed."

