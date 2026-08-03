#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REJECTED_TERM="$(printf '\150\145\162\144')"

# Tracked files are the whole scope. The previous ripgrep and grep branches
# disagreed about hidden files, ignore rules, and build output, so whichever
# tool the runner happened to have installed decided what was checked.
tracked="$(mktemp)"
trap 'rm -f "$tracked"' EXIT

# The listing is produced and checked on its own. Folded into the grep pipeline it
# hid behind the tolerance that pipeline needs, so a run that listed nothing at all
# still reported a pass. The list is kept in a file because command substitution
# drops the NUL separators that make the names unambiguous.
if ! (cd "$PROJECT_ROOT" && git ls-files -z) > "$tracked"; then
  echo "Public-language check could not list the tracked files of $PROJECT_ROOT." >&2
  exit 1
fi

if [[ ! -s "$tracked" ]]; then
  echo "Public-language check found no tracked files in $PROJECT_ROOT." >&2
  exit 1
fi

# xargs reports 123 when any grep batch matches nothing, so the finding is read
# from the output rather than from the exit status.
matches="$(cd "$PROJECT_ROOT" && { xargs -0 grep -HIFni -e "$REJECTED_TERM" < "$tracked" || true; })"

if [[ -n "$matches" ]]; then
  printf '%s\n' "$matches" >&2
  echo "Public-language check failed." >&2
  exit 1
fi

echo "Public-language check passed."
