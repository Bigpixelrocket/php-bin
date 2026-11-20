#!/usr/bin/env bash

set -euo pipefail

# Retry a read-only gh command. A paginated request can print partial output
# before failing, so only send stdout from a successful attempt to the caller.
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
transient='HTTP (408|429|5[0-9]{2})([^0-9]|$)|unexpected EOF|connection (reset|refused)|i/o timeout|TLS handshake timeout|temporary failure in name resolution|context deadline exceeded'

for attempt in 1 2 3 4; do
  if LC_ALL=C gh "$@" > "$scratch/stdout" 2> "$scratch/stderr"; then
    cat "$scratch/stderr" >&2
    cat "$scratch/stdout"
    exit 0
  else
    status=$?
  fi
  cat "$scratch/stderr" >&2
  if (( attempt == 4 )) || ! grep -Eiq "$transient" "$scratch/stderr"; then
    echo "GitHub read (gh $1) failed after $attempt attempt(s), exit $status." >&2
    exit "$status"
  fi
  delay=$((2 ** attempt))
  echo "GitHub read (gh $1) failed on attempt $attempt of 4. Retrying in ${delay}s." >&2
  sleep "$delay"
done
