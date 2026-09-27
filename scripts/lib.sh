#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Read by the scripts that source this file, not by this file.
# shellcheck disable=SC2034
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

require_macos_arm64() {
  if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "arm64" ]]; then
    echo "This build supports macOS arm64 only." >&2
    return 1
  fi
}

require_file() {
  if [[ ! -f "$1" ]]; then
    echo "Required file not found: $1" >&2
    return 1
  fi
}

# Print a shared-extension list (see stages/s4-shared.txt) as tab-separated
# rows: name, default (on|off), loader (extension|zend_extension), requires
# (comma list or -), and pin (<source>:<url> or -). Any malformed line, unknown
# field, duplicate, or unresolvable requirement fails the whole list, so a typo
# can never silently drop an extension from a release.
read_shared_extensions() {
  awk '
    function fail(message) {
      printf "%s:%d: %s\n", FILENAME, FNR, message > "/dev/stderr"
      failed = 1
      exit 1
    }
    { sub(/#.*/, "") }
    NF == 0 { next }
    {
      name = $1
      state = $2
      loader = "extension"
      requires = "-"
      pin = "-"
      if (name !~ /^[a-z][a-z0-9_]*$/) fail("invalid extension name: " name)
      if (state != "on" && state != "off") fail("default must be on or off: " state)
      for (i = 3; i <= NF; i++) {
        if ($i == "zend") {
          loader = "zend_extension"
        } else if ($i ~ /^requires=[a-z][a-z0-9_]*(,[a-z][a-z0-9_]*)*$/) {
          requires = substr($i, 10)
        } else if ($i ~ /^pin=[A-Za-z0-9_-]+:https:\/\/[^[:space:]]+$/) {
          pin = substr($i, 5)
        } else {
          fail("unknown field: " $i)
        }
      }
      if (name in states) fail("duplicate extension: " name)
      states[name] = state
      order[++count] = name
      rows[name] = name "\t" state "\t" loader "\t" requires "\t" pin
      needs[name] = requires
    }
    END {
      if (failed) exit 1
      for (i = 1; i <= count; i++) {
        name = order[i]
        if (needs[name] == "-") continue
        split(needs[name], required, ",")
        for (j in required) {
          dependency = required[j]
          if (!(dependency in states)) {
            printf "%s: %s requires unlisted extension %s\n", FILENAME, name, dependency > "/dev/stderr"
            exit 1
          }
          if (states[name] == "on" && states[dependency] != "on") {
            printf "%s: default-on %s requires off-by-default %s\n", FILENAME, name, dependency > "/dev/stderr"
            exit 1
          }
        }
      }
      for (i = 1; i <= count; i++) print rows[order[i]]
    }
  ' "$1"
}
