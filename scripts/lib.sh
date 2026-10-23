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

# Print the PHP source version to build for a build.sh target: a branch such as
# 8.4, an exact patch such as 8.4.5, or a release tag such as 8.4.5-1. The
# revision numbers a rebuild of the same patch, so it names the release, never
# the PHP source.
php_source_version() {
  if [[ ! "$1" =~ ^[0-9]+\.[0-9]+(\.[0-9]+(-[1-9][0-9]*)?)?$ ]]; then
    echo "PHP version must be a major.minor branch, an exact patch version, or a release tag like 8.4.5-1." >&2
    return 1
  fi
  printf '%s\n' "${1%%-*}"
}

# A branch's module list, expected-modules/<branch>.txt, holds one module name per
# line as `php -m` reports it once normalized (see normalize_modules), for the
# static binary plus every default-on shared extension. A `!<extension>` line
# names a stage extension that branch does not build because it does not compile
# there; the build leaves it out and the module comparison ignores the line.

# Print the modules a module list expects, one per line.
module_list_modules() {
  grep -Ev '^[[:space:]]*(#|!|$)' "$1" || true
}

# Print the extensions a module list says its branch does not build, one per line.
module_list_unbuilt() {
  awk '
    /^[[:space:]]*!/ {
      name = $0
      sub(/^[[:space:]]*![[:space:]]*/, "", name)
      sub(/[[:space:]]+$/, "", name)
      if (name !~ /^[a-z][a-z0-9_]*$/) {
        printf "%s:%d: invalid unbuilt extension: %s\n", FILENAME, FNR, name > "/dev/stderr"
        failed = 1
        exit 1
      }
      print name
    }
    END { if (failed) exit 1 }
  ' "$1"
}

# Normalize `php -m` output or a module list on stdin: lowercase names, one per
# line, sorted and unique, with section headers dropped.
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

# Print a shared-extension list (see stages/s4-shared.txt) as tab-separated
# rows: name, default (on|off), loader (extension|zend_extension), requires
# (comma list or -), and pin (<source>:<url> or -). Any malformed line, unknown
# field, duplicate, or unresolvable requirement fails the whole list, so a typo
# can never silently drop an extension from a release. A requirement must be
# listed before the extension that needs it: mise-php writes php.ini lines in
# this order, and PHP loads them top to bottom.
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
      position[name] = count
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
          if (position[dependency] >= i) {
            printf "%s: %s must be listed after its requirement %s\n", FILENAME, name, dependency > "/dev/stderr"
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
