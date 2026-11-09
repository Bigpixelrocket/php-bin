#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Read by the scripts that source this file, not by this file.
# shellcheck disable=SC2034
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Print the platform this machine builds for, as release archive names spell it:
# macos-aarch64, linux-x86_64, or linux-aarch64. Linux builds need
# glibc, since the binary links it dynamically to load shared extensions; any
# other machine fails.
build_platform() {
  case "$(uname -s)/$(uname -m)" in
    Darwin/arm64)
      echo macos-aarch64
      return
      ;;
    Linux/x86_64 | Linux/aarch64 | Linux/arm64)
      if ! getconf GNU_LIBC_VERSION > /dev/null 2>&1; then
        echo "Linux builds need a glibc system; this one has another C library." >&2
        return 1
      fi
      if [[ "$(uname -m)" == x86_64 ]]; then
        echo linux-x86_64
      else
        echo linux-aarch64
      fi
      return
      ;;
  esac
  echo "This build supports macOS arm64, Linux x86_64, and Linux aarch64 only." >&2
  return 1
}

require_supported_platform() {
  build_platform > /dev/null
}

# Print the SHA-256 digest of a file. Linux has sha256sum and macOS has shasum;
# both print the digest first.
sha256_of() {
  if command -v sha256sum > /dev/null 2>&1; then
    sha256sum "$1"
  else
    shasum -a 256 "$1"
  fi | awk '{ print $1 }'
}

# Print the file name and expected SHA-256 digest, tab-separated, of the one
# pinned download in .spc-sha256 whose name matches an extended regular
# expression. The file lists every pinned toolchain download as `<sha256>  <name>`,
# the format sha256sum prints; a missing or ambiguous match fails.
pinned_download() {
  local pins="$PROJECT_ROOT/.spc-sha256" matches

  require_file "$pins" || return 1
  # ENVIRON keeps the backslashes awk -v would treat as escape sequences.
  matches="$(PIN_PATTERN="^($1)\$" awk '$2 ~ ENVIRON["PIN_PATTERN"] { print $2 "\t" $1 }' "$pins")"
  if [[ -z "$matches" || "$matches" == *$'\n'* ]]; then
    echo "Expected exactly one pinned download matching $1 in .spc-sha256." >&2
    return 1
  fi
  if [[ ! "${matches#*$'\t'}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "The pinned digest for ${matches%%$'\t'*} is not a SHA-256 digest." >&2
    return 1
  fi
  printf '%s\n' "$matches"
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
# (comma list or -), pin (<source>:<url> or -), and the pin's SHA-256 digest (or
# -). Any malformed line, unknown field, duplicate, or unresolvable requirement
# fails the whole list, so a typo can never silently drop an extension from a
# release. A requirement must be listed before the extension that needs it:
# mise-php writes php.ini lines in this order, and PHP loads them top to bottom.
# A digest needs a pin, and a GitHub-hosted pin needs a digest, since build.sh
# downloads a pin with a digest itself (see fetch_pinned_sources there).
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
      digest = "-"
      if (name !~ /^[a-z][a-z0-9_]*$/) fail("invalid extension name: " name)
      if (state != "on" && state != "off") fail("default must be on or off: " state)
      for (i = 3; i <= NF; i++) {
        if ($i == "zend") {
          loader = "zend_extension"
        } else if ($i ~ /^requires=[a-z][a-z0-9_]*(,[a-z][a-z0-9_]*)*$/) {
          requires = substr($i, 10)
        } else if ($i ~ /^pin=[A-Za-z0-9_-]+:https:\/\/[^[:space:]]+$/) {
          pin = substr($i, 5)
        } else if ($i ~ /^sha256=[0-9a-f]+$/ && length($i) == 71) {
          digest = substr($i, 8)
        } else {
          fail("unknown field: " $i)
        }
      }
      if (digest != "-" && pin == "-") fail("sha256= needs a pin=: " name)
      if (digest == "-" && pin ~ /^[^:]+:https:\/\/([a-z.]+\.)?github(usercontent)?\.com\//) fail("a GitHub-hosted pin needs sha256=: " name)
      if (name in states) fail("duplicate extension: " name)
      states[name] = state
      order[++count] = name
      position[name] = count
      rows[name] = name "\t" state "\t" loader "\t" requires "\t" pin "\t" digest
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

# Print an ELF file's dynamic symbol table as `readelf --dyn-syms -W` does, with
# one field per column, so the name is always field 8 and the section index field 7.
# zig's linker leaves the ELF OS/ABI at System V, so readelf names an ifunc's
# STT_GNU_IFUNC type "<OS specific>: 10" and a STB_GNU_UNIQUE binding the same way,
# three fields where every other value has one; a type or binding it has no name
# for prints as "<processor specific>: N" or "<unknown>: N". Each is folded into
# one field, however many a row holds. A note readelf adds after the visibility for
# other st_other bits, such as aarch64's "[VARIANT_PCS]", is dropped. PHP 8.2 and
# 8.3 export their x86_64 base64 functions as ifuncs when built for the baseline
# CPU. readelf translates these labels, so it runs in the C locale.
elf_dynamic_symbols() {
  LC_ALL=C readelf --dyn-syms -W "$1" | sed -E \
    -e 's/ \[[^]]*\]//g' \
    -e 's/<([A-Za-z]+) specific>: *([0-9]+)/\1_specific_\2/g' \
    -e 's/<unknown>: *([0-9]+)/unknown_\1/g'
}

# Print the dynamic symbols an ELF file defines, one per line, without versions.
# Only numbered symbol rows count; the table's title and header lines do not.
elf_defined_symbols() {
  elf_dynamic_symbols "$1" | awk '$1 ~ /^[0-9]+:$/ && $7 != "UND" && $8 != "" { sub(/@.*/, "", $8); print $8 }'
}

# Print the unversioned symbols an ELF file needs from elsewhere, one per line.
# Weak references are left out, since they resolve to null when absent.
elf_required_symbols() {
  elf_dynamic_symbols "$1" | awk '$1 ~ /^[0-9]+:$/ && $7 == "UND" && $5 != "WEAK" && $8 != "" && $8 !~ /@/ { print $8 }'
}
