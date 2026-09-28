#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <php-binary> <release-tag>" >&2
  exit 2
fi

PHP_BIN="$1"
RELEASE_TAG="$2"

if [[ ! "$RELEASE_TAG" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[1-9][0-9]*)?$ ]]; then
  echo "Release tag must be an exact patch version like 8.4.5, optionally with a build number like 8.4.5-1." >&2
  exit 2
fi

if [[ ! -x "$PHP_BIN" ]]; then
  echo "PHP executable not found: $PHP_BIN" >&2
  exit 2
fi

PHP_PATCH_VERSION="${RELEASE_TAG%%-*}"
ACTUAL_VERSION="$("$PHP_BIN" -r 'echo PHP_VERSION;')"
if [[ "$ACTUAL_VERSION" != "$PHP_PATCH_VERSION" ]]; then
  echo "Binary reports PHP $ACTUAL_VERSION, but release tag is $RELEASE_TAG." >&2
  exit 1
fi

# The build and release workflows read .artifacts from the working tree, so that
# stays the default; the override exists for callers that must not write there.
ARTIFACT_DIR="${ARTIFACT_DIR:-$PROJECT_ROOT/.artifacts}"
ARTIFACT_NAME="php-${RELEASE_TAG}-cli-macos-aarch64.tar.gz"
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/php-bin-package.XXXXXX")"
trap 'rm -rf "$TEMP_DIR"' EXIT

# The binary sits in <build>/buildroot/bin; build.sh leaves the build kit, the
# shared extensions, and the shared-extension list it verified around it.
BUILDROOT="$(cd "$(dirname "$PHP_BIN")/.." && pwd)"
BUILD_DIR="$(dirname "$BUILDROOT")"
SHARED_LIST="$BUILD_DIR/shared-extensions.txt"
MARKER="@PHP_BIN_PREFIX@"
PACKAGE="$TEMP_DIR/package"

for required in bin/phpize bin/php-config include/php/main/php_config.h lib/php/build; do
  if [[ ! -e "$BUILDROOT/$required" ]]; then
    echo "Build kit is incomplete, missing: $BUILDROOT/$required" >&2
    exit 1
  fi
done
require_file "$SHARED_LIST"
SHARED_ROWS="$(read_shared_extensions "$SHARED_LIST")"

mkdir -p "$ARTIFACT_DIR" "$PACKAGE/bin" "$PACKAGE/include" \
  "$PACKAGE/lib/php/extensions" "$PACKAGE/share/php-bin"
install -m 0755 "$PHP_BIN" "$PACKAGE/bin/php"
install -m 0755 "$BUILDROOT/bin/phpize" "$PACKAGE/bin/phpize"
install -m 0755 "$BUILDROOT/bin/php-config" "$PACKAGE/bin/php-config"
cp -R "$BUILDROOT/include/php" "$PACKAGE/include/php"
cp -R "$BUILDROOT/lib/php/build" "$PACKAGE/lib/php/build"
install -m 0644 "$PROJECT_ROOT/LICENSE" "$PACKAGE/LICENSE"
install -m 0644 "$PROJECT_ROOT/NOTICE" "$PACKAGE/NOTICE"

# Stage one library header and every header of that library it reaches through
# "<prefix>..." includes, keeping the library's own layout under include/php.
stage_header_closure() {
  local source_root="$1" prefix="$2" header included
  local -a queue=("$3")
  while ((${#queue[@]})); do
    header="${queue[0]}"
    queue=("${queue[@]:1}")
    [[ -f "$PACKAGE/include/php/$header" ]] && continue
    require_file "$source_root/$header"
    mkdir -p "$(dirname "$PACKAGE/include/php/$header")"
    install -m 0644 "$source_root/$header" "$PACKAGE/include/php/$header"
    while IFS= read -r included; do
      queue+=("$included")
    done < <(sed -nE "s|^[[:space:]]*#[[:space:]]*include[[:space:]]*[\"<](${prefix}[^\">]+)[\">].*|\\1|p" \
      "$source_root/$header")
  done
}

# The installed PHP headers include three libraries the binary links statically but
# the build kit does not carry: ext/gmp includes <gmp.h>, ext/sodium includes
# <sodium.h>, and ext/uri's WHATWG parser includes lexbor's URL headers, which
# php-src compiles in but does not install. Each is staged under include/php,
# which php-config --includes names, in the library's own layout, so an extension
# that includes those PHP headers builds against the libraries this binary links.
KIT_INCLUDE="$PACKAGE/include/php"
if [[ -f "$KIT_INCLUDE/ext/gmp/php_gmp_int.h" ]]; then
  require_file "$BUILDROOT/include/gmp.h"
  install -m 0644 "$BUILDROOT/include/gmp.h" "$KIT_INCLUDE/gmp.h"
fi
if [[ -f "$KIT_INCLUDE/ext/sodium/php_libsodium.h" ]]; then
  # libsodium's headers include each other without a folder prefix, so its public
  # header folder is staged whole.
  require_file "$BUILDROOT/include/sodium.h"
  if [[ ! -d "$BUILDROOT/include/sodium" ]]; then
    echo "Build kit is incomplete, missing: $BUILDROOT/include/sodium" >&2
    exit 1
  fi
  install -m 0644 "$BUILDROOT/include/sodium.h" "$KIT_INCLUDE/sodium.h"
  mkdir -p "$KIT_INCLUDE/sodium"
  # Each copy runs in this shell, so a failed one stops packaging; find -exec would
  # report success whatever its command returned.
  copied=0
  while IFS= read -r -d '' header; do
    install -m 0644 "$header" "$KIT_INCLUDE/sodium/"
    copied=$((copied + 1))
  done < <(find "$BUILDROOT/include/sodium" -maxdepth 1 -type f -name '*.h' -print0)
  if ((copied == 0)); then
    echo "Build kit is incomplete, no headers in: $BUILDROOT/include/sodium" >&2
    exit 1
  fi
fi
if [[ -f "$KIT_INCLUDE/ext/uri/uri_parser_whatwg.h" ]]; then
  stage_header_closure "$BUILD_DIR/source/php-src/ext/lexbor" "lexbor/" lexbor/url/url.h
fi

# Ship exactly the listed shared extensions: a missing or unlisted .so means
# the build and the list the gate verified have drifted apart.
cut -f1 <<< "$SHARED_ROWS" | LC_ALL=C sort > "$TEMP_DIR/listed.txt"
find "$BUILDROOT/modules" -maxdepth 1 -name '*.so' -exec basename {} .so \; 2>/dev/null \
  | LC_ALL=C sort > "$TEMP_DIR/built.txt"
if ! diff -u "$TEMP_DIR/listed.txt" "$TEMP_DIR/built.txt" >&2; then
  echo "Shared extensions in $BUILDROOT/modules differ from $SHARED_LIST." >&2
  exit 1
fi
while IFS= read -r name; do
  install -m 0644 "$BUILDROOT/modules/$name.so" "$PACKAGE/lib/php/extensions/$name.so"
done < "$TEMP_DIR/listed.txt"

# Rewrite a file through sed without relying on GNU or BSD in-place flags.
rewrite() {
  local file="$1"
  shift
  sed "$@" "$file" > "$TEMP_DIR/rewrite"
  cat "$TEMP_DIR/rewrite" > "$file"
}

# Escape a path for a basic regular expression delimited by "|".
regex_escape() {
  printf '%s' "$1" | sed 's/[][\.*^$]/\\&/g'
}

# php-config and phpize carry the build machine's paths. Each install's
# PostInstall hook in mise-php replaces the marker with that install's folder,
# so PIE and phpize build against the install they run from. extension_dir is
# where PIE installs an extension, and the libraries only the static binary
# links against mean nothing to an extension build.
BUILDROOT_PATTERN="$(regex_escape "$(cd "$BUILDROOT" && pwd -P)")"
BUILD_DIR_PATTERN="$(regex_escape "$(cd "$BUILD_DIR" && pwd -P)")"
rewrite "$PACKAGE/bin/php-config" \
  -e 's|^SED=.*|SED="/usr/bin/sed"|' \
  -e "s|^prefix=.*|prefix=\"$MARKER\"|" \
  -e "s|^datarootdir=.*|datarootdir=\"$MARKER/share\"|" \
  -e 's|^ldflags=.*|ldflags=""|' \
  -e 's|^libs=.*|libs=""|' \
  -e "s|^extension_dir=.*|extension_dir=\"$MARKER/lib/php/extensions\"|" \
  -e 's|^program_prefix=.*|program_prefix=""|' \
  -e "s|^ini_path=.*|ini_path=\"$MARKER/bin\"|" \
  -e "s|$BUILDROOT_PATTERN|$MARKER|g" \
  -e "s|$BUILD_DIR_PATTERN|$MARKER|g"
rewrite "$PACKAGE/bin/phpize" \
  -e "s|^prefix=.*|prefix='$MARKER'|" \
  -e "s|^datarootdir=.*|datarootdir='$MARKER/share'|" \
  -e 's|^SED=.*|SED="/usr/bin/sed"|'
# build-defs.h records PHP's configure command, and gmp.h the flags GMP was
# compiled with; both are informational strings that name the build tree.
for header in main/build-defs.h gmp.h; do
  if [[ -f "$PACKAGE/include/php/$header" ]]; then
    rewrite "$PACKAGE/include/php/$header" \
      -e "s|$BUILDROOT_PATTERN|$MARKER|g" \
      -e "s|$BUILD_DIR_PATTERN|$MARKER|g"
  fi
done

# The manifest tells mise-php which shared extensions exist, how to load each
# one, and which are on by default in a fresh php.ini.
awk -F '\t' -v release="$RELEASE_TAG" -v php="$PHP_PATCH_VERSION" '
  BEGIN {
    printf "{\n  \"schemaVersion\": 1,\n  \"release\": \"%s\",\n  \"phpVersion\": \"%s\",\n  \"extensions\": [", release, php
  }
  {
    requires = ""
    if ($4 != "-") {
      count = split($4, names, ",")
      for (i = 1; i <= count; i++) requires = requires (i > 1 ? ", " : "") "\"" names[i] "\""
    }
    printf "%s\n    {\"name\": \"%s\", \"zend\": %s, \"default\": %s, \"requires\": [%s]}", (NR > 1 ? "," : ""), $1, ($3 == "zend_extension" ? "true" : "false"), ($2 == "on" ? "true" : "false"), requires
  }
  END { printf "\n  ]\n}\n" }
' <<< "$SHARED_ROWS" > "$PACKAGE/share/php-bin/manifest.json"

# Compiled binaries keep source file paths for assertion messages, as every
# release always has; everything a user reads or runs as text must not.
LEFTOVERS="$(grep -rIl -F -e "$BUILD_DIR" -e "$PROJECT_ROOT" \
  -e "$(cd "$BUILD_DIR" && pwd -P)" -e "$(cd "$PROJECT_ROOT" && pwd -P)" "$PACKAGE" || true)"
if [[ -n "$LEFTOVERS" ]]; then
  echo "Build-host paths remain in:" >&2
  printf '%s\n' "${LEFTOVERS//$PACKAGE\//  }" >&2
  exit 1
fi
if [[ -n "$(find "$PACKAGE" -type l)" ]]; then
  echo "The package contains symbolic links, which releases must not:" >&2
  find "$PACKAGE" -type l >&2
  exit 1
fi

COPYFILE_DISABLE=1 tar -czf "$ARTIFACT_DIR/$ARTIFACT_NAME" -C "$PACKAGE" .
(
  cd "$ARTIFACT_DIR"
  shasum -a 256 "$ARTIFACT_NAME" > SHA256SUMS
)

tar -tzf "$ARTIFACT_DIR/$ARTIFACT_NAME" | grep -Eq '^\./bin/php$'
tar -tzf "$ARTIFACT_DIR/$ARTIFACT_NAME" | grep -Eq '^\./share/php-bin/manifest\.json$'
echo "Created $ARTIFACT_DIR/$ARTIFACT_NAME"
echo "Created $ARTIFACT_DIR/SHA256SUMS"
