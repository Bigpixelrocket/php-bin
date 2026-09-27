#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

require_macos_arm64

PHP_VERSION="${1:-8.4}"
STAGE="${2:-s4}"
STAGE_FILE="$PROJECT_ROOT/stages/$STAGE.txt"
# Only stages with a companion list build shared extensions; see its header.
SHARED_FILE="$PROJECT_ROOT/stages/$STAGE-shared.txt"
SPC_BIN="${SPC_BIN:-$PROJECT_ROOT/.spc/spc}"
BUILD_DIR="$PROJECT_ROOT/.build/$PHP_VERSION/$STAGE"

if [[ ! "$PHP_VERSION" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
  echo "PHP version must be a major.minor branch or an exact patch version." >&2
  exit 1
fi

require_file "$STAGE_FILE"
if [[ ! -x "$SPC_BIN" ]]; then
  echo "StaticPHP is not installed at $SPC_BIN." >&2
  echo "Run scripts/install-spc.sh or set SPC_BIN." >&2
  exit 1
fi

EXTENSIONS="$(grep -Ev '^[[:space:]]*(#|$)' "$STAGE_FILE" | paste -sd, -)"
mkdir -p "$BUILD_DIR"

SHARED_ROWS=""
SHARED_EXTENSIONS=""
if [[ -f "$SHARED_FILE" ]]; then
  SHARED_ROWS="$(read_shared_extensions "$SHARED_FILE")"
  SHARED_EXTENSIONS="$(cut -f1 <<< "$SHARED_ROWS" | paste -sd, -)"
fi

print_failure_logs() {
  local log_file

  for log_file in \
    "$BUILD_DIR/log/spc.output.log" \
    "$BUILD_DIR/log/spc.shell.log"
  do
    if [[ -f "$log_file" ]]; then
      echo "Sanitized tail of ${log_file#"$PROJECT_ROOT/"}:" >&2
      tail -n 300 "$log_file" \
        | sed -E \
          -e 's/(Authorization:[[:space:]]*Bearer[[:space:]]+)[^"[:space:]]+/\1[REDACTED]/g' \
          -e 's/gh[a-zA-Z]_[A-Za-z0-9_]+/[REDACTED]/g' \
          -e 's/github_pat_[A-Za-z0-9_]+/[REDACTED]/g' >&2
    fi
  done
}

# The compiled-in php.ini path points below /dev/null, which can never be a
# directory, so a stray system php.ini is never read; each install's own
# bin/php.ini beside the binary is found first. No scan directory is compiled
# in either, which keeps PHP_INI_SCAN_DIR as the only way to add one.
# ac_cv_header_unix_h stops configure from picking up c-client's unix.h, which
# would otherwise leave HAVE_UNIX_H in the shipped php_config.h and break
# user-built extensions.
{
  cat <<EOF
php-version: "$PHP_VERSION"
extensions: $EXTENSIONS
EOF
  if [[ -n "$SHARED_EXTENSIONS" ]]; then
    echo "shared-extensions: $SHARED_EXTENSIONS"
  fi
  cat <<EOF
sapi: cli
debug: false
build-options:
  with-clean: false
  with-suggested-libs: false
  with-suggested-exts: false
  no-strip: false
  with-config-file-path: "/dev/null/php-bin"
  with-config-file-scan-dir: ""
download-options:
  retry: 5
EOF
  if awk -F '\t' '$5 != "-" { found = 1 } END { exit !found }' <<< "$SHARED_ROWS"; then
    echo "  custom-url:"
    awk -F '\t' '$5 != "-" { printf "    - \"%s\"\n", $5 }' <<< "$SHARED_ROWS"
  fi
  cat <<EOF
extra-env:
  MACOSX_DEPLOYMENT_TARGET: "26.0"
  ac_cv_func_memset_s: "no"
  ac_cv_header_unix_h: "no"
EOF
} > "$BUILD_DIR/craft.yml"

if ! (
  cd "$BUILD_DIR"
  "$SPC_BIN" doctor
  "$SPC_BIN" craft
); then
  print_failure_logs
  exit 1
fi

PHP_BIN="$BUILD_DIR/buildroot/bin/php"
if [[ ! -x "$PHP_BIN" ]]; then
  echo "Build completed without the expected executable: $PHP_BIN" >&2
  exit 1
fi

"$PHP_BIN" -v
"$PHP_BIN" -r 'exit(PHP_SAPI === "cli" ? 0 : 1);'
[ "$(lipo -archs "$PHP_BIN")" = "arm64" ]

MINIMUM_MACOS_VERSION="$(vtool -show-build "$PHP_BIN" | awk '$1 == "minos" { print $2; exit }')"
if [[ "$MINIMUM_MACOS_VERSION" != "26.0" ]]; then
  echo "Expected a macOS 26.0 minimum, got: ${MINIMUM_MACOS_VERSION:-unknown}" >&2
  exit 1
fi
echo "Verified macOS minimum: $MINIMUM_MACOS_VERSION"

# Run PHP with no php.ini and the given extension loader flags, failing unless
# it exits cleanly with no output at all, so startup warnings cannot pass.
run_php_silently() {
  local output

  if ! output="$("$PHP_BIN" -n -d display_startup_errors=1 -d display_errors=1 "$@" 2>&1)"; then
    printf '%s\n' "$output" >&2
    return 1
  fi
  if [[ -n "$output" ]]; then
    printf 'Unexpected PHP output with %s:\n%s\n' "$*" "$output" >&2
    return 1
  fi
}

# Print, on one line, the -d flags that load one shared extension after its
# declared requirements.
shared_extension_flags() {
  local name="$1"
  local requires dependency

  requires="$(awk -F '\t' -v name="$name" '$1 == name { print $4 }' <<< "$SHARED_ROWS")"
  {
    if [[ "$requires" != "-" ]]; then
      for dependency in ${requires//,/ }; do
        awk -F '\t' -v name="$dependency" '$1 == name { printf "-d %s=%s ", $3, $1 }' <<< "$SHARED_ROWS"
      done
    fi
    awk -F '\t' -v name="$name" '$1 == name { printf "-d %s=%s", $3, $1 }' <<< "$SHARED_ROWS"
  }
  echo
}

# The module gate for a build with shared extensions:
# - php -n -m is exactly the static set (expected modules minus default-on);
# - static plus every default-on .so is exactly the expected module list;
# - every .so loads alone (with only its declared requirements) and cleanly;
# - declared requirements equal the extension's own required shared dependencies;
# - every off-by-default extension reports a stable version;
# - every .so links only system libraries and targets macOS 26.0;
# - the shipped php_config.h does not define HAVE_UNIX_H.
verify_shared_extensions() {
  local expected_file="$1"
  local modules_dir="$BUILD_DIR/buildroot/modules"
  local gate_dir="$BUILD_DIR/gate"
  local name state loader requires _pin so_file version
  local dependency declared library install_name minimum
  local flags=()
  local default_flags=()

  rm -rf "$gate_dir"
  mkdir -p "$gate_dir"

  cut -f1 <<< "$SHARED_ROWS" | LC_ALL=C sort > "$gate_dir/listed.txt"
  find "$modules_dir" -maxdepth 1 -name '*.so' -exec basename {} .so \; \
    | LC_ALL=C sort > "$gate_dir/built.txt"
  if ! diff -u "$gate_dir/listed.txt" "$gate_dir/built.txt" >&2; then
    echo "Built shared extensions differ from ${SHARED_FILE#"$PROJECT_ROOT/"}." >&2
    return 1
  fi

  awk -F '\t' '$2 == "on" { print $1 }' <<< "$SHARED_ROWS" > "$gate_dir/default-on.txt"
  grep -Ev '^[[:space:]]*(#|$)' "$expected_file" \
    | grep -Fvx -f "$gate_dir/default-on.txt" > "$gate_dir/static-expected.txt"
  "$PHP_BIN" -n -m > "$gate_dir/static-actual.txt"
  echo "Checking the static module set:"
  "$SCRIPT_DIR/compare-modules.sh" "$gate_dir/static-actual.txt" "$gate_dir/static-expected.txt" exact

  while IFS=$'\t' read -r name state loader requires _pin; do
    if [[ "$state" == "on" ]]; then
      default_flags+=(-d "$loader=$name")
    fi
  done <<< "$SHARED_ROWS"
  run_php_silently -d "extension_dir=$modules_dir" "${default_flags[@]}" -r ''
  "$PHP_BIN" -n -d "extension_dir=$modules_dir" "${default_flags[@]}" -m > "$gate_dir/default-actual.txt"
  echo "Checking static plus default-on shared modules:"
  "$SCRIPT_DIR/compare-modules.sh" "$gate_dir/default-actual.txt" "$expected_file" exact

  # The PHP snippets below read $argv, which the shell must not expand.
  # shellcheck disable=SC2016
  while IFS=$'\t' read -r name state loader requires _pin; do
    so_file="$modules_dir/$name.so"
    read -r -a flags <<< "$(shared_extension_flags "$name")"
    run_php_silently -d "extension_dir=$modules_dir" "${flags[@]}" \
      -r 'exit(extension_loaded($argv[1]) ? 0 : 1);' -- "$name"

    "$PHP_BIN" -n -d "extension_dir=$modules_dir" "${flags[@]}" -r '
      foreach ((new ReflectionExtension($argv[1]))->getDependencies() as $dependency => $kind) {
        if ($kind === "Required") {
          echo strtolower($dependency), "\n";
        }
      }
    ' -- "$name" > "$gate_dir/dependencies.txt"
    declared=",${requires/#-/},"
    while IFS= read -r dependency; do
      if grep -Fqx "$dependency" "$gate_dir/listed.txt" && [[ "$declared" != *",$dependency,"* ]]; then
        echo "$name requires shared extension $dependency, which the list does not declare." >&2
        return 1
      fi
    done < "$gate_dir/dependencies.txt"
    if [[ "$requires" != "-" ]]; then
      for dependency in ${requires//,/ }; do
        if ! grep -Fqx "$dependency" "$gate_dir/dependencies.txt"; then
          echo "$name does not require $dependency, but the list declares it." >&2
          return 1
        fi
      done
    fi

    if [[ "$state" == "off" ]]; then
      version="$("$PHP_BIN" -n -d "extension_dir=$modules_dir" "${flags[@]}" \
        -r 'echo phpversion($argv[1]);' -- "$name")"
      if [[ -z "$version" || "$version" =~ [Aa]lpha|[Bb]eta|RC|rc|[Dd]ev ]]; then
        echo "$name reports a prerelease or missing version: '${version}'. Pin a stable release." >&2
        return 1
      fi
      echo "Loaded $name $version"
    fi

    install_name="$(otool -D "$so_file" | tail -n +2)"
    while IFS= read -r library; do
      if [[ -n "$library" && "$library" != "$install_name" \
        && "$library" != /usr/lib/* && "$library" != /System/Library/* ]]; then
        echo "$name.so links a non-system library: $library" >&2
        return 1
      fi
    done < <(otool -L "$so_file" | tail -n +2 | awk '{ print $1 }')

    minimum="$(vtool -show-build "$so_file" | awk '$1 == "minos" { print $2; exit }')"
    if [[ "$minimum" != "26.0" ]]; then
      echo "$name.so targets macOS ${minimum:-unknown}, expected 26.0." >&2
      return 1
    fi
  done <<< "$SHARED_ROWS"

  if grep -Eq '^#define HAVE_UNIX_H' "$BUILD_DIR/buildroot/include/php/main/php_config.h"; then
    echo "php_config.h still defines HAVE_UNIX_H; user-built extensions would fail." >&2
    return 1
  fi

  echo "Shared extension gate passed."
}

PHP_MINOR="${PHP_VERSION%.*}"
if [[ "$PHP_VERSION" =~ ^[0-9]+\.[0-9]+$ ]]; then
  PHP_MINOR="$PHP_VERSION"
fi

if [[ -n "$SHARED_ROWS" ]]; then
  verify_shared_extensions "$PROJECT_ROOT/expected-modules/$PHP_MINOR.txt"
  # package.sh reads the list the gate just verified, not the working tree's.
  cp "$SHARED_FILE" "$BUILD_DIR/shared-extensions.txt"
elif [[ "$STAGE" == "s4" ]]; then
  "$SCRIPT_DIR/compare-modules.sh" \
    "$PHP_BIN" \
    "$PROJECT_ROOT/expected-modules/$PHP_MINOR.txt" \
    exact
else
  "$SCRIPT_DIR/compare-modules.sh" "$PHP_BIN" "$STAGE_FILE" subset
fi

echo "Stage $STAGE passed: $PHP_BIN"
