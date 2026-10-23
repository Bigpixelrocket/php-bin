#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

require_macos_arm64

# The publisher passes the full release tag, 8.4.5-1 for a rebuild; the build
# folder keeps that tag, and StaticPHP gets the PHP version without it.
BUILD_TARGET="${1:-8.4}"
# PHP_SOURCE=tag builds the exact php-src git tag instead of the php.net release
# tarball, so the upstream canary can build a patch, or the next branch's
# pre-release, before php.net announces it. Releases never set it: only a
# php.net tarball is ever published.
PHP_SOURCE="${PHP_SOURCE:-release}"
PHP_SOURCE_PIN=""
case "$PHP_SOURCE" in
  release)
    PHP_VERSION="$(php_source_version "$BUILD_TARGET")"
    ;;
  tag)
    if [[ ! "$BUILD_TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+((alpha|beta|RC)[0-9]+)?$ ]]; then
      echo "PHP_SOURCE=tag needs an exact php-src tag version, got: $BUILD_TARGET" >&2
      exit 1
    fi
    PHP_VERSION="$BUILD_TARGET"
    PHP_SOURCE_PIN="php-src:https://github.com/php/php-src/archive/refs/tags/php-$PHP_VERSION.tar.gz"
    ;;
  *)
    echo "PHP_SOURCE must be release or tag, got: $PHP_SOURCE" >&2
    exit 1
    ;;
esac
STAGE="${2:-s4}"
STAGE_FILE="$PROJECT_ROOT/stages/$STAGE.txt"
# Only stages with a companion list build shared extensions; see its header.
SHARED_FILE="$PROJECT_ROOT/stages/$STAGE-shared.txt"
SPC_BIN="${SPC_BIN:-$PROJECT_ROOT/.spc/spc}"
BUILD_DIR="$PROJECT_ROOT/.build/$BUILD_TARGET/$STAGE"

require_file "$STAGE_FILE"
if [[ ! -x "$SPC_BIN" ]]; then
  echo "StaticPHP is not installed at $SPC_BIN." >&2
  echo "Run scripts/install-spc.sh or set SPC_BIN." >&2
  exit 1
fi

mkdir -p "$BUILD_DIR"

# The branch's module list says what the build must produce and which stage
# extensions the branch does not build. A branch-only target such as 8.4 reads
# the 8.4 list, and a pre-release such as 8.6.0RC4 the 8.6 list.
PHP_MINOR="${PHP_VERSION%.*}"
if [[ "$PHP_VERSION" =~ ^[0-9]+\.[0-9]+$ ]]; then
  PHP_MINOR="$PHP_VERSION"
fi
MODULE_LIST="$PROJECT_ROOT/expected-modules/$PHP_MINOR.txt"

# DISCOVER_MODULE_LIST=<path> is how a new branch learns its module list. Every
# stage extension is tried, whatever any list says; an extension a compiler error
# names is left out, with every shared extension that requires it, and the build
# is retried. The list of what then built and passed the gate, plus a
# `!<extension>` line for each one left out, is written to <path>. Only the
# new-branch discovery and the canary set it; a release build never does.
DISCOVER_MODULE_LIST="${DISCOVER_MODULE_LIST:-}"
UNBUILT=""
if [[ -z "$DISCOVER_MODULE_LIST" && -f "$MODULE_LIST" ]]; then
  UNBUILT="$(module_list_unbuilt "$MODULE_LIST")"
fi
FULL_SHARED_ROWS=""
if [[ -f "$SHARED_FILE" ]]; then
  FULL_SHARED_ROWS="$(read_shared_extensions "$SHARED_FILE")"
fi

# Print the lines of a stage list whose extension is not unbuilt; comments stay.
without_unbuilt() {
  awk -v unbuilt="${UNBUILT//$'\n'/,}" '
    BEGIN { split(unbuilt, names, ","); for (i in names) skip[names[i]] = 1 }
    { line = $0; sub(/#.*/, "", line); split(line, words, " ") }
    !((1 in words) && (words[1] in skip))
  ' "$1"
}

# Set the static and shared extensions to build: the stage lists minus every
# unbuilt extension. The filtered shared list is the one the gate verifies and
# package.sh ships; a kept extension that requires an unbuilt one fails it.
select_build_sets() {
  EXTENSIONS="$(without_unbuilt "$STAGE_FILE" | grep -Ev '^[[:space:]]*(#|$)' | paste -sd, -)"
  SHARED_ROWS=""
  SHARED_EXTENSIONS=""
  if [[ -f "$SHARED_FILE" ]]; then
    without_unbuilt "$SHARED_FILE" > "$BUILD_DIR/shared-extensions.txt"
    SHARED_ROWS="$(read_shared_extensions "$BUILD_DIR/shared-extensions.txt")"
    SHARED_EXTENSIONS="$(cut -f1 <<< "$SHARED_ROWS" | paste -sd, -)"
  fi
}

# Add extensions to the unbuilt set, with every shared extension that requires
# one of them, directly or through another.
add_unbuilt() {
  local name requires dependency changed=1

  UNBUILT="$(printf '%s\n' "$UNBUILT" "$@" | awk 'NF' | LC_ALL=C sort -u)"
  while (( changed )); do
    changed=0
    while IFS=$'\t' read -r name _ _ requires _; do
      if [[ -z "$name" || "$requires" == "-" ]] || grep -Fqx "$name" <<< "$UNBUILT"; then
        continue
      fi
      for dependency in ${requires//,/ }; do
        if grep -Fqx "$dependency" <<< "$UNBUILT"; then
          UNBUILT="$(printf '%s\n' "$UNBUILT" "$name" | awk 'NF' | LC_ALL=C sort -u)"
          changed=1
          break
        fi
      done
    done <<< "$FULL_SHARED_ROWS"
  done
}

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
craft_file() {
  cat <<EOF
php-version: "${PHP_VERSION%%[!0-9.]*}"
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
  # Stages without a shared list leave SHARED_ROWS empty, which awk still
  # reads as one blank record; NF skips it.
  if [[ -n "$PHP_SOURCE_PIN" ]] \
    || awk -F '\t' 'NF && $5 != "-" { found = 1 } END { exit !found }' <<< "$SHARED_ROWS"; then
    echo "  custom-url:"
    if [[ -n "$PHP_SOURCE_PIN" ]]; then
      printf '    - "%s"\n' "$PHP_SOURCE_PIN"
    fi
    awk -F '\t' 'NF && $5 != "-" { printf "    - \"%s\"\n", $5 }' <<< "$SHARED_ROWS"
  fi
  cat <<EOF
extra-env:
  MACOSX_DEPLOYMENT_TARGET: "26.0"
  ac_cv_func_memset_s: "no"
  ac_cv_header_unix_h: "no"
craft-options:
  download: $1
  build: $2
EOF
}

# Remove every php-src/ext directory that holds no config*.m4. Such a directory
# is not an extension PHP's build can configure: upstream leaves test folders
# behind when an extension moves out of core (ext/imap/tests since 8.4.27 and
# 8.5.12), and keeps Windows-only and template directories there. StaticPHP
# skips extracting a PECL source into a directory that already exists, so a
# leftover folder would otherwise hide the extension it should become.
remove_unconfigurable_extension_dirs() {
  local dir

  for dir in source/php-src/ext/*/; do
    if ! compgen -G "${dir}config*.m4" > /dev/null; then
      echo "Removing ${dir%/}: it holds no config*.m4."
      rm -rf "$dir" || return 1
    fi
  done
}

# StaticPHP's macOS default micro patch list; an SPC_MICRO_PATCHES already in the
# environment replaces it. Only the CLI is built, but the patches still touch
# php-src (macos_iconv fixes iconv detection against the bundled libiconv).
MICRO_PATCHES="${SPC_MICRO_PATCHES-cli_checks,macos_iconv}"
IFS=. read -r PHP_MAJOR PHP_MINOR_NUMBER _ <<< "${PHP_VERSION%%[!0-9.]*}"
# Micro patch files carry the branch they target as <major><minor>, 84 for 8.4.
PHP_BRANCH_NUMBER="$PHP_MAJOR$PHP_MINOR_NUMBER"

# Print the micro patches to apply, as exact file names. StaticPHP picks each
# patch from a version table that ends at the newest branch it knows and falls
# back to the oldest file for any newer branch, which then fails to apply. Each
# patch is resolved here instead: its newest file not newer than this branch that
# applies cleanly to this source. A patch with no such file is skipped, and the
# build and module gates decide whether the result is sound.
resolve_micro_patches() {
  local name file version chosen
  local patches_dir="source/php-src/sapi/micro/patches"
  local resolved=()

  for name in ${MICRO_PATCHES//,/ }; do
    chosen=""
    while IFS= read -r file; do
      if [[ "$file" != "$name.patch" ]]; then
        version="${file#"${name}_"}"
        version="${version%.patch}"
        if [[ ! "$version" =~ ^[0-9]+$ ]] || (( 10#$version > 10#$PHP_BRANCH_NUMBER )); then
          continue
        fi
      fi
      if (cd source/php-src && patch -p1 --dry-run --silent --force < "sapi/micro/patches/$file") > /dev/null 2>&1; then
        chosen="${file%.patch}"
        break
      fi
    done < <(find "$patches_dir" -maxdepth 1 \( -name "$name.patch" -o -name "${name}_*.patch" \) -exec basename {} \; | sort -rV)
    if [[ -n "$chosen" ]]; then
      resolved+=("$chosen")
    else
      echo "Skipping micro patch $name: no version of it applies to PHP $PHP_VERSION." >&2
    fi
  done
  (IFS=,; echo "${resolved[*]+"${resolved[*]}"}")
}

# Each step runs on its own: inside `if ! ( ... )` bash ignores `set -e`, so a
# failed step would otherwise fall through to the next one.
run_staticphp() {
  local micro_patches

  cd "$BUILD_DIR" \
    && "$SPC_BIN" doctor \
    && "$SPC_BIN" craft craft-download.yml \
    && "$SPC_BIN" extract php-src,micro \
    && remove_unconfigurable_extension_dirs \
    && micro_patches="$(resolve_micro_patches)" \
    && echo "Micro patches: ${micro_patches:-none}" \
    && SPC_MICRO_PATCHES="$micro_patches" "$SPC_BIN" craft craft-build.yml
}

# Put the build back to before php-src was extracted, keeping every library
# already built: StaticPHP skips a library installed in buildroot, so a retry
# only rebuilds PHP and its extensions.
reset_php_build() {
  rm -rf "$BUILD_DIR/source" "$BUILD_DIR/buildroot/modules" \
    "$BUILD_DIR/buildroot/include/php" "$BUILD_DIR/buildroot/lib/php"
  rm -f "$BUILD_DIR"/buildroot/bin/php* "$BUILD_DIR"/buildroot/lib/libphp*
}

attempt=1
while true; do
  select_build_sets
  craft_file true false > "$BUILD_DIR/craft-download.yml"
  craft_file false true > "$BUILD_DIR/craft-build.yml"
  if (run_staticphp); then
    break
  fi
  print_failure_logs
  if [[ -z "$DISCOVER_MODULE_LIST" ]]; then
    exit 1
  fi
  # Every retry leaves out at least one more extension the build tried, so the
  # loop ends: with a build that passes, or with an error that names none.
  tried="$EXTENSIONS${SHARED_EXTENSIONS:+,$SHARED_EXTENSIONS}"
  # StaticPHP builds what a tried extension depends on even when it was left out;
  # its own table says which tried extensions pulled such a dependency back in.
  "$SPC_BIN" dev:extensions "$tried" > "$BUILD_DIR/extension-dependencies.txt"
  culprits="$("$SCRIPT_DIR/attribute-build-failure" \
    --log-dir "$BUILD_DIR/log" \
    --extensions "$tried" \
    --unbuilt "${UNBUILT//$'\n'/,}" \
    --dependencies "$BUILD_DIR/extension-dependencies.txt")"
  if [[ -z "$culprits" ]]; then
    echo "The build failed and no compiler error names an extension it could leave out." >&2
    exit 1
  fi
  echo "Attempt $attempt: leaving out $(paste -sd, - <<< "$culprits"): it does not compile on PHP $PHP_VERSION. Retrying."
  # The names are validated extension identifiers, one per line.
  # shellcheck disable=SC2086
  add_unbuilt $culprits
  reset_php_build
  attempt=$((attempt + 1))
done

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

# A discovered list is exactly what built: the static modules plus every
# default-on shared extension, and a `!` line for each extension left out. The
# gate below then verifies the build against it like any other list.
if [[ -n "$DISCOVER_MODULE_LIST" ]]; then
  default_on=()
  while IFS=$'\t' read -r name state loader _ _; do
    if [[ "$state" == "on" ]]; then
      default_on+=(-d "$loader=$name")
    fi
  done <<< "$SHARED_ROWS"
  {
    "$PHP_BIN" -n -d "extension_dir=$BUILD_DIR/buildroot/modules" ${default_on[@]+"${default_on[@]}"} -m \
      | normalize_modules
    awk 'NF { print "!" $0 }' <<< "$UNBUILT"
  } > "$DISCOVER_MODULE_LIST"
  MODULE_LIST="$DISCOVER_MODULE_LIST"
  echo "Discovered module list for PHP $PHP_MINOR:"
  cat "$MODULE_LIST"
fi

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
  module_list_modules "$expected_file" \
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

if [[ -n "$SHARED_ROWS" ]]; then
  # package.sh reads $BUILD_DIR/shared-extensions.txt, the filtered list this
  # gate verifies, not the working tree's stage list.
  verify_shared_extensions "$MODULE_LIST"
elif [[ "$STAGE" == "s4" ]]; then
  "$SCRIPT_DIR/compare-modules.sh" "$PHP_BIN" "$MODULE_LIST" exact
else
  "$SCRIPT_DIR/compare-modules.sh" "$PHP_BIN" "$STAGE_FILE" subset
fi

echo "Stage $STAGE passed: $PHP_BIN"
