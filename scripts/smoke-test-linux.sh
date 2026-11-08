#!/usr/bin/env bash

# Run a packaged Linux archive on the glibc distributions it promises to support,
# each in its own container: PHP starts, `php -m` with every default-on shared
# extension equals the branch's module list, every shared extension loads cleanly
# on its own, and HTTPS works through both OpenSSL streams and curl once
# openssl.cafile and curl.cainfo name the distribution's CA bundle.
#
# HTTPS with no CA setting at all is measured and reported, never failed: OpenSSL
# looks under /etc/ssl, which only some distributions fill, and each install's
# php.ini is where that gets settled.
#
# Usage: smoke-test-linux.sh <archive> <expected-modules-file>
# DOCKER overrides the container command, for example DOCKER="sudo docker".

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <archive> <expected-modules-file>" >&2
  exit 2
fi
ARCHIVE="$1"
EXPECTED="$2"
require_file "$ARCHIVE"
require_file "$EXPECTED"

PLATFORM="$(build_platform)"
if [[ "$PLATFORM" != linux-* ]]; then
  echo "The distribution smoke test runs on Linux only." >&2
  exit 1
fi
read -r -a DOCKER <<< "${DOCKER:-docker}"

# glibc 2.17 is the baseline; Ubuntu 16.04 (glibc 2.23) is the oldest image
# that still installs CA certificates. Arch publishes no arm64 image.
IMAGES=(
  fedora:latest
  ubuntu:16.04
  ubuntu:latest
  debian:stable
  gentoo/stage3:latest
)
if [[ "$PLATFORM" == linux-x86_64 ]]; then
  IMAGES+=(archlinux:latest)
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/php-bin-smoke.XXXXXX")"
CONTAINERS=()
cleanup() {
  if ((${#CONTAINERS[@]})); then
    "${DOCKER[@]}" rm -f "${CONTAINERS[@]}" > /dev/null 2>&1 || true
  fi
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

mkdir -p "$WORK_DIR/php"
tar -xzf "$ARCHIVE" -C "$WORK_DIR/php"
require_file "$WORK_DIR/php/share/php-bin/manifest.json"

# Turn the manifest into the loader flags the containers use: one line with
# every default-on extension, then one line per extension with its requirements
# first, as mise-php writes php.ini.
python3 -I - "$WORK_DIR/php/share/php-bin/manifest.json" > "$WORK_DIR/flags.txt" <<'PY'
import json
import sys

extensions = json.load(open(sys.argv[1]))["extensions"]
by_name = {extension["name"]: extension for extension in extensions}


def flag(extension):
    loader = "zend_extension" if extension["zend"] else "extension"
    return f"-d {loader}={extension['name']}"


print("default", " ".join(flag(e) for e in extensions if e["default"]))
for extension in extensions:
    chain = [by_name[name] for name in extension["requires"]] + [extension]
    print(extension["name"], " ".join(flag(e) for e in chain))
PY

# Runs inside each container with POSIX sh, since not every image has bash.
cat > "$WORK_DIR/inside.sh" <<'SH'
#!/bin/sh
set -u
PHP=/opt/php-bin/bin/php
EXT="-d extension_dir=/opt/php-bin/lib/php/extensions"
URL=https://www.php.net/robots.txt

# A desktop or server install has CA certificates; most base images do not.
if command -v apt-get > /dev/null; then
  apt-get update -qq > /dev/null 2>&1
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates > /dev/null 2>&1
elif command -v dnf > /dev/null; then
  dnf install -y -q ca-certificates > /dev/null 2>&1
elif command -v pacman > /dev/null; then
  pacman -Sy --noconfirm --needed ca-certificates > /dev/null 2>&1
fi

echo "glibc $(getconf GNU_LIBC_VERSION | cut -d' ' -f2)"
if ! version="$($PHP -n -v 2>&1)"; then
  echo "FAIL php -v: $version"
  exit 1
fi
echo "ok php -v: $(echo "$version" | head -n 1)"

status=0
# Load with no php.ini; any startup warning or error output fails the check.
quiet() {
  output="$($PHP -n -d display_startup_errors=1 -d display_errors=1 $EXT "$@" 2>&1)" \
    && [ -z "$output" ]
}

default_flags="$(sed -n 's/^default //p' /in/flags.txt)"
# The host compares the module list between these markers with the branch's.
# shellcheck disable=SC2086
if quiet $default_flags -r ''; then
  echo "--- modules"
  $PHP -n $EXT $default_flags -m
  echo "--- end"
else
  echo "FAIL default-on extensions: $output"
  status=1
fi

loaded=0
while read -r name flags; do
  [ "$name" = default ] && continue
  # shellcheck disable=SC2086
  if quiet $flags -r 'exit(extension_loaded($argv[1]) ? 0 : 1);' -- "$name"; then
    loaded=$((loaded + 1))
  else
    echo "FAIL load $name: $output"
    status=1
  fi
done < /in/flags.txt
echo "ok loaded $loaded shared extensions one by one"
if quiet -d zend_extension=/opt/php-bin/lib/php/extensions/xdebug.so \
  -r 'exit(extension_loaded("xdebug") ? 0 : 1);'; then
  echo "ok xdebug by absolute path"
else
  echo "FAIL xdebug by absolute path: $output"
  status=1
fi

# The build links a libcrypt whose crypt() always fails, for imap's c-client
# alone; PHP's crypt() and password functions must still use PHP's bundled
# implementation. The expected hash is what `openssl passwd -6 -salt saltsalt x`
# prints.
if $PHP -n -r '
  $hash = password_hash("secret", PASSWORD_DEFAULT);
  $sha512 = crypt("x", "\$6\$saltsalt\$");
  exit(password_verify("secret", $hash) && !password_verify("other", $hash)
    && $sha512 === "\$6\$saltsalt\$8RWsOfwR6M6PpnoeQiEiWzNTPo1f0HjVYjDnLZhGx16aBFRkeqiHAzfXP/LgrOWMBMXqiU2pLrXsSOHNUyUm91"
    ? 0 : 1);
'; then
  echo "ok crypt and password_hash use PHP's implementation"
else
  echo "FAIL crypt or password_hash"
  status=1
fi

bundle=""
for candidate in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt \
  /etc/ssl/cert.pem /etc/ssl/ca-bundle.pem; do
  if [ -f "$candidate" ]; then
    bundle="$candidate"
    break
  fi
done
echo "bundle ${bundle:-none}"
$PHP -n -r '
  $locations = openssl_get_cert_locations();
  $file = $locations["default_cert_file"];
  $dir = $locations["default_cert_dir"];
  $hashed = count(glob("$dir/*.[0-9]") ?: []);
  printf("openssl default file %s (%s), dir %s (%d hashed links)\n",
    $file, is_file($file) ? "present" : "missing", $dir, $hashed);
  $c = curl_init();
  printf("curl default CA file %s\n",
    defined("CURLINFO_CAINFO") ? var_export(curl_getinfo($c, CURLINFO_CAINFO), true) : "unknown");
'

https() {
  label="$1"
  shift
  stream="$($PHP -n "$@" -r '
    $body = @file_get_contents($argv[1]);
    echo $body === false ? "fail (" . error_get_last()["message"] . ")" : "ok";
  ' -- "$URL" 2>&1 | tr '\n' ' ')"
  curl="$($PHP -n "$@" -r '
    $c = curl_init($argv[1]);
    curl_setopt_array($c, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 30]);
    echo curl_exec($c) === false ? "fail (" . curl_error($c) . ")" : "ok";
  ' -- "$URL" 2>&1 | tr '\n' ' ')"
  echo "https $label: stream $stream; curl $curl"
}
https "no CA setting"
if [ -n "$bundle" ]; then
  https "with bundle" -d "openssl.cafile=$bundle" -d "curl.cainfo=$bundle"
  case "$stream$curl" in
    okok) ;;
    *) status=1 ;;
  esac
else
  echo "FAIL no CA bundle found"
  status=1
fi
exit "$status"
SH

FAILED=()
index=0
for image in "${IMAGES[@]}"; do
  index=$((index + 1))
  name="php-bin-smoke-$$-$index"
  log="$WORK_DIR/$index.log"
  echo "=== $image"
  CONTAINERS+=("$name")
  if ! "${DOCKER[@]}" pull -q "$image" > /dev/null; then
    echo "FAIL could not pull $image"
    FAILED+=("$image")
    continue
  fi
  result=0
  "${DOCKER[@]}" run --rm --name "$name" \
    -v "$WORK_DIR/php:/opt/php-bin:ro" \
    -v "$WORK_DIR/inside.sh:/in/inside.sh:ro" \
    -v "$WORK_DIR/flags.txt:/in/flags.txt:ro" \
    "$image" sh /in/inside.sh > "$log" 2>&1 || result=$?
  sed '/^--- modules$/,/^--- end$/d' "$log"
  sed -n '/^--- modules$/,/^--- end$/{/^---/d;p;}' "$log" > "$WORK_DIR/$index.modules"
  if [[ ! -s "$WORK_DIR/$index.modules" ]]; then
    echo "FAIL no module list"
    result=1
  elif ! "$SCRIPT_DIR/compare-modules.sh" "$WORK_DIR/$index.modules" "$EXPECTED" exact; then
    result=1
  fi
  if ((result != 0)); then
    FAILED+=("$image")
  fi
done

if ((${#FAILED[@]})); then
  echo "Smoke test failed on: ${FAILED[*]}" >&2
  exit 1
fi
echo "Smoke test passed on: ${IMAGES[*]}"
