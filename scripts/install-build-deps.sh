#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

PLATFORM="$(build_platform)"

if [[ "$PLATFORM" == macos-* ]]; then
  if ! command -v brew >/dev/null 2>&1; then
    echo "Homebrew is required to install build dependencies." >&2
    exit 1
  fi

  brew install \
    autoconf \
    automake \
    bison \
    cmake \
    imagemagick \
    libtool \
    openldap \
    pkg-config \
    re2c \
    unixodbc
  echo "Build dependencies are installed. Run scripts/install-spc.sh next."
  exit 0
fi

# Linux builds compile every library from source with StaticPHP's pinned zig, so
# the host supplies only the tools StaticPHP's doctor checks for. gcc stays
# because zig links gcc's crtbeginS.o and crtendS.o into shared objects.
SUDO=()
if [[ "$(id -u)" -ne 0 ]]; then
  SUDO=(sudo)
fi
if command -v apt-get >/dev/null 2>&1; then
  "${SUDO[@]}" apt-get update
  "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
    autoconf automake autopoint bison bzip2 ca-certificates cmake curl file flex \
    g++ gcc git gzip libtool make patch perl pkg-config re2c tar unzip xz-utils
elif command -v dnf >/dev/null 2>&1; then
  "${SUDO[@]}" dnf install --assumeyes \
    autoconf automake bison bzip2 ca-certificates cmake curl file flex gcc gcc-c++ \
    gettext-devel git gzip libtool make patch perl re2c tar unzip which xz
elif command -v pacman >/dev/null 2>&1; then
  "${SUDO[@]}" pacman -S --needed --noconfirm \
    base-devel bzip2 ca-certificates cmake curl git perl re2c unzip xz
else
  echo "Install build dependencies by hand: no apt-get, dnf, or pacman found." >&2
  exit 1
fi

echo "Build dependencies are installed. Run scripts/install-spc.sh next."
