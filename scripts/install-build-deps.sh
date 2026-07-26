#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

require_macos_arm64

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
