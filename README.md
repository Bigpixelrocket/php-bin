# php-bin

Reproducible, fat static PHP CLI binaries for Apple Silicon Macs.

This repository owns the build recipe and release contract consumed by
[`bigpixelrocket/mise-php`](https://github.com/bigpixelrocket/mise-php). It does
not manage PHP versions on a developer's machine and it does not provide a web
server, DNS, databases, or a desktop UI.

## Status

Public macOS arm64 releases are available for every maintained PHP branch:
[8.2.32](https://github.com/bigpixelrocket/php-bin/releases/tag/8.2.32),
[8.3.32](https://github.com/bigpixelrocket/php-bin/releases/tag/8.3.32),
[8.4.23](https://github.com/bigpixelrocket/php-bin/releases/tag/8.4.23), and
[8.5.8](https://github.com/bigpixelrocket/php-bin/releases/tag/8.5.8).
Each release is rebuilt on macOS 26 arm64 and published only after its exact
module baseline and deployment target checks pass.

## Release contract

Published releases use a PHP version tag such as `8.4.5`, or `8.4.5-1` for a
recipe-only rebuild. Each release contains:

```text
php-<tag>-cli-macos-aarch64.tar.gz
SHA256SUMS
```

The archive layout is stable:

```text
bin/php
```

## Build locally

Requirements: an Apple Silicon Mac running macOS 26 or newer, Homebrew, Xcode
command-line tools, and enough free disk space for a full StaticPHP build.

```bash
scripts/install-build-deps.sh
scripts/install-spc.sh
scripts/build.sh 8.4 s0
scripts/compare-modules.sh .build/8.4/s0/buildroot/bin/php stages/s0.txt subset
```

Advance through `s1`, `s2`, `s3`, and `s4`. Stage `s4` runs the exact comparison
against `expected-modules/8.4.txt`:

```bash
scripts/build.sh 8.4 s4
scripts/compare-modules.sh \
  .build/8.4/s4/buildroot/bin/php \
  expected-modules/8.4.txt exact
```

When the exact check is green, package the binary with its full PHP patch
version:

```bash
scripts/package.sh .build/8.4/s4/buildroot/bin/php 8.4.5
```

Runtime packages required by particular extensions are documented in
[`docs/runtime-deps.md`](docs/runtime-deps.md). The build and release workflow
is documented in [`docs/release-process.md`](docs/release-process.md).

## Supported target

- macOS 26 (Tahoe) or newer
- arm64 / aarch64
- Currently supported PHP branches: 8.2 through 8.5
- CLI SAPI

Other operating systems, Intel Macs, and PHP 7.x are outside the v1 target.

## Contributing and security

See [`CONTRIBUTING.md`](CONTRIBUTING.md) before changing recipes. Report
security issues using [`SECURITY.md`](SECURITY.md), not a public issue.

## License

Build code is MIT licensed. Redistributed binaries contain PHP and third-party
software under their own licenses; see [`NOTICE`](NOTICE).
