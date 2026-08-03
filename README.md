# php-bin

Reproducible, fat static PHP CLI binaries for Apple Silicon Macs.

This repository owns the build recipe and release contract consumed by
[`bigpixelrocket/mise-php`](https://github.com/bigpixelrocket/mise-php). It does
not manage PHP versions on a developer's machine and it does not provide a web
server, DNS, databases, or a desktop UI.

## Status

Public macOS arm64 releases are available for every maintained PHP branch. See
[the releases page](https://github.com/bigpixelrocket/php-bin/releases) for the
current set; it is published automatically, so any list repeated here would go
stale on the next patch. Each release is rebuilt on macOS 26 arm64 and
published only after its exact module baseline and deployment target checks
pass.

## Autorelease

Releases are produced automatically. A daily watcher detects upstream PHP
release and lifecycle changes, a read-only Codex agent investigates, and
deterministic workflows build, verify, and publish the binaries. The agent
holds no write credential and cannot tag, publish, or merge.

See [AUTORELEASE.md](AUTORELEASE.md) for the full contract, the operator
pause control, and maintainer commands.

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

## Publishing and recovery policy

Only branches maintained upstream are discoverable and eligible for new
publication. Exact historical versions remain installable while their
immutable assets exist. Protected controls always change through reviewed pull
requests.

### New patch on a supported branch

For an ordinary stable patch, the admitted no-edit intent goes directly to
`Autorelease publish transaction`; no implementation job or PR is created. A
recipe change uses a sealed automation PR first. Never move an existing tag or
replace a published asset. Use a rebuild tag such as `8.5.9-1` when the PHP
patch is unchanged but the recipe changes the bytes.

### New PHP branch

For a new branch such as PHP `8.6`:

Codex prepares bounded changes in both repositories. Staged S0–S4 builds must
resolve extension compatibility and exact-module drift without weakening a
gate. Publication waits for readiness records tied to the same action key,
evidence digests, php-bin policy commit, and exact repository commits.

A new major such as PHP `9.0` follows the same process unchanged: no validator,
regular expression, or policy file is anchored to PHP 8, so any maintained
major and minor is admissible without a code change.

### End-of-life branches

When captured upstream evidence shows EOL, the same unattended path stops new
publication for that branch and delists it: admitted changes remove its
shorthand and active build support in both repositories. Nothing is deleted or
retracted. Every already-published GitHub Release stays immutable, and exact
historical installation of those versions keeps working indefinitely.

Runtime packages required by particular extensions are documented in
[`docs/runtime-deps.md`](docs/runtime-deps.md). The build and release workflow
is documented in [`docs/release-process.md`](docs/release-process.md).

## Supported target

- macOS 26 (Tahoe) or newer
- arm64 / aarch64
- Supported PHP branches: whichever branches
  [`support-policy.json`](support-policy.json) currently lists, which the
  autorelease system regenerates from upstream lifecycle evidence
- CLI SAPI

Other operating systems, Intel Macs, and PHP 7.x are outside the v1 target.

## Contributing and security

See [`CONTRIBUTING.md`](CONTRIBUTING.md) before changing recipes. Report
security issues using [`SECURITY.md`](SECURITY.md), not a public issue.

## License

Build code is MIT licensed. Redistributed binaries contain PHP and third-party
software under their own licenses; see [`NOTICE`](NOTICE).
