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

## Publishing newer PHP versions

Only publish PHP branches that are still maintained upstream. Use a pull
request for every recipe, supported-version, workflow, or module-baseline
change.

### New patch on a supported branch

For a release such as PHP `8.5.9`:

1. Confirm the patch exists upstream and its PHP branch is still maintained.
2. Run the S4 build for that branch and require the exact module and macOS 26.0
   deployment-target checks to pass.
3. From an up-to-date `php-bin/main`, create and push an annotated tag:

   ```bash
   git tag -a 8.5.9 -m "PHP 8.5.9 for macOS arm64"
   git push origin 8.5.9
   ```

   Push release tags individually so each push produces its own GitHub Actions
   tag event.
4. Wait for the release workflow to rebuild the exact patch, publish the
   archive and `SHA256SUMS`, and create the GitHub Release.
5. Run the published-release test in `mise-php`:

   ```bash
   gh workflow run e2e.yml \
     -R bigpixelrocket/mise-php \
     -f version=8.5.9
   ```

6. Verify both the exact version and its branch shorthand locally, for example
   `mise install php@8.5.9` and `mise install php@8.5`.

Never move an existing tag or replace a published asset. Use a rebuild tag such
as `8.5.9-1` when the PHP patch is unchanged but the recipe must change.

### New PHP branch

For a new branch such as PHP `8.6`:

1. Confirm the branch is maintained upstream and supported by the pinned
   StaticPHP toolchain.
2. In a `php-bin` pull request, add `expected-modules/8.6.txt`, allow the branch
   in the build, package, and release validators, and update the documented
   supported range.
3. Run staged builds from S0 through S4. Resolve extension compatibility and
   module drift rather than weakening the exact-module gate.
4. In a coordinated `mise-php` pull request, allow the branch in
   `lib/releases.lua` and `hooks/parse_legacy_file.lua`, then update its tests
   and supported-version documentation.
5. After both pull requests pass and merge, tag the exact first patch and
   follow the patch-release procedure above.

A new major such as PHP `9.0` follows the same process, but every validator and
parser anchored to PHP 8 must be reviewed explicitly.

### End-of-life branches

When upstream ends support for a branch, use coordinated pull requests to stop
building and listing it, remove its `expected-modules/<minor>.txt`, and update
tests and documentation. Keep existing GitHub Releases available for
reproducibility, but do not publish new ones.

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
