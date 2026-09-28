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
release and lifecycle changes, fixed rules classify them into one plan, an
independent admission check accepts or rejects that plan, and deterministic
workflows build, verify, and publish the binaries. No model takes part in any
step.

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
bin/php                          static CLI binary
bin/phpize, bin/php-config       build kit for PIE and phpize
include/php/, lib/php/build/     PHP headers and build files
lib/php/extensions/<name>.so     shared extensions
share/php-bin/manifest.json      release, PHP version, and shared extensions
LICENSE, NOTICE
```

Most modules are compiled into `bin/php`. The extensions listed in
[`stages/s4-shared.txt`](stages/s4-shared.txt) ship as shared `.so` files
instead, so each install can turn them on or off. The manifest records, for
each one, its name, whether it loads with `zend_extension`, whether it is on by
default, and which other shared extensions it requires:

```json
{
  "schemaVersion": 1,
  "release": "8.5.11-1",
  "phpVersion": "8.5.11",
  "extensions": [
    {"name": "redis", "zend": false, "default": true, "requires": ["igbinary"]},
    {"name": "xdebug", "zend": true, "default": false, "requires": []}
  ]
}
```

The archive ships no `php.ini`. `mise-php` writes one per install at
`bin/php.ini`, where PHP always looks first; the binary's compiled-in
configuration path cannot exist and it has no scan directory, so no system
`php.ini` is ever read. `bin/php-config` and `bin/phpize` hold the placeholder
`@PHP_BIN_PREFIX@` where the install folder belongs, and `mise-php` replaces it
at install time. `include/php/` also carries the library headers the PHP
headers include: `gmp.h`, `sodium.h` with `sodium/`, and, from PHP 8.5, the
lexbor URL headers under `lexbor/`, so an extension can build against
`ext/gmp`, `ext/sodium`, or the `ext/uri` WHATWG parser with `phpize` alone.

Releases published before shared extensions contain only `bin/php`, `LICENSE`,
and `NOTICE`, with every module compiled in.

## Build locally

Requirements: an Apple Silicon Mac running macOS 26 or newer, Homebrew, Xcode
command-line tools, and enough free disk space for a full StaticPHP build.

```bash
scripts/install-build-deps.sh
scripts/install-spc.sh
scripts/build.sh 8.4 s0
scripts/compare-modules.sh .build/8.4/s0/buildroot/bin/php stages/s0.txt subset
```

Advance through `s1`, `s2`, `s3`, and `s4`. Stage `s4` also builds the shared
extensions in `stages/s4-shared.txt` and runs the module gate:

```bash
scripts/build.sh 8.4 s4
```

The gate requires `php -n -m` to equal the static set, the static set plus every
default-on extension to equal `expected-modules/8.4.txt` exactly, every shared
extension to load cleanly with only its declared requirements, every
off-by-default extension to report a stable version, and every `.so` to link
only system libraries and target macOS 26.0.

When the gate is green, package the build with its full PHP patch version:

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
replace a published asset. When the PHP patch is unchanged but the recipe
changes, the watcher selects a rebuild tag such as `8.5.9-1` for each
published version, one per run.

### New PHP branch

For a new branch such as PHP `8.6`:

The watcher adds the branch to `support-policy.json` and copies the newest
maintained branch's module list to `expected-modules/<branch>.txt`, and
`mise-php` regenerates its support snapshot from the new policy. The branch
merges only after its first release builds and passes the exact module
comparison; a module difference stops with an owner issue that names it, and
the list is then corrected by pull request. Publication waits for readiness
records tied to the same action key, evidence digests, php-bin policy commit,
and exact repository commits.

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
