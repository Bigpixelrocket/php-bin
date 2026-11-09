# php-bin

Reproducible, fat static PHP CLI binaries for Apple Silicon Macs and glibc
Linux on x86_64 and aarch64.

This repository owns the build recipe and release contract consumed by
[`bigpixelrocket/mise-php`](https://github.com/bigpixelrocket/mise-php). It does
not manage PHP versions on a developer's machine and it does not provide a web
server, DNS, databases, or a desktop UI.

## Status

[![php-bin status](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fbigpixelrocket.github.io%2Fphp-bin%2Fstatus.json&query=%24.summary&label=php-bin)](https://bigpixelrocket.github.io/php-bin/)
[![PHP 8.5](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fbigpixelrocket.github.io%2Fphp-bin%2Fstatus.json&query=%24.badges%5B%278.5%27%5D&label=PHP%208.5)](https://bigpixelrocket.github.io/php-bin/)
[![PHP 8.4](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fbigpixelrocket.github.io%2Fphp-bin%2Fstatus.json&query=%24.badges%5B%278.4%27%5D&label=PHP%208.4)](https://bigpixelrocket.github.io/php-bin/)
[![PHP 8.3](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fbigpixelrocket.github.io%2Fphp-bin%2Fstatus.json&query=%24.badges%5B%278.3%27%5D&label=PHP%208.3)](https://bigpixelrocket.github.io/php-bin/)
[![PHP 8.2](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fbigpixelrocket.github.io%2Fphp-bin%2Fstatus.json&query=%24.badges%5B%278.2%27%5D&label=PHP%208.2)](https://bigpixelrocket.github.io/php-bin/)
[![Last checked](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fbigpixelrocket.github.io%2Fphp-bin%2Fstatus.json&query=%24.checkedAt&label=last%20checked)](https://bigpixelrocket.github.io/php-bin/)

The badges read the status document the watcher publishes every 12 hours to
[`status.json`](https://bigpixelrocket.github.io/php-bin/status.json), with a readable copy at [https://bigpixelrocket.github.io/php-bin/](https://bigpixelrocket.github.io/php-bin/). For each
maintained branch it gives php.net's newest release, the newest php-bin
release, and whether php-bin is current; its shape is
[`schemas/autorelease-status.schema.json`](schemas/autorelease-status.schema.json).
A dashboard should read that document and alert when its `checkedAt` is older
than about 24 hours. A newly maintained branch needs its badge added here.

Public releases for macOS arm64, Linux x86_64, and Linux aarch64 are available
for every maintained PHP branch. See
[the releases page](https://github.com/bigpixelrocket/php-bin/releases) for the
current set; it is published automatically, so any list repeated here would go
stale on the next patch. Each release builds every platform on its own native
runner (macOS 26 arm64, Ubuntu x86_64, Ubuntu arm64) and is published only after
every platform passes its exact module baseline and platform checks, and each
Linux archive passes the distribution smoke test. A failure on any platform
publishes nothing.

The Linux archives need glibc 2.17 or newer. Every release is smoke-tested on
Fedora, Ubuntu 16.04 and current, Debian stable, Gentoo, and, on x86_64, Arch
Linux. musl distributions such as Alpine, and NixOS, are not supported.

## Autorelease

Releases are produced automatically. A watcher running every 12 hours detects upstream PHP
release and lifecycle changes, fixed rules classify them into one plan, an
independent admission check accepts or rejects that plan, and deterministic
workflows build, verify, and publish the binaries. No model takes part in any
step.

See [AUTORELEASE.md](AUTORELEASE.md) for the full contract, the operator
pause control, and maintainer commands.

## Release contract

Published releases use a PHP version tag such as `8.4.5`, or `8.4.5-1` for a
recipe-only rebuild. Each release contains one archive per platform and one
checksum file:

```text
php-<tag>-cli-macos-aarch64.tar.gz
php-<tag>-cli-linux-x86_64.tar.gz
php-<tag>-cli-linux-aarch64.tar.gz
SHA256SUMS
```

`SHA256SUMS` holds one `<sha256>  <filename>` line per archive, sorted by file
name. Releases published before Linux builds contain only the macOS archive and
its one checksum line; they stay as published, so an exact version from before
then installs on macOS only, and a branch shorthand on Linux resolves to the
newest release that has a Linux archive.

The archive layout is stable and identical on every platform, with the same
`share/php-bin/manifest.json`:

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
at install time. The informational build strings in
`include/php/main/build-defs.h` and `include/php/gmp.h` carry the same
placeholder. `include/php/` also carries the library headers the PHP
headers include: `gmp.h`, `sodium.h` with `sodium/`, simdjson's `simdjson.h`
beside the `ext/simdjson` bindings header, and, from PHP 8.5, the lexbor URL
headers under `lexbor/`, so an extension can build against `ext/gmp`,
`ext/sodium`, `ext/simdjson`, or the `ext/uri` WHATWG parser with `phpize`
alone.

Releases published before shared extensions contain only `bin/php`, `LICENSE`,
and `NOTICE`, with every module compiled in.

## Build locally

Builds run on three platforms, each producing its own archive:

| Platform | Build machine | Archive suffix |
| --- | --- | --- |
| macOS arm64 | Apple Silicon Mac on macOS 26 or newer, Homebrew, Xcode command-line tools | `macos-aarch64` |
| Linux x86_64 | glibc Linux with `apt-get`, `dnf`, or `pacman` and sudo | `linux-x86_64` |
| Linux aarch64 | glibc Linux with `apt-get`, `dnf`, or `pacman` and sudo | `linux-aarch64` |

Every platform also needs enough free disk space for a full StaticPHP build.
On Linux, StaticPHP compiles with a pinned zig release against glibc 2.17
symbols, so the build machine's own glibc version does not matter. The same
commands work on each:

```bash
scripts/install-build-deps.sh
scripts/install-spc.sh
scripts/build.sh 8.4 s0
scripts/compare-modules.sh .build/8.4/s0/buildroot/bin/php stages/s0.txt subset
```

`scripts/install-spc.sh` downloads StaticPHP for this platform, and on Linux the
zig compiler, and checks each against its SHA-256 pin in `.spc-sha256`.

Advance through `s1`, `s2`, `s3`, and `s4`. Stage `s4` also builds the shared
extensions in `stages/s4-shared.txt` and runs the module gate:

```bash
scripts/build.sh 8.4 s4
```

The gate requires `php -n -m` to equal the static set, the static set plus every
default-on extension to equal `expected-modules/8.4.txt` exactly, every shared
extension to load cleanly with only its declared requirements, and every
off-by-default extension to report a stable version. On macOS, every `.so`
must link only system libraries and target macOS 26.0. On Linux, `bin/php` and
every `.so` must need no shared library outside glibc (`libc`, `libm`, `libdl`,
`libpthread`, `librt`, `libresolv`, `libutil`, and the dynamic loader) and no
glibc symbol newer than 2.17, and every symbol a `.so` leaves undefined must be
defined by `bin/php` or by an extension it requires.

When the gate is green, package the build with its full PHP patch version:

```bash
scripts/package.sh .build/8.4/s4/buildroot/bin/php 8.4.5
```

On Linux, `scripts/smoke-test-linux.sh` then runs the archive in Docker
containers of Fedora, Ubuntu 16.04 and current, Debian stable, Gentoo, and, on
x86_64, Arch Linux. Each checks `php -v`, the exact module list, every shared
extension, PHP's `crypt()` and `password_hash()`, and HTTPS through OpenSSL
streams and curl. A last Debian run repeats those checks with PHP under QEMU on
the architecture's baseline CPU, since every container shares the build
machine's CPU and could not catch an instruction older CPUs lack. It needs
Docker; set `DOCKER="sudo docker"` where Docker needs root:

```bash
scripts/smoke-test-linux.sh .artifacts/php-8.4.5-cli-linux-x86_64.tar.gz expected-modules/8.4.txt
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
changes, the watcher selects a rebuild tag such as `8.5.9-1` for the newest
version of each maintained branch and publishes all of them concurrently from
one run. Older patch versions keep their original binaries.

### New PHP branch

For a new branch such as PHP `8.6`:

The watcher adds the branch to `support-policy.json` and writes
`expected-modules/<branch>.txt` from a discovery build on every platform:
whatever builds on the new branch, with a `!<extension>` line for each optional
extension that does not compile there yet on any platform and was left out
everywhere. `mise-php` regenerates its support snapshot from the new policy. The
branch merges only after its first release builds on every platform and passes
the exact module comparison against that list, and every later release of the
branch is held to the same list. The upstream canary
reports when a left-out extension compiles again, with the list edit that
adds it back by pull request. Publication waits for readiness
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
