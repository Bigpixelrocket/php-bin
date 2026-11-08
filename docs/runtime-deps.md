# Runtime dependencies

The CLI executable is built to be as self-contained as practical. A module can
be present in `php -m` while still requiring a service, driver, or operating
system package for a particular connection or feature.

## Shared extensions

Shared extensions load from each install's `bin/php.ini`. One that is turned off
there is absent from `php -m` even though its `.so` ships in
`lib/php/extensions`. Every shared extension links only operating system
libraries (macOS system libraries, or glibc on Linux); anything else it needs is
built into its own `.so`.

## Linux

The Linux archives, `linux-x86_64` and `linux-aarch64`, run on any glibc
distribution with glibc 2.17 or newer: Fedora, RHEL and its rebuilds from 7 on,
Ubuntu from 16.04 on, Debian, Pop!_OS, Arch Linux and Omarchy, and Gentoo with
glibc. `bin/php` links glibc dynamically, because PHP can load the shared
extensions only through glibc's dynamic loader, and builds everything else in,
including the C++ runtime that imagick and mongodb use. It needs no
distribution package besides glibc itself, which every such system has.

musl distributions such as Alpine, and NixOS, which has no dynamic loader at
the standard path, cannot run these archives.

### HTTPS certificates on Linux

PHP's OpenSSL streams and its curl extension both look for CA certificates
where OpenSSL was configured to, `/etc/ssl`: the bundle `/etc/ssl/cert.pem` and
the hashed certificate folder `/etc/ssl/certs`. curl is built with no CA path
of its own and uses the same defaults. Without any php.ini setting, HTTPS
verified on Fedora, Arch Linux, Ubuntu 16.04 and current, Debian stable, and
Gentoo, each with its CA package installed, but failed on CentOS 7, where
`/etc/ssl/certs` points into `/etc/pki/tls/certs`, which has neither a hashed
folder nor `cert.pem`. Setting `openssl.cafile` and `curl.cainfo` to the
distribution's bundle, `/etc/ssl/certs/ca-certificates.crt` or
`/etc/pki/tls/certs/ca-bundle.crt`, works on all of them, and that is what
`mise-php` writes into each install's php.ini on Linux.

Two libraries are built differently on Linux because zig, the compiler the
Linux build uses, is stricter than the GCC that StaticPHP's Linux recipes
assume:

- imap's c-client library links a `crypt()` that always fails instead of the
  system libcrypt, which glibc 2.17 ships as `libcrypt.so.1` while Fedora and
  Arch ship only `libcrypt.so.2`. c-client calls `crypt()` only to check a local
  Unix password when it serves IMAP itself, which PHP's imap extension, a
  client, never does. PHP's own `crypt()` and `password_hash()` use PHP's
  bundled implementation, and the smoke test checks both on every distribution.
- libde265, the HEIC decoder behind imagick, uses its SSE4.1 kernels on x86_64
  CPUs that have SSE4.1 and its plain C kernels on older ones. Its AVX2 and
  AVX-512 kernels need a CPU-detection runtime zig does not provide, so they are
  never selected.

## SQL Server

`sqlsrv` and `pdo_sqlsrv` require a compatible ODBC driver at runtime. On an
Apple Silicon Mac, install Microsoft's current ODBC driver using its published
Homebrew instructions. On Linux, install Microsoft's `msodbcsql18` package for
the distribution; the unixODBC driver manager built into PHP reads the driver
list from `/etc/odbcinst.ini`, where that package registers itself.
`unixODBC` alone provides the driver manager; it does not provide the SQL
Server driver.

Verify the installation with:

```bash
odbcinst -j
odbcinst -q -d
php -r 'var_dump(extension_loaded("sqlsrv"), extension_loaded("pdo_sqlsrv"));'
```

## External services

Database and messaging extensions also require a reachable server and valid
client settings. The PHP archive does not install or operate MySQL, PostgreSQL,
MongoDB, Redis, Memcached, RabbitMQ, Kafka, LDAP, or SQL Server services.

## ImageMagick

The build gate verifies that `imagick` loads. If a future recipe links against
dynamic ImageMagick components, the release notes must name the required
runtime formula and supported major before publishing.

