# PHP 8.4 spike status

The repository contains the complete staged recipe and CI path, but the spike
is not complete until every checkbox below is backed by a green Apple Silicon
build log.

- [x] S0: pinned toolchain passes `doctor` and produces a working CLI
- [x] S1: baseline extension subset is present
- [x] S2: medium-complexity extension subset is present
- [x] S3: `sqlsrv` and `pdo_sqlsrv` are present
- [x] S4: exact `expected-modules/8.4.txt` comparison passes
- [x] Packaged archive has the documented layout and checksum
- [x] Ready for the first official PHP 8.4 release

The complete S4 recipe passed locally and in GitHub Actions on a macOS 26
Apple Silicon runner. The spike is ready for phase 2: the PHP 8.4 release and
the full supported-version matrix.
