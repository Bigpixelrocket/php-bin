# PHP 8.4 spike status

The repository contains the complete staged recipe and CI path, but the spike
is not complete until every checkbox below is backed by a green Apple Silicon
build log.

- [ ] S0: pinned toolchain passes `doctor` and produces a working CLI
- [ ] S1: baseline extension subset is present
- [ ] S2: medium-complexity extension subset is present
- [ ] S3: `sqlsrv` and `pdo_sqlsrv` are present
- [ ] S4: exact `expected-modules/8.4.txt` comparison passes
- [ ] Packaged archive has the documented layout and checksum
- [ ] Ready for the first official PHP 8.4 release

If S3 cannot be completed after investigation, stop before version-matrix or
release work and record the technical blocker for maintainer review.

