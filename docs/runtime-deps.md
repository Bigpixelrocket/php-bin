# Runtime dependencies

The CLI executable is built to be as self-contained as practical. A module can
be present in `php -m` while still requiring a service, driver, or operating
system package for a particular connection or feature.

## SQL Server

`sqlsrv` and `pdo_sqlsrv` require a compatible ODBC driver at runtime. On an
Apple Silicon Mac, install Microsoft's current ODBC driver using its published
Homebrew instructions. `unixODBC` alone provides the driver manager; it does
not provide the SQL Server driver.

Verify the installation with:

```bash
odbcinst -j
odbcinst -q -d
php -r 'var_dump(extension_loaded("sqlsrv"), extension_loaded("pdo_sqlsrv"));'
```

## External services

Database extensions also require a reachable server and valid client settings.
The PHP archive does not install or operate MySQL, PostgreSQL, MongoDB, Redis,
LDAP, or SQL Server services.

## ImageMagick

The build gate verifies that `imagick` loads. If a future recipe links against
dynamic ImageMagick components, the release notes must name the required
runtime formula and supported major before publishing.

