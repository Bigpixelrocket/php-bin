# Runtime dependencies

The CLI executable is built to be as self-contained as practical. A module can
be present in `php -m` while still requiring a service, driver, or operating
system package for a particular connection or feature.

## Shared extensions

Shared extensions load from each install's `bin/php.ini`. One that is turned off
there is absent from `php -m` even though its `.so` ships in
`lib/php/extensions`. Every shared extension links only macOS system
libraries; anything else it needs is built into its own `.so`.

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

Database and messaging extensions also require a reachable server and valid
client settings. The PHP archive does not install or operate MySQL, PostgreSQL,
MongoDB, Redis, Memcached, RabbitMQ, Kafka, LDAP, or SQL Server services.

## ImageMagick

The build gate verifies that `imagick` loads. If a future recipe links against
dynamic ImageMagick components, the release notes must name the required
runtime formula and supported major before publishing.

