<?php

declare(strict_types=1);

if (patch_point() !== 'before-php-configure' || builder()->getPHPVersionID() >= 80200) {
    return;
}

$variable = 'SPC_CMD_VAR_PHP_MAKE_EXTRA_CFLAGS';
$flags = getenv($variable) ?: '';

if (!str_contains($flags, '-std=')) {
    f_putenv($variable . '=' . trim($flags . ' -std=gnu17'));
}
