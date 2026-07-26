<?php

declare(strict_types=1);

if (PHP_OS_FAMILY !== 'Darwin' || patch_point() !== 'before-library[postgresql]-build') {
    return;
}

$path = SOURCE_PATH . '/postgresql/src/port/snprintf.c';
$source = file_get_contents($path);
if ($source === false) {
    throw new RuntimeException("Unable to read PostgreSQL source: {$path}");
}

$replacement = <<<'C'
#ifndef HAVE_STRCHRNUL

static inline const char *
pg_strchrnul(const char *s, int c)
{
	while (*s != '\0' && *s != c)
		s++;
	return s;
}

#define strchrnul pg_strchrnul

#else
C;

if (str_contains($source, '#define strchrnul pg_strchrnul')) {
    return;
}

$pattern = <<<'C'
#ifndef HAVE_STRCHRNUL

static inline const char *
strchrnul(const char *s, int c)
{
	while (*s != '\0' && *s != c)
		s++;
	return s;
}

#else
C;

$patched = str_replace($pattern, $replacement, $source, $count);
if ($count !== 1) {
    throw new RuntimeException('PostgreSQL strchrnul fallback did not match the expected source.');
}

if (file_put_contents($path, $patched) === false) {
    throw new RuntimeException("Unable to patch PostgreSQL source: {$path}");
}
