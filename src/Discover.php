<?php

declare(strict_types=1);

namespace Frost;

/**
 * Which files are PHP.
 *
 * The extension list is longer than `.php` on purpose. Legacy estates put the
 * interesting code in `.inc` (an include that was never meant to be requested
 * directly, and often can be), templates in `.phtml`, and Drupal keeps whole
 * modules in `.module`, `.install` and `.theme`. Those are the files a scanner
 * that only globs `*.php` walks straight past.
 */
final class Discover
{
    /** @var list<string> */
    public const EXTENSIONS = ['php', 'phtml', 'inc', 'php3', 'php4', 'php5', 'php7', 'module', 'install', 'theme'];

    /** @var list<string> */
    public const SKIP_DIRS = [
        '.git', '.svn', '.hg', 'node_modules', '.idea', '.vscode',
        'vendor', 'bower_components', 'build', 'dist', '.phpunit.cache',
    ];

    /**
     * Every PHP file under the given paths, sorted, de-duplicated.
     *
     * @param list<string> $paths
     * @param list<string> $extensions
     *
     * @return list<string>
     */
    public static function files(array $paths, array $extensions = self::EXTENSIONS, bool $vendor = false): array
    {
        $out = [];
        foreach ($paths as $path) {
            if (is_file($path)) {
                $out[] = $path;
                continue;
            }
            if (!is_dir($path)) {
                continue;
            }
            self::walk($path, $extensions, $vendor, $out);
        }
        $out = array_values(array_unique($out));
        sort($out);

        return $out;
    }

    /** @param list<string> $extensions @param list<string> $out */
    private static function walk(string $dir, array $extensions, bool $vendor, array &$out): void
    {
        $skip = self::SKIP_DIRS;
        if ($vendor) {
            $skip = array_values(array_diff($skip, ['vendor']));
        }

        $entries = @scandir($dir);
        if ($entries === false) {
            return;
        }
        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $full = $dir . DIRECTORY_SEPARATOR . $entry;
            if (is_dir($full)) {
                if (in_array($entry, $skip, true)) {
                    continue;
                }
                self::walk($full, $extensions, $vendor, $out);
                continue;
            }
            if (self::hasExtension($entry, $extensions)) {
                $out[] = $full;
            }
        }
    }

    /** @param list<string> $extensions */
    public static function hasExtension(string $name, array $extensions = self::EXTENSIONS): bool
    {
        $dot = strrpos($name, '.');

        return $dot !== false && in_array(strtolower(substr($name, $dot + 1)), $extensions, true);
    }
}
