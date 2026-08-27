<?php

declare(strict_types=1);

namespace Frost\Composer;

use Frost\Analysis;
use Frost\Discover;
use Frost\Extract\Extractor;
use Frost\Extract\Usage;

/**
 * What runs before you call anything.
 *
 * Every language has a supply-chain question. PHP's has a specific and
 * under-appreciated shape, and it is not "could this package do something
 * dangerous if I called it".
 *
 *   composer.json `autoload.files`  is a list of PHP files that Composer's
 *   autoloader includes eagerly, at the top of every single request, before
 *   one line of application code runs. A package with a socket call at the top
 *   level of a `files` entry has already opened it. Nobody called anything.
 *
 *   composer.json `scripts`         run on the developer's machine and on the
 *   build agent, at install time, as whatever user ran composer. `post-install-cmd`
 *   is a shell command in a JSON file downloaded from the internet.
 *
 * Those two are where the published Packagist incidents lived, and neither is
 * visible to a tool that only asks what a function body can do. So `frostphp
 * deps` separates install-time from request-time from merely-reachable, and
 * reports the first two loudly.
 */
final class Deps
{
    /** Reading a setting is not the same as opening a socket, and only one is news. */
    private const QUIET_AT_LOAD = ['env.read', 'env.ini', 'include.autoload', 'response.session'];

    /**
     * @return array{packages: int, files: int, eager: list<array{string, Usage}>, scripts: list<array{string, string, string}>, findings: list<array{string, Usage}>}
     */
    public static function audit(string $root): array
    {
        $vendor = rtrim($root, '/\\') . DIRECTORY_SEPARATOR . 'vendor';
        $installed = self::installed($vendor);

        $eager = [];
        $findings = [];
        // Keyed by path: an autoload.files entry is walked twice, once as an
        // eager include and once as part of its package, and reporting it as
        // two files would overstate what was read.
        $seen = [];

        foreach ($installed as $package) {
            $name = $package['name'];
            $base = $package['path'];

            foreach ($package['files'] as $relative) {
                $path = $base . DIRECTORY_SEPARATOR . $relative;
                if (!is_file($path)) {
                    continue;
                }
                $seen[$path] = true;
                foreach (self::usesIn($path) as $use) {
                    if ($use->topLevel && !in_array($use->capability, self::QUIET_AT_LOAD, true)) {
                        $eager[] = [$name, $use];
                    }
                }
            }
        }

        // Everything else in the tree: reachable, not automatic.
        foreach ($installed as $package) {
            foreach (Discover::files([$package['path']], Discover::EXTENSIONS, vendor: true) as $path) {
                $seen[$path] = true;
                foreach (self::usesIn($path) as $use) {
                    if ($use->topLevel && !in_array($use->capability, self::QUIET_AT_LOAD, true)) {
                        $findings[] = [$package['name'], $use];
                    }
                }
            }
        }

        return [
            'packages' => count($installed),
            'files' => count($seen),
            'eager' => $eager,
            'scripts' => self::scripts($root, $installed),
            'findings' => $findings,
        ];
    }

    /** @return list<Usage> */
    private static function usesIn(string $path): array
    {
        $code = @file_get_contents($path);
        if ($code === false) {
            return [];
        }
        try {
            [$uses] = Extractor::run($path, $code);
        } catch (\PhpParser\Error) {
            return [];
        }

        return $uses;
    }

    /**
     * Installed packages, with the files Composer includes eagerly for each.
     *
     * @return list<array{name: string, version: string, path: string, files: list<string>, scripts: array<string, mixed>}>
     */
    public static function installed(string $vendor): array
    {
        $manifest = $vendor . '/composer/installed.json';
        $raw = @file_get_contents($manifest);
        if ($raw === false) {
            return [];
        }
        $data = json_decode($raw, true);
        if (!is_array($data)) {
            return [];
        }
        $packages = $data['packages'] ?? $data;
        if (!is_array($packages)) {
            return [];
        }

        $out = [];
        foreach ($packages as $package) {
            if (!is_array($package) || !isset($package['name'])) {
                continue;
            }
            $install = $package['install-path'] ?? null;
            $path = is_string($install)
                ? self::normalize($vendor . '/composer/' . $install)
                : $vendor . '/' . $package['name'];

            $out[] = [
                'name' => (string) $package['name'],
                'version' => (string) ($package['version'] ?? '?'),
                'path' => $path,
                'files' => array_values(array_filter(
                    (array) ($package['autoload']['files'] ?? []),
                    static fn ($f): bool => is_string($f)
                )),
                'scripts' => (array) ($package['scripts'] ?? []),
            ];
        }

        return $out;
    }

    /**
     * Install-time commands, from the root manifest and from every package.
     *
     * @param list<array{name: string, version: string, path: string, files: list<string>, scripts: array<string, mixed>}> $installed
     *
     * @return list<array{string, string, string}> package, hook, command
     */
    public static function scripts(string $root, array $installed): array
    {
        $out = [];

        $rootJson = @file_get_contents(rtrim($root, '/\\') . '/composer.json');
        if ($rootJson !== false) {
            $data = json_decode($rootJson, true);
            if (is_array($data)) {
                foreach (self::flatten((array) ($data['scripts'] ?? [])) as [$hook, $command]) {
                    $out[] = ['(this project)', $hook, $command];
                }
            }
        }

        foreach ($installed as $package) {
            foreach (self::flatten($package['scripts']) as [$hook, $command]) {
                $out[] = [$package['name'], $hook, $command];
            }
        }

        return $out;
    }

    /**
     * @param array<string, mixed> $scripts
     *
     * @return list<array{string, string}>
     */
    private static function flatten(array $scripts): array
    {
        $out = [];
        foreach ($scripts as $hook => $commands) {
            foreach ((array) $commands as $command) {
                if (is_string($command)) {
                    $out[] = [(string) $hook, $command];
                }
            }
        }

        return $out;
    }

    private static function normalize(string $path): string
    {
        $parts = [];
        foreach (explode('/', str_replace('\\', '/', $path)) as $part) {
            if ($part === '..' && $parts !== [] && end($parts) !== '..') {
                array_pop($parts);
            } elseif ($part !== '.' && $part !== '') {
                $parts[] = $part;
            }
        }

        return (str_starts_with($path, '/') ? '/' : '') . implode('/', $parts);
    }
}
