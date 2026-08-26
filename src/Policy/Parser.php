<?php

declare(strict_types=1);

namespace Frost\Policy;

use Frost\Capabilities;

/**
 * The frost dialect. One rule per line; `--` starts a comment.
 *
 *     policy "<name>"
 *     extends "<path to another policy>"
 *     may use <capability> [in "<glob>"] [until YYYY-MM-DD]
 *     forbid <capability>
 */
final class Parser
{
    private const POLICY = '/^policy\s+"([^"]*)"$/';
    private const EXTENDS = '/^extends\s+"([^"]*)"$/';
    private const MAY = '/^may use\s+(.+?)(?:\s+in\s+"([^"]*)")?(?:\s+until\s+(\d{4}-\d{2}-\d{2}))?$/';
    private const FORBID = '/^forbid\s+(.+)$/';

    public static function parse(string $text, ?string $path = null): Policy
    {
        $policy = new Policy(path: $path);

        foreach (preg_split('/\r\n|\r|\n/', $text) ?: [] as $index => $raw) {
            $number = $index + 1;
            [$body, $note] = self::split($raw);
            if ($body === '') {
                continue;
            }
            if (preg_match(self::POLICY, $body, $m) === 1) {
                $policy->name = $m[1];
                continue;
            }
            if (preg_match(self::EXTENDS, $body, $m) === 1) {
                $policy->extends[] = $m[1];
                continue;
            }

            $forbid = false;
            $until = null;
            $glob = null;

            if (preg_match(self::MAY, $body, $m) === 1) {
                $words = trim($m[1]);
                $glob = ($m[2] ?? '') !== '' ? $m[2] : null;
                if (($m[3] ?? '') !== '') {
                    $until = self::date($m[3], $number);
                }
            } elseif (preg_match(self::FORBID, $body, $m) === 1) {
                $words = trim($m[1]);
                $forbid = true;
            } else {
                throw new PolicyError(sprintf('line %d: cannot read "%s"', $number, $body));
            }

            $capability = Capabilities::resolve($words);
            if ($capability === null) {
                throw new PolicyError(sprintf('line %d: unknown capability "%s"', $number, $words));
            }

            $policy->rules[] = new Rule($capability, $glob, $note, $number, $forbid, $until, $path);
        }

        return $policy;
    }

    /**
     * Parse a policy and merge in every base it `extends`.
     *
     * A base is resolved relative to the file that names it, so a shared policy
     * can live one directory up or in a package. The child's rules come last,
     * which matters only for `forbid`: an inherited prohibition a child can
     * silently drop is not a prohibition.
     *
     * @param list<string> $seen
     */
    public static function load(string $path, array $seen = []): Policy
    {
        $real = realpath($path);
        if ($real === false) {
            throw new PolicyError(sprintf('%s: no such policy file', $path));
        }
        if (in_array($real, $seen, true)) {
            throw new PolicyError(sprintf('%s: circular extends', $real));
        }
        $text = @file_get_contents($real);
        if ($text === false) {
            throw new PolicyError(sprintf('%s: cannot be read', $real));
        }

        $policy = self::parse($text, $real);
        if ($policy->extends === []) {
            return $policy;
        }

        $merged = [];
        foreach ($policy->extends as $base) {
            $parent = self::load(dirname($real) . DIRECTORY_SEPARATOR . $base, [...$seen, $real]);
            $merged = [...$merged, ...$parent->rules];
        }
        $policy->rules = [...$merged, ...$policy->rules];

        return $policy;
    }

    /** @return array{string, string} the rule body and its `--` note */
    private static function split(string $raw): array
    {
        $at = strpos($raw, '--');

        return $at === false
            ? [trim($raw), '']
            : [trim(substr($raw, 0, $at)), trim(substr($raw, $at + 2))];
    }

    private static function date(string $value, int $number): string
    {
        $parsed = \DateTimeImmutable::createFromFormat('!Y-m-d', $value, new \DateTimeZone('UTC'));
        if ($parsed === false || $parsed->format('Y-m-d') !== $value) {
            throw new PolicyError(sprintf('line %d: bad date "%s"', $number, $value));
        }

        return $value;
    }
}
