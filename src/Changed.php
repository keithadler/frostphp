<?php

declare(strict_types=1);

namespace Frost;

/**
 * Which lines this branch changed.
 *
 * The gentlest way to put a gate on a codebase with history: judge what this
 * branch added and hold back what it inherited. Nobody has to fix a decade of
 * `mysql_query` on the afternoon they install the linter, and nobody gets to
 * add the next one.
 */
final class Changed
{
    /**
     * @return array<string, list<array{int, int}>> file => list of [start, end] line ranges
     */
    public static function since(string $ref, ?string $cwd = null): array
    {
        $command = sprintf(
            'git -C %s diff --unified=0 --no-color --diff-filter=d %s -- 2>/dev/null',
            escapeshellarg($cwd ?? getcwd() ?: '.'),
            escapeshellarg($ref)
        );
        // frostphp: allow process.exec -- reading a git diff is the whole point of --diff
        $output = @shell_exec($command);
        if (!is_string($output) || trim($output) === '') {
            return [];
        }

        $ranges = [];
        $file = null;
        foreach (explode("\n", $output) as $line) {
            if (str_starts_with($line, '+++ b/')) {
                $file = substr($line, 6);
                continue;
            }
            if ($file === null || !str_starts_with($line, '@@')) {
                continue;
            }
            if (preg_match('/^@@ -\S+ \+(\d+)(?:,(\d+))? @@/', $line, $m) !== 1) {
                continue;
            }
            $start = (int) $m[1];
            $count = isset($m[2]) ? (int) $m[2] : 1;
            if ($count > 0) {
                $ranges[$file][] = [$start, $start + $count - 1];
            }
        }

        return $ranges;
    }

    /** @param array<string, list<array{int, int}>> $ranges */
    public static function touches(array $ranges, string $file, int $line): bool
    {
        $normalized = str_replace('\\', '/', $file);
        foreach ($ranges as $candidate => $spans) {
            if (!self::sameFile($candidate, $normalized)) {
                continue;
            }
            foreach ($spans as [$start, $end]) {
                if ($line >= $start && $line <= $end) {
                    return true;
                }
            }
        }

        return false;
    }

    /** git reports repository-relative paths; the CLI may have been given any prefix. */
    private static function sameFile(string $fromGit, string $given): bool
    {
        return $fromGit === $given
            || str_ends_with($given, '/' . $fromGit)
            || str_ends_with($fromGit, '/' . ltrim($given, './'));
    }
}
