<?php

declare(strict_types=1);

namespace Frost;

/**
 * Inline exceptions, which must name the capability and say why.
 *
 *     shell_exec($cmd);  // frostphp: allow process.exec -- vetted, argv is fixed
 *
 * Both halves are compulsory. A bare ignore comment is how a policy dies: it
 * spreads, it takes ten seconds to add, and six months later nobody can say
 * which of them were decisions. Naming the capability keeps the exception
 * narrow, and the reason is the part a reviewer actually reads.
 */
final class Suppress
{
    /**
     * Suppressions in a file: line number => list of capability codes.
     *
     * @return array<int, list<string>>
     */
    public static function marks(string $code): array
    {
        $out = [];
        foreach (preg_split('/\r\n|\r|\n/', $code) ?: [] as $index => $line) {
            if (preg_match('/frostphp:\s*allow\s+([A-Za-z0-9_.*]+)\s*--\s*(\S.*)$/', $line, $m) !== 1) {
                continue;
            }
            $number = $index + 1;
            $out[$number][] = $m[1];
            // A comment on its own line covers the line beneath it, which is
            // where people naturally put it for a long call.
            if (trim((string) preg_replace('#^\s*(//|\#|/\*)\s*#', '', $line)) === trim($m[0])) {
                $out[$number + 1][] = $m[1];
            }
        }

        return $out;
    }

    /**
     * @param array<int, list<string>> $marks
     */
    public static function covers(array $marks, int $line, string $capability): bool
    {
        foreach ($marks[$line] ?? [] as $allowed) {
            if ($allowed === '*' || Capabilities::covers($allowed, $capability)) {
                return true;
            }
        }

        return false;
    }
}
