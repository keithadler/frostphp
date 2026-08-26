<?php

declare(strict_types=1);

namespace Frost\Policy;

/**
 * Path globs for a rule's `in "<glob>"` scope.
 *
 * Implemented rather than delegated to fnmatch(), because a policy that scopes a
 * grant to "src/legacy/*" and silently matches nothing on one platform is worse
 * than no scope at all. `**` crosses directory separators, `*` and `?` do not.
 */
final class Glob
{
    public static function match(string $pattern, string $path): bool
    {
        $path = str_replace('\\', '/', $path);
        $pattern = str_replace('\\', '/', $pattern);

        return (bool) preg_match('#^' . self::toRegex($pattern) . '$#', $path);
    }

    private static function toRegex(string $pattern): string
    {
        $out = '';
        $length = strlen($pattern);

        for ($i = 0; $i < $length; $i++) {
            $char = $pattern[$i];
            if ($char === '*') {
                if (($pattern[$i + 1] ?? '') === '*') {
                    // `**` crosses separators; `**/` also matches zero directories,
                    // so "src/**/*.php" covers "src/a.php" as well as "src/a/b.php".
                    $i++;
                    if (($pattern[$i + 1] ?? '') === '/') {
                        $i++;
                        $out .= '(?:.*/)?';
                    } else {
                        $out .= '.*';
                    }
                } else {
                    $out .= '[^/]*';
                }
                continue;
            }
            $out .= match ($char) {
                '?' => '[^/]',
                default => preg_quote($char, '#'),
            };
        }

        return $out;
    }
}
