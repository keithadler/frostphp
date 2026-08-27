<?php

declare(strict_types=1);

namespace Frost;

/**
 * Blade templates, turned into the PHP they stand for.
 *
 * A `.blade.php` file is not PHP. `@if`, `{{ $x }}` and `{!! $x !!}` all parse
 * as ordinary text, so the file comes back with no statements in it at all -
 * no error, no findings, and a Laravel application's entire view layer reports
 * clean because none of it was ever read. That is the same failure as short
 * open tags wearing a different hat, and it is the one this tool exists to
 * refuse.
 *
 * What is converted is what carries an expression and cannot unbalance
 * anything: the two output forms and `@php` blocks.
 *
 *     {!! $x !!}   ->  <?= $x  ?>      raw output; the risky one
 *     {{ $x }}     ->  <?=e( $x )?>    escaped; `e()` is a known sanitiser,
 *                                      so this is read and stays quiet
 *     @php ... @endphp  ->  <?php ... ?>
 *
 * Control directives are deliberately left as text. Rewriting `@if` means
 * rewriting every matching `@endif` too, and one directive this file has not
 * heard of would unbalance the block and turn a template into a syntax error -
 * trading a silent miss for a broken build across a whole view directory. The
 * expressions inside conditions are not analysed; the output they guard is.
 *
 * `{{--` comments and `@verbatim` blocks are blanked with spaces rather than
 * removed, so every line and column downstream stays exactly where it was.
 */
final class Blade
{
    /**
     * Where a template prints without escaping.
     *
     * After conversion a `{!! ... !!}` block is an ordinary `<?=`, which is the
     * right thing for taint - it is an output sink either way - but loses the
     * fact that the author asked for the unescaped form. That is a capability
     * worth a policy line of its own: `forbid raw output` is a rule a team can
     * hold, and without it a view directory with no superglobals in it reports
     * nothing at all and looks like it was never read.
     *
     * @return list<array{int, int}> line and column of each raw block
     */
    public static function rawOutputs(string $code): array
    {
        $out = [];
        $line = 1;
        $column = 0;
        $length = strlen($code);

        for ($i = 0; $i < $length; $i++) {
            if ($code[$i] === "\n") {
                $line++;
                $column = 0;
                continue;
            }

            // A block that is not rendered cannot print anything, however much
            // it looks like it does.
            $skip = self::inertSpan($code, $i, $length);
            if ($skip !== null) {
                for ($end = $i + $skip; $i < $end && $i < $length; $i++) {
                    if ($code[$i] === "\n") {
                        $line++;
                        $column = 0;
                    } else {
                        $column++;
                    }
                }
                $i--;
                continue;
            }

            // `@{!!` prints the braces literally rather than opening a block.
            if (substr($code, $i, 3) === '{!!' && ($i === 0 || $code[$i - 1] !== '@')) {
                $out[] = [$line, $column];
            }
            $column++;
        }

        return $out;
    }

    /** The length of a comment or verbatim block starting here, if one does. */
    private static function inertSpan(string $code, int $i, int $length): ?int
    {
        if (substr($code, $i, 4) === '{{--') {
            $end = strpos($code, '--}}', $i + 4);

            return $end === false ? $length - $i : $end + 4 - $i;
        }
        if (substr($code, $i, 9) === '@verbatim') {
            $end = strpos($code, '@endverbatim', $i);

            return $end === false ? $length - $i : $end + 12 - $i;
        }

        return null;
    }

    public static function isBlade(string $file): bool
    {
        return str_ends_with(strtolower($file), '.blade.php');
    }

    /**
     * @return array{string, list<array{int, int}>} the code, and [offset, shift] pairs
     */
    public static function prepare(string $code): array
    {
        $out = '';
        $shifts = [];
        $total = 0;
        $length = strlen($code);
        $i = 0;

        while ($i < $length) {
            // `@{{` and `@{!!` are how a template prints the braces literally.
            if ($code[$i] === '@' && (substr($code, $i + 1, 2) === '{{' || substr($code, $i + 1, 3) === '{!!')) {
                $take = substr($code, $i + 1, 3) === '{!!' ? 4 : 3;
                $out .= substr($code, $i, $take);
                $i += $take;
                continue;
            }

            $replaced = self::at($code, $i, $length);
            if ($replaced === null) {
                $out .= $code[$i++];
                continue;
            }

            [$text, $consumed] = $replaced;
            $shift = strlen($text) - $consumed;
            $out .= $text;
            if ($shift !== 0) {
                $total += $shift;
                $shifts[] = [strlen($out), $total];
            }
            $i += $consumed;
        }

        return [$out, $shifts];
    }

    /**
     * The replacement for the construct at this offset, if there is one.
     *
     * @return array{string, int}|null the text to write, and the bytes it replaces
     */
    private static function at(string $code, int $i, int $length): ?array
    {
        // A comment: blanked, so nothing downstream moves.
        if (substr($code, $i, 4) === '{{--') {
            $end = strpos($code, '--}}', $i + 4);
            $span = $end === false ? $length - $i : $end + 4 - $i;

            return [self::blank(substr($code, $i, $span)), $span];
        }

        // Raw output. The opening and closing tokens are three bytes each on
        // both sides of the swap, so this one moves nothing at all.
        if (substr($code, $i, 3) === '{!!') {
            $end = strpos($code, '!!}', $i + 3);
            if ($end === false) {
                return null;
            }
            $expression = substr($code, $i + 3, $end - $i - 3);

            return ['<?=' . $expression . ' ?>', $end + 3 - $i];
        }

        // Escaped output. Wrapped in Laravel's own escaper, which frostphp
        // knows sanitises for markup, so it is read and correctly stays quiet.
        if (substr($code, $i, 2) === '{{') {
            $end = strpos($code, '}}', $i + 2);
            if ($end === false) {
                return null;
            }
            $expression = substr($code, $i + 2, $end - $i - 2);
            if (trim($expression) === '') {
                return null;
            }

            return ['<?=e(' . $expression . ')?>', $end + 2 - $i];
        }

        if (substr($code, $i, 9) === '@verbatim') {
            $end = strpos($code, '@endverbatim', $i);
            $span = $end === false ? $length - $i : $end + 12 - $i;

            return [self::blank(substr($code, $i, $span)), $span];
        }

        if (substr($code, $i, 7) === '@endphp') {
            return ['?>', 7];
        }

        if (substr($code, $i, 4) === '@php') {
            $after = $code[$i + 4] ?? '';
            // The inline form, `@php($x = 1)`, is one statement.
            if ($after === '(') {
                $end = self::matchParen($code, $i + 4, $length);
                if ($end === null) {
                    return null;
                }
                $body = substr($code, $i + 5, $end - $i - 5);

                return ['<?php ' . $body . '; ?>', $end + 1 - $i];
            }
            if ($after === '' || preg_match('/\s/', $after) === 1) {
                return ['<?php', 4];
            }
        }

        return null;
    }

    /** Same length, same newlines, no content. */
    private static function blank(string $text): string
    {
        return (string) preg_replace('/[^\n]/', ' ', $text);
    }

    private static function matchParen(string $code, int $open, int $length): ?int
    {
        $depth = 0;
        for ($i = $open; $i < $length; $i++) {
            $char = $code[$i];
            if ($char === '(') {
                $depth++;
            } elseif ($char === ')') {
                $depth--;
                if ($depth === 0) {
                    return $i;
                }
            } elseif ($char === "'" || $char === '"') {
                for ($i++; $i < $length; $i++) {
                    if ($code[$i] === '\\') {
                        $i++;
                    } elseif ($code[$i] === $char) {
                        break;
                    }
                }
            }
        }

        return null;
    }
}
