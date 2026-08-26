<?php

declare(strict_types=1);

namespace Frost;

use PhpParser\Error as ParseError;
use PhpParser\Node\Stmt;
use PhpParser\Parser;
use PhpParser\ParserFactory;
use PhpParser\PhpVersion;

/**
 * Turning bytes into a syntax tree, for a codebase that is not all one age.
 *
 * The tool runs on PHP 8. The code it reads very often does not: a real
 * estate of PHP is PHP 5 source kept alive on a modern runtime, and half of
 * what frostphp exists to find - `create_function`, `preg_replace` with `/e`,
 * `mysql_query`, `$HTTP_GET_VARS`, `import_request_variables` - only appears
 * in exactly that code. A parser that refuses PHP 5 refuses the files that
 * most need reading.
 *
 * The two dialects genuinely conflict, so neither target can read both:
 *
 *     $s{0}                       parses as 5.6 or 7.4, rejected by 8.x
 *     match ($x) { 1 => 'a' }     parses as 8.x, rejected by 5.6 or 7.4
 *
 * So a file is parsed at the newest supported version, and on a syntax error
 * parsed again as PHP 5.6. A repository mid-migration has both kinds of file
 * in it and each is read on its own terms. Short open tags (`<? ... ?>`) need
 * no special handling: the emulative lexer accepts them whatever the target.
 *
 * When both attempts fail the file really is broken, and the reported error is
 * the attempt that reached the furthest line - the one more likely to be about
 * the actual mistake rather than about the dialect.
 *
 * Short open tags need handling before any of that, and getting it wrong is
 * the most dangerous bug this tool could have. PHP's own tokenizer only honours
 * `<?` when `short_open_tag` is on in php.ini, and it is off by default, so a
 * file written as `<? ... ?>` does not fail to parse - it parses perfectly, as
 * one long piece of inert HTML. Every function in it disappears. The linter
 * then reports nothing and exits 0, and the green tick means only that nothing
 * was read. A check decided by something other than the thing under test is
 * worse than no check, because someone believes it.
 *
 * So the tags are rewritten to `<?php` before parsing, and because that makes
 * the text three bytes longer, every shift is recorded and subtracted again
 * when a column is reported. Line numbers never move: no newline is added.
 */
final class Source
{
    /** Parse targets, newest first. Legacy last, because most code is modern. */
    public const AUTO_VERSIONS = ['8.5', '5.6'];

    /**
     * Rewrite the open tags PHP's tokenizer will not see, recording how far
     * each rewrite pushes the text along.
     *
     * `<?=` is left alone: it has been unconditional since PHP 5.4.
     *
     * The scan tracks whether it is in markup or in code, because a tag only
     * opens a block from markup. Inside code, `<?` is just two characters in a
     * string - and a template engine, or this file, is full of them. Rewriting
     * those corrupts the source and the file stops parsing, which is how this
     * was found. For the same reason the scan steps over strings, heredocs and
     * comments before looking for a closing tag: `echo "?>";` closes nothing.
     *
     * @return array{string, list<array{int, int}>} the code, and [offset, shift] pairs
     */
    public static function prepare(string $code): array
    {
        if (preg_match('/<\?(?!php|=)|<%/i', $code) !== 1) {
            return [$code, []];
        }

        $out = '';
        $shifts = [];
        $total = 0;
        $length = strlen($code);
        $i = 0;
        $inPhp = false;
        $aspOpened = false;

        while ($i < $length) {
            $two = substr($code, $i, 2);

            if (!$inPhp) {
                if ($two === '<?' || $two === '<%') {
                    [$replacement, $consumed] = self::openTag($code, $i, $two);
                    $shift = strlen($replacement) - $consumed;
                    $out .= $replacement;
                    if ($shift !== 0) {
                        $total += $shift;
                        $shifts[] = [strlen($out), $total];
                    }
                    $i += $consumed;
                    $inPhp = true;
                    $aspOpened = $two === '<%';
                    continue;
                }
                $out .= $code[$i++];
                continue;
            }

            // `%>` closes a block only when `<%` opened one, so a stray `%>`
            // in ordinary code is left exactly as it was. Both are two bytes,
            // so this rewrite shifts nothing.
            if ($two === '?>' || ($aspOpened && $two === '%>')) {
                $out .= '?>';
                $i += 2;
                $inPhp = false;
                $aspOpened = false;
                continue;
            }

            $skipped = self::skipAtomic($code, $i, $length);
            if ($skipped !== null) {
                [$text, $i, $closedTag] = $skipped;
                $out .= $text;
                if ($closedTag) {
                    $inPhp = false;
                    $aspOpened = false;
                }
                continue;
            }

            $out .= $code[$i++];
        }

        return [$out, $shifts];
    }

    /** @return array{string, int} what to write, and how many bytes it replaces */
    private static function openTag(string $code, int $i, string $two): array
    {
        if ($two === '<?') {
            if (strcasecmp(substr($code, $i + 2, 3), 'php') === 0) {
                return ['<?php', 5];
            }

            return substr($code, $i + 2, 1) === '=' ? ['<?=', 3] : ['<?php', 2];
        }

        return substr($code, $i + 2, 1) === '=' ? ['<?=', 3] : ['<?php', 2];
    }

    /**
     * Step over one string, heredoc or comment without interpreting it.
     *
     * @return array{string, int, bool}|null the text, the next offset, and
     *                                       whether a closing tag was consumed
     */
    private static function skipAtomic(string $code, int $i, int $length): ?array
    {
        $char = $code[$i];
        $two = substr($code, $i, 2);

        if ($char === "'" || $char === '"') {
            $j = $i + 1;
            while ($j < $length) {
                if ($code[$j] === '\\') {
                    $j += 2;
                    continue;
                }
                if ($code[$j] === $char) {
                    $j++;
                    break;
                }
                $j++;
            }

            return [substr($code, $i, $j - $i), $j, false];
        }

        if ($two === '/*') {
            $close = strpos($code, '*/', $i + 2);
            $j = $close === false ? $length : $close + 2;

            return [substr($code, $i, $j - $i), $j, false];
        }

        // `#[` opens an attribute in PHP 8, not a comment.
        if ($two === '//' || ($char === '#' && $two !== '#[')) {
            $j = $i;
            while ($j < $length && $code[$j] !== "\n") {
                // A closing tag ends a line comment, and the block with it.
                if (substr($code, $j, 2) === '?>') {
                    return [substr($code, $i, $j - $i) . '?>', $j + 2, true];
                }
                $j++;
            }

            return [substr($code, $i, $j - $i), $j, false];
        }

        if (substr($code, $i, 3) === '<<<') {
            return self::skipHeredoc($code, $i, $length);
        }

        return null;
    }

    /** @return array{string, int, bool}|null */
    private static function skipHeredoc(string $code, int $i, int $length): ?array
    {
        if (preg_match('/\G<<<[ \t]*([\'"]?)([A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*)\1\r?\n/', $code, $m, 0, $i) !== 1) {
            return null;
        }
        $label = $m[2];
        $j = $i + strlen($m[0]);
        // The closing label sits at the start of a line, optionally indented,
        // and must not be followed by another identifier character.
        if (preg_match('/^[ \t]*' . preg_quote($label, '/') . '(?![A-Za-z0-9_\x80-\xff])/m', $code, $end, PREG_OFFSET_CAPTURE, $j) !== 1) {
            return [substr($code, $i), $length, false];
        }
        $j = $end[0][1] + strlen($end[0][0]);

        return [substr($code, $i, $j - $i), $j, false];
    }

    /**
     * A file that holds PHP but yielded no PHP. The only way this happens is a
     * tag the tokenizer did not recognise, and it must never pass for clean.
     *
     * @param list<Stmt> $stmts
     */
    public static function isVacuous(array $stmts, string $code): bool
    {
        if (!preg_match('/<\?|<%/', $code)) {
            return false;
        }
        foreach ($stmts as $stmt) {
            if (!$stmt instanceof Stmt\InlineHTML) {
                return false;
            }
        }

        return $stmts !== [];
    }

    /** @var array<string, Parser> */
    private static array $parsers = [];

    /**
     * @return array{list<Stmt>, string} the statements, and the version that read them
     *
     * @throws ParseError if no supported dialect can read the file
     */
    public static function parse(string $code, ?string $pin = null): array
    {
        $versions = $pin !== null ? [$pin] : self::AUTO_VERSIONS;
        $furthest = null;

        foreach ($versions as $version) {
            try {
                $stmts = self::parser($version)->parse($code);
                if ($stmts !== null) {
                    return [$stmts, $version];
                }
            } catch (ParseError $e) {
                if ($furthest === null || $e->getStartLine() > $furthest->getStartLine()) {
                    $furthest = $e;
                }
            }
        }

        throw $furthest ?? new ParseError('cannot be parsed');
    }

    /** Is this a version frostphp can be pinned to? */
    public static function supports(string $version): bool
    {
        try {
            PhpVersion::fromString($version);

            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    private static function parser(string $version): Parser
    {
        return self::$parsers[$version] ??= (new ParserFactory())
            ->createForVersion(PhpVersion::fromString($version));
    }
}
