<?php

declare(strict_types=1);

namespace Frost\Taint;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Scalar;

/**
 * Where in the query does the value actually land?
 *
 * Escaping a value is not a property of the value. It is a property of the
 * value *and the place it is put*, and every escaping function PHP ships
 * protects exactly one place: inside a quoted string literal. Put the same
 * escaped value anywhere else in the statement and the escaping does nothing,
 * because there were no quotes for it to break out of in the first place:
 *
 *     $id = mysqli_real_escape_string($db, $_GET['id']);
 *     "SELECT * FROM u WHERE id = $id"            -- injectable. 1 OR 1=1
 *     "SELECT * FROM u ORDER BY $id"              -- injectable. an identifier
 *     "SELECT * FROM u LIMIT $id"                 -- injectable
 *     "SELECT * FROM u WHERE n = '$id'"           -- safe, and the only safe one
 *
 * Every tool that models escaping as a flag calls all four of those clean.
 * They are the commonest surviving SQL injection in code that was audited
 * once, "fixed" by wrapping everything in an escape call, and signed off.
 *
 * So frostphp reconstructs the literal skeleton of the query, finds each hole
 * where a value is dropped in, and reads the characters immediately before it.
 */
final class Sql
{
    public const CONTEXT_QUOTED = 'quoted';
    public const CONTEXT_BARE = 'bare';
    public const CONTEXT_IDENTIFIER = 'identifier';
    public const CONTEXT_UNKNOWN = 'unknown';

    /** SQL positions where no amount of escaping helps, because a quote is not expected. */
    private const IDENTIFIER_BEFORE = '/\b(order\s+by|group\s+by|limit|offset|from|join|into|update|table|having|as)\s+[`"\[]?\s*$/i';

    /**
     * The context of each interpolated hole, in order.
     *
     * @return list<array{Expr, string}> the expression dropped in, and where it lands
     */
    public static function holes(Node $query): array
    {
        $parts = self::flatten($query);
        $literal = '';
        $out = [];

        foreach ($parts as $part) {
            if (is_string($part)) {
                $literal .= $part;
                continue;
            }
            $out[] = [$part, self::contextAfter($literal)];
            // The value itself is opaque; assume it closes nothing it opened.
            $literal .= "\x00";
        }

        return $out;
    }

    /** Reading the query text that precedes a hole. */
    public static function contextAfter(string $literal): string
    {
        if ($literal === '') {
            return self::CONTEXT_UNKNOWN;
        }
        if (self::insideQuotes($literal)) {
            return self::CONTEXT_QUOTED;
        }
        if (preg_match(self::IDENTIFIER_BEFORE, $literal) === 1) {
            return self::CONTEXT_IDENTIFIER;
        }

        return self::CONTEXT_BARE;
    }

    /**
     * Is the end of this text inside an open string literal?
     *
     * Counting quotes is enough because a query skeleton is literal text: any
     * quote in it was typed by the developer, and a hole cannot close one it
     * did not open.
     */
    private static function insideQuotes(string $text): bool
    {
        $single = 0;
        $double = 0;
        $length = strlen($text);
        for ($i = 0; $i < $length; $i++) {
            $char = $text[$i];
            if ($char === '\\') {
                $i++;
                continue;
            }
            if ($char === "'" && $double % 2 === 0) {
                $single++;
            } elseif ($char === '"' && $single % 2 === 0) {
                $double++;
            }
        }

        return $single % 2 === 1 || $double % 2 === 1;
    }

    /**
     * The expression as an alternating run of literal text and dropped-in values.
     *
     * @return list<string|Expr>
     */
    private static function flatten(Node $node): array
    {
        if ($node instanceof Scalar\String_) {
            return [$node->value];
        }
        if ($node instanceof Expr\BinaryOp\Concat) {
            return [...self::flatten($node->left), ...self::flatten($node->right)];
        }
        if ($node instanceof Scalar\InterpolatedString) {
            $out = [];
            foreach ($node->parts as $part) {
                $out = $part instanceof Node\InterpolatedStringPart
                    ? [...$out, $part->value]
                    : [...$out, $part];
            }

            return $out;
        }
        if ($node instanceof Expr\Assign) {
            return self::flatten($node->expr);
        }

        return $node instanceof Expr ? [$node] : [];
    }

    /** Why this landing place is or is not protected by escaping. */
    public static function explain(string $context): string
    {
        return match ($context) {
            self::CONTEXT_BARE => 'the value lands outside quotes, where escaping does nothing',
            self::CONTEXT_IDENTIFIER => 'the value lands in an identifier or LIMIT position, which escaping never protects',
            default => '',
        };
    }
}
