<?php

declare(strict_types=1);

namespace Frost\Taint;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Scalar;

/**
 * Checks that make a value safe by proving what it is.
 *
 * Careful code does not sanitise untrusted input so much as refuse it. It
 * looks the value up in a list of the ones it will accept and gives up if it
 * is not there:
 *
 *     if ( ! isset( $allowed[ $name ] ) ) { return false; }
 *     return new $name();                 // $name is now one of the keys
 *
 * An analysis that cannot read that guard reports the `new $name` and is
 * wrong, and it is wrong specifically on the codebases that took the most
 * care - which is the worst possible place for a linter to be noisy. This is
 * where most of frostphp's false positives on WordPress core came from.
 *
 * Only guards that constrain the value to a known set count. `if ($x)` proves
 * nothing, `strlen($x) < 10` proves nothing, and an unanchored regex proves
 * nothing about the rest of the string - so none of them appear here.
 */
final class Guards
{
    /**
     * The variable this condition vouches for, and whether the check is
     * inverted - `!isset(...)`, the shape of an early return.
     *
     * @return array{string, bool}|null the variable name, lowercased, and whether negated
     */
    public static function read(Expr $cond): ?array
    {
        if ($cond instanceof Expr\BooleanNot) {
            $inner = self::read($cond->expr);

            return $inner === null ? null : [$inner[0], !$inner[1]];
        }

        // `isset($allowed[$name])` and `!empty($allowed[$name])`
        if ($cond instanceof Expr\Isset_) {
            foreach ($cond->vars as $var) {
                $name = self::keyVariable($var);
                if ($name !== null) {
                    return [$name, false];
                }
            }

            return null;
        }
        if ($cond instanceof Expr\Empty_) {
            $name = self::keyVariable($cond->expr);

            return $name === null ? null : [$name, true];
        }

        if ($cond instanceof Expr\FuncCall && $cond->name instanceof Node\Name) {
            return self::call(strtolower(ltrim($cond->name->toString(), '\\')), $cond);
        }

        // `$x === 'literal'`, which pins the value exactly.
        if ($cond instanceof Expr\BinaryOp\Identical || $cond instanceof Expr\BinaryOp\Equal) {
            foreach ([[$cond->left, $cond->right], [$cond->right, $cond->left]] as [$side, $other]) {
                if ($side instanceof Expr\Variable && is_string($side->name) && $other instanceof Scalar\String_) {
                    return [strtolower($side->name), false];
                }
            }
        }
        if ($cond instanceof Expr\BinaryOp\NotIdentical || $cond instanceof Expr\BinaryOp\NotEqual) {
            foreach ([[$cond->left, $cond->right], [$cond->right, $cond->left]] as [$side, $other]) {
                if ($side instanceof Expr\Variable && is_string($side->name) && $other instanceof Scalar\String_) {
                    return [strtolower($side->name), true];
                }
            }
        }

        // `$x === 'a' || $x === 'b'` vouches only if every arm vouches for the
        // same variable; one loose arm and the value is not pinned at all.
        if ($cond instanceof Expr\BinaryOp\BooleanOr || $cond instanceof Expr\BinaryOp\LogicalOr) {
            $left = self::read($cond->left);
            $right = self::read($cond->right);

            return $left !== null && $right !== null && $left === $right ? $left : null;
        }
        // `isset($a[$x]) && something_else` still proves the isset.
        if ($cond instanceof Expr\BinaryOp\BooleanAnd || $cond instanceof Expr\BinaryOp\LogicalAnd) {
            foreach ([$cond->left, $cond->right] as $side) {
                $found = self::read($side);
                if ($found !== null && !$found[1]) {
                    return $found;
                }
            }
        }

        return null;
    }

    /** @return array{string, bool}|null */
    private static function call(string $name, Expr\FuncCall $cond): ?array
    {
        $arg = static fn (int $i): ?Expr => ($cond->args[$i] ?? null) instanceof Node\Arg
            ? $cond->args[$i]->value
            : null;

        if ($name === 'in_array' || $name === 'array_key_exists') {
            $subject = $arg(0);

            return $subject instanceof Expr\Variable && is_string($subject->name)
                ? [strtolower($subject->name), false]
                : null;
        }

        // An anchored pattern describes the whole string. An unanchored one
        // says only that the string contains something somewhere, which
        // constrains nothing about the rest of it.
        if ($name === 'preg_match') {
            $pattern = $arg(0);
            $subject = $arg(1);
            if (!$pattern instanceof Scalar\String_ || !$subject instanceof Expr\Variable || !is_string($subject->name)) {
                return null;
            }

            return self::anchored($pattern->value) ? [strtolower($subject->name), false] : null;
        }

        // `ctype_alnum($x)`, `is_numeric($x)` and friends describe every byte.
        if (in_array($name, ['ctype_alnum', 'ctype_alpha', 'ctype_digit', 'ctype_xdigit', 'is_numeric', 'is_int', 'is_integer'], true)) {
            $subject = $arg(0);

            return $subject instanceof Expr\Variable && is_string($subject->name)
                ? [strtolower($subject->name), false]
                : null;
        }

        return null;
    }

    /** Does this pattern have to match the whole subject? */
    private static function anchored(string $pattern): bool
    {
        if (strlen($pattern) < 2) {
            return false;
        }
        $delimiter = $pattern[0];
        $closing = match ($delimiter) { '(' => ')', '[' => ']', '{' => '}', '<' => '>', default => $delimiter };
        $end = strrpos($pattern, $closing);
        if ($end === false || $end === 0) {
            return false;
        }
        $body = substr($pattern, 1, $end - 1);
        $modifiers = substr($pattern, $end + 1);

        // A multiline pattern anchors to a line, not to the string, so `^`
        // and `$` stop being a statement about the whole value.
        if (str_contains($modifiers, 'm')) {
            return false;
        }

        return (str_starts_with($body, '^') || str_starts_with($body, '\\A'))
            && (str_ends_with($body, '$') || str_ends_with($body, '\\z') || str_ends_with($body, '\\Z'));
    }

    /**
     * The variable used as the key in `$map[$var]`.
     *
     * `isset($_GET['x'])` proves the request has an `x`, not that `x` is safe,
     * so a superglobal base never vouches for anything.
     */
    private static function keyVariable(Expr $expr): ?string
    {
        if (!$expr instanceof Expr\ArrayDimFetch || $expr->dim === null) {
            return null;
        }
        $base = $expr->var;
        if ($base instanceof Expr\Variable && is_string($base->name) && isset(Vocabulary::SUPERGLOBALS[$base->name])) {
            return null;
        }

        return $expr->dim instanceof Expr\Variable && is_string($expr->dim->name)
            ? strtolower($expr->dim->name)
            : null;
    }

    /**
     * Does this block always leave, so that what follows it is only reached
     * when the guard passed?
     *
     * @param list<Node> $stmts
     */
    public static function alwaysExits(array $stmts): bool
    {
        $last = end($stmts);
        if ($last === false) {
            return false;
        }
        if ($last instanceof Node\Stmt\Return_
            || $last instanceof Node\Stmt\Throw_
            || $last instanceof Node\Stmt\Continue_
            || $last instanceof Node\Stmt\Break_) {
            return true;
        }
        if ($last instanceof Node\Stmt\Expression) {
            $expr = $last->expr;
            if ($expr instanceof Expr\Exit_ || $expr instanceof Expr\Throw_) {
                return true;
            }
            // wp_die(), abort(), dd() and friends: named, and they do not return.
            if ($expr instanceof Expr\FuncCall && $expr->name instanceof Node\Name) {
                return in_array(
                    strtolower(ltrim($expr->name->toString(), '\\')),
                    ['exit', 'die', 'wp_die', 'abort', 'dd', 'trigger_error'],
                    true
                );
            }
        }

        return false;
    }
}
