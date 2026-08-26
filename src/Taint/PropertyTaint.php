<?php

declare(strict_types=1);

namespace Frost\Taint;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\NodeFinder;

/**
 * Properties that hold untrusted input.
 *
 * The commonest shape in any framework-era PHP application is a controller
 * that stashes the request in one method and uses it in another:
 *
 *     class Report {
 *         function load()  { $this->range = $_GET['range']; }
 *         function build() { return "SELECT * FROM h WHERE d > {$this->range}"; }
 *     }
 *
 * Analysing each method in isolation sees neither half of that. A property
 * assigned untrusted input anywhere in a class is treated as untrusted
 * everywhere in it - flow-insensitive on purpose, because the call order
 * between methods is exactly what a static pass cannot know.
 */
final class PropertyTaint
{
    /**
     * @param list<Node> $stmts
     *
     * @return array<string, Value>
     */
    public static function find(array $stmts): array
    {
        $out = [];
        foreach ((new NodeFinder())->findInstanceOf($stmts, Expr\Assign::class) as $assign) {
            /** @var Expr\Assign $assign */
            $target = $assign->var;
            if (!$target instanceof Expr\PropertyFetch || !$target->name instanceof Node\Identifier) {
                continue;
            }
            $origin = self::sourceIn($assign->expr);
            if ($origin !== null) {
                $out[strtolower($target->name->toString())] = new Value($origin);
            }
        }

        return $out;
    }

    /** The name of an untrusted read inside this expression, if there is one. */
    private static function sourceIn(Node $node): ?string
    {
        if ($node instanceof Expr\ArrayDimFetch) {
            $base = $node->var;
            if ($base instanceof Expr\Variable && is_string($base->name) && isset(Vocabulary::SUPERGLOBALS[$base->name])) {
                $key = $node->dim instanceof Node\Scalar\String_ ? sprintf("'%s'", $node->dim->value) : '...';

                return sprintf('$%s[%s]', $base->name, $key);
            }
        }
        if ($node instanceof Expr\Variable && is_string($node->name) && isset(Vocabulary::SUPERGLOBALS[$node->name])) {
            return '$' . $node->name;
        }
        foreach ($node->getSubNodeNames() as $key) {
            $sub = $node->{$key};
            foreach (is_array($sub) ? $sub : [$sub] as $child) {
                if ($child instanceof Node\Arg) {
                    $child = $child->value;
                }
                if ($child instanceof Node) {
                    $found = self::sourceIn($child);
                    if ($found !== null) {
                        return $found;
                    }
                }
            }
        }

        return null;
    }
}
