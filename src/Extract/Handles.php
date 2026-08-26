<?php

declare(strict_types=1);

namespace Frost\Extract;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\NodeFinder;

/**
 * Which variables in this file are database handles.
 *
 * `$db->query($sql)` is a query. `$builder->query()` is a fluent API, and
 * `$this->logger->query()` is somebody's domain method. There is no way to
 * tell them apart from the method name, so frostphp does not try: a method
 * call counts as a query only when the receiver was seen being assigned a
 * connection in this file, or is one of the two globals PHP applications
 * genuinely share by convention.
 *
 * The cost of this is a missed query when the handle arrives as an untyped
 * parameter from elsewhere. That is the right trade: a capability linter that
 * cries wolf on `->query()` gets switched off in a week, and then it finds
 * nothing at all.
 */
final class Handles
{
    /** Constructors and functions that hand back a connection. @var list<string> */
    private const CONNECTORS = [
        'pdo', 'mysqli', 'sqlite3', 'mongodb\driver\manager',
    ];

    /** @var list<string> */
    private const CONNECT_CALLS = [
        'mysql_connect', 'mysql_pconnect', 'mysqli_connect', 'pg_connect', 'pg_pconnect',
        'sqlsrv_connect', 'oci_connect', 'oci_pconnect', 'ibm_db2_connect',
    ];

    /** Globals a PHP application shares by long convention. @var list<string> */
    private const KNOWN_GLOBALS = ['wpdb'];

    /** Methods that run SQL, on something already known to be a handle. @var list<string> */
    public const QUERY_METHODS = [
        'query', 'exec', 'prepare', 'multi_query', 'real_query', 'unbuffered_query',
        'get_results', 'get_row', 'get_var', 'get_col', 'get_charset_collate',
    ];

    /**
     * Variable and property names that hold a connection.
     *
     * @param list<Node> $stmts
     *
     * @return array{vars: array<string,true>, props: array<string,true>}
     */
    public static function find(array $stmts): array
    {
        $vars = [];
        $props = [];
        foreach (self::KNOWN_GLOBALS as $name) {
            $vars[$name] = true;
        }

        foreach ((new NodeFinder())->findInstanceOf($stmts, Expr\Assign::class) as $assign) {
            /** @var Expr\Assign $assign */
            if (!self::isConnection($assign->expr)) {
                continue;
            }
            $target = $assign->var;
            if ($target instanceof Expr\Variable && is_string($target->name)) {
                $vars[strtolower($target->name)] = true;
            } elseif ($target instanceof Expr\PropertyFetch && $target->name instanceof Node\Identifier) {
                $props[strtolower($target->name->toString())] = true;
            }
        }

        return ['vars' => $vars, 'props' => $props];
    }

    private static function isConnection(Expr $expr): bool
    {
        if ($expr instanceof Expr\New_ && $expr->class instanceof Node\Name) {
            $class = strtolower(ltrim($expr->class->toString(), '\\'));

            return in_array($class, self::CONNECTORS, true)
                || in_array(strtolower(Names::shortName($class)), self::CONNECTORS, true);
        }
        if ($expr instanceof Expr\FuncCall && $expr->name instanceof Node\Name) {
            return in_array(strtolower(ltrim($expr->name->toString(), '\\')), self::CONNECT_CALLS, true);
        }

        return false;
    }

    /** Is this method call made on something known to hold a connection? */
    public static function isHandle(Expr $receiver, array $known): bool
    {
        if ($receiver instanceof Expr\Variable && is_string($receiver->name)) {
            return isset($known['vars'][strtolower($receiver->name)]);
        }
        if ($receiver instanceof Expr\PropertyFetch && $receiver->name instanceof Node\Identifier) {
            return isset($known['props'][strtolower($receiver->name->toString())]);
        }

        return false;
    }
}
