<?php

declare(strict_types=1);

namespace Frost\Taint;

use Frost\Extract\Handles;
use Frost\Extract\Names;
use Frost\Extract\Snippet;
use Frost\Source;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Scalar;
use PhpParser\Node\Stmt;

/**
 * Does untrusted input reach somewhere dangerous?
 *
 * The walk is deliberately bounded, and every bound is a decision about false
 * positives rather than a limitation nobody got round to:
 *
 *   Branches merge, they do not overwrite.  `$c = $_GET['c']` in one arm of an
 *   `if` leaves `$c` tainted afterwards, because one path really does reach the
 *   sink. Overwriting is how a real flow gets hidden.
 *
 *   An unknown call ends the chain.  `sanitise($x)` stops taint rather than
 *   guessing, because a tool that guesses here reports the whole codebase.
 *
 *   One hop, not many.  A tainted argument into a helper that sinks it. What
 *   the helper does is discovered by running this same analysis with one
 *   parameter marked tainted, so a helper can never drift from a direct call.
 */
final class Analyzer
{
    /** @var list<Flow> */
    private array $flows = [];

    /** @var array<string, Value> lowercased variable name => taint */
    private array $scope = [];

    /** @var array<string, Value> lowercased property name => taint, per class */
    private array $properties = [];

    private int $depth = 0;

    private Names $names;

    /** @var array{vars: array<string,true>, props: array<string,true>} */
    private array $handles = ['vars' => [], 'props' => []];

    private function __construct(
        private readonly string $file,
        private readonly Snippet $snippet,
        private readonly Helpers $helpers,
        private readonly bool $probing = false,
    ) {
        $this->names = new Names();
    }

    /**
     * @return array{list<Flow>, string}
     *
     * @throws \PhpParser\Error
     */
    public static function run(string $file, string $raw, ?Helpers $helpers = null, ?string $pin = null): array
    {
        [$code, $shifts] = Source::prepare($raw);
        [$stmts, $version] = Source::parse($code, $pin);
        $analyzer = new self($file, new Snippet($code, $shifts), $helpers ?? new Helpers());
        $analyzer->handles = Handles::find($stmts);
        $analyzer->properties = PropertyTaint::find($stmts);
        $analyzer->predeclare($stmts);
        $analyzer->statements($stmts);

        return [$analyzer->flows, $version];
    }

    /**
     * What one parameter of one function body reaches, with nothing else tainted.
     *
     * @return list<Flow>
     */
    public static function probe(Node\FunctionLike $function, int $index, Snippet $snippet): array
    {
        $params = $function->getParams();
        if (!isset($params[$index]) || !$params[$index]->var instanceof Expr\Variable) {
            return [];
        }
        $name = $params[$index]->var->name;
        if (!is_string($name)) {
            return [];
        }

        $analyzer = new self('', $snippet, new Helpers(), probing: true);
        $analyzer->scope[strtolower($name)] = new Value('parameter');
        $analyzer->statements($function->getStmts() ?? []);

        return $analyzer->flows;
    }

    /**
     * PHP hoists top-level function declarations, so a call above the
     * declaration still reaches it. Collect them before the walk.
     *
     * @param list<Node> $stmts
     */
    private function predeclare(array $stmts): void
    {
        foreach ((new \PhpParser\NodeFinder())->findInstanceOf($stmts, Stmt\Function_::class) as $function) {
            /** @var Stmt\Function_ $function */
            $this->names->declareFunction($function->name->toString());
        }
    }

    // ---- statements -----------------------------------------------------

    /** @param list<Node> $stmts */
    private function statements(array $stmts): void
    {
        foreach ($stmts as $stmt) {
            $this->statement($stmt);
        }
    }

    private function statement(Node $stmt): void
    {
        switch (true) {
            case $stmt instanceof Stmt\Namespace_:
                $this->names->enterNamespace($stmt->name);
                $this->statements($stmt->stmts ?? []);

                return;

            case $stmt instanceof Stmt\Use_:
                foreach ($stmt->uses as $use) {
                    $this->names->addUse($use, $stmt->type);
                }

                return;

            case $stmt instanceof Stmt\Expression:
                $this->expr($stmt->expr);

                return;

            case $stmt instanceof Stmt\Echo_:
                foreach ($stmt->exprs as $expr) {
                    $this->sink($this->expr($expr), 'html', 'echo', $expr);
                }

                return;

            case $stmt instanceof Stmt\Return_:
                if ($stmt->expr !== null) {
                    $this->expr($stmt->expr);
                }

                return;

            case $stmt instanceof Stmt\If_:
                $this->conditional($stmt);

                return;

            case $stmt instanceof Stmt\While_:
            case $stmt instanceof Stmt\Do_:
            case $stmt instanceof Stmt\For_:
            case $stmt instanceof Stmt\Foreach_:
                $this->loop($stmt);

                return;

            case $stmt instanceof Stmt\Switch_:
                $this->switch($stmt);

                return;

            case $stmt instanceof Stmt\TryCatch:
                $this->try($stmt);

                return;

            case $stmt instanceof Stmt\Function_:
            case $stmt instanceof Stmt\ClassMethod:
                $this->body($stmt);

                return;

            case $stmt instanceof Stmt\Class_:
            case $stmt instanceof Stmt\Trait_:
            case $stmt instanceof Stmt\Interface_:
                $saved = $this->properties;
                $this->properties = PropertyTaint::find([$stmt]);
                $this->statements($stmt->stmts);
                $this->properties = $saved;

                return;

            case $stmt instanceof Stmt\Global_:
                // `global $wpdb;` and friends: the name keeps whatever taint
                // the file-level scope gave it, which is nothing by default.
                return;

            default:
                foreach ($stmt->getSubNodeNames() as $name) {
                    $sub = $stmt->{$name};
                    foreach (is_array($sub) ? $sub : [$sub] as $child) {
                        if ($child instanceof Stmt) {
                            $this->statement($child);
                        } elseif ($child instanceof Expr) {
                            $this->expr($child);
                        }
                    }
                }
        }
    }

    /** A function or method body: its own scope, and not top-level code. */
    private function body(Stmt\Function_|Stmt\ClassMethod $node): void
    {
        if ($node instanceof Stmt\Function_) {
            $this->names->declareFunction($node->name->toString());
        }
        $saved = $this->scope;
        $this->scope = [];
        $this->depth++;
        $this->statements($node->stmts ?? []);
        $this->depth--;
        $this->scope = $saved;
    }

    private function conditional(Stmt\If_ $stmt): void
    {
        $this->expr($stmt->cond);
        $before = $this->scope;

        $arms = [];
        $arms[] = $this->arm($before, $stmt->stmts);
        foreach ($stmt->elseifs as $elseif) {
            $this->expr($elseif->cond);
            $arms[] = $this->arm($before, $elseif->stmts);
        }
        $arms[] = $stmt->else !== null ? $this->arm($before, $stmt->else->stmts) : $before;

        $this->scope = $before;
        foreach ($arms as $arm) {
            $this->scope = self::mergeScopes($this->scope, $arm);
        }
    }

    private function loop(Node $stmt): void
    {
        $before = $this->scope;
        foreach (['cond', 'init', 'loop', 'expr', 'keyVar', 'valueVar'] as $name) {
            if (!property_exists($stmt, $name)) {
                continue;
            }
            $sub = $stmt->{$name};
            foreach (is_array($sub) ? $sub : [$sub] as $child) {
                if ($child instanceof Expr) {
                    $this->expr($child);
                }
            }
        }
        // `foreach ($_GET as $k => $v)` taints the loop variables.
        if ($stmt instanceof Stmt\Foreach_) {
            $source = $this->expr($stmt->expr);
            if ($source !== null) {
                foreach ([$stmt->keyVar, $stmt->valueVar] as $var) {
                    if ($var instanceof Expr\Variable && is_string($var->name)) {
                        $this->scope[strtolower($var->name)] = $source;
                    }
                }
            }
        }
        // One pass, then merged with the state before it: enough to catch a
        // value that becomes tainted on the second turn of the loop.
        $after = $this->arm($this->scope, $stmt->stmts ?? []);
        $this->scope = self::mergeScopes($before, $after);
        $this->statements($stmt->stmts ?? []);
    }

    private function switch(Stmt\Switch_ $stmt): void
    {
        $this->expr($stmt->cond);
        $before = $this->scope;
        $merged = $before;
        foreach ($stmt->cases as $case) {
            $merged = self::mergeScopes($merged, $this->arm($before, $case->stmts));
        }
        $this->scope = $merged;
    }

    private function try(Stmt\TryCatch $stmt): void
    {
        $before = $this->scope;
        $merged = $this->arm($before, $stmt->stmts);
        foreach ($stmt->catches as $catch) {
            $merged = self::mergeScopes($merged, $this->arm($before, $catch->stmts));
        }
        if ($stmt->finally !== null) {
            $merged = self::mergeScopes($merged, $this->arm($merged, $stmt->finally->stmts));
        }
        $this->scope = $merged;
    }

    /**
     * Run a branch from a given state and hand back the state it ends in,
     * without disturbing the caller's.
     *
     * @param array<string, Value> $from
     * @param list<Node>           $stmts
     *
     * @return array<string, Value>
     */
    private function arm(array $from, array $stmts): array
    {
        $saved = $this->scope;
        $this->scope = $from;
        $this->statements($stmts);
        $after = $this->scope;
        $this->scope = $saved;

        return $after;
    }

    /**
     * @param array<string, Value> $a
     * @param array<string, Value> $b
     *
     * @return array<string, Value>
     */
    private static function mergeScopes(array $a, array $b): array
    {
        $out = $a;
        foreach ($b as $name => $value) {
            $out[$name] = isset($out[$name]) ? $out[$name]->merge($value) : $value;
        }

        return $out;
    }

    // ---- expressions ----------------------------------------------------

    /** Evaluate an expression, reporting anything it sinks along the way. */
    private function expr(?Node $node): ?Value
    {
        if (!$node instanceof Expr) {
            return null;
        }

        return match (true) {
            $node instanceof Expr\Assign, $node instanceof Expr\AssignRef => $this->assign($node),
            $node instanceof Expr\AssignOp\Concat => $this->assignConcat($node),
            $node instanceof Expr\Variable => $this->variable($node),
            $node instanceof Expr\ArrayDimFetch => $this->dim($node),
            $node instanceof Expr\PropertyFetch => $this->property($node),
            $node instanceof Expr\BinaryOp\Concat => $this->binary($node),
            $node instanceof Scalar\InterpolatedString => $this->interpolated($node),
            $node instanceof Expr\FuncCall => $this->call($node),
            $node instanceof Expr\MethodCall, $node instanceof Expr\NullsafeMethodCall => $this->method($node),
            $node instanceof Expr\StaticCall => $this->staticCall($node),
            $node instanceof Expr\Eval_ => $this->construct($node, $node->expr, 'code', 'eval'),
            $node instanceof Expr\Include_ => $this->construct($node, $node->expr, 'inclusion', self::includeName($node)),
            $node instanceof Expr\ShellExec => $this->shellExec($node),
            $node instanceof Expr\Print_ => $this->construct($node, $node->expr, 'html', 'print'),
            $node instanceof Expr\Cast\Int_, $node instanceof Expr\Cast\Double_, $node instanceof Expr\Cast\Bool_ => $this->cast($node),
            $node instanceof Expr\Ternary => $this->ternary($node),
            $node instanceof Expr\New_ => $this->new($node),
            default => $this->children($node),
        };
    }

    /** Anything without special handling: walk into it, join what comes back. */
    private function children(Expr $node): ?Value
    {
        $value = null;
        foreach ($node->getSubNodeNames() as $name) {
            $sub = $node->{$name};
            foreach (is_array($sub) ? $sub : [$sub] as $child) {
                if ($child instanceof Node\Arg) {
                    $child = $child->value;
                }
                if (!$child instanceof Expr) {
                    continue;
                }
                $found = $this->expr($child);
                $value = self::join($value, $found);
            }
        }

        return $value;
    }

    private static function join(?Value $a, ?Value $b): ?Value
    {
        if ($a === null) {
            return $b;
        }

        return $b === null ? $a : $a->merge($b);
    }

    private function assign(Expr\Assign|Expr\AssignRef $node): ?Value
    {
        $value = $this->expr($node->expr);
        $target = $node->var;

        // `$$name = $_GET['v']` writes to a variable chosen by data.
        if ($target instanceof Expr\Variable && !is_string($target->name)) {
            $chosen = $this->expr($target->name);
            if ($chosen !== null) {
                $this->report('scope', $chosen, 'a variable variable', $node);
            }
        }

        $this->store($target, $value);

        return $value;
    }

    private function assignConcat(Expr\AssignOp\Concat $node): ?Value
    {
        $value = self::join($this->expr($node->var), $this->expr($node->expr));
        $this->store($node->var, $value);

        return $value;
    }

    private function store(Expr $target, ?Value $value): void
    {
        if ($target instanceof Expr\Variable && is_string($target->name)) {
            $key = strtolower($target->name);
            if ($value === null) {
                unset($this->scope[$key]);
            } else {
                $this->scope[$key] = $value;
            }

            return;
        }
        // `$row['name'] = $_GET['n']` taints the array as a whole: tracking
        // keys would be precision nobody can rely on.
        if ($target instanceof Expr\ArrayDimFetch) {
            $this->store($target->var, $value);

            return;
        }
        if ($target instanceof Expr\PropertyFetch && $target->name instanceof Node\Identifier && $value !== null) {
            $this->properties[strtolower($target->name->toString())] = $value;
        }
    }

    private function variable(Expr\Variable $node): ?Value
    {
        if (!is_string($node->name)) {
            $this->expr($node->name);

            return null;
        }
        if (isset(Vocabulary::SUPERGLOBALS[$node->name])) {
            return new Value('$' . $node->name);
        }

        return $this->scope[strtolower($node->name)] ?? null;
    }

    private function dim(Expr\ArrayDimFetch $node): ?Value
    {
        $this->expr($node->dim);
        $base = $node->var;
        if ($base instanceof Expr\Variable && is_string($base->name) && isset(Vocabulary::SUPERGLOBALS[$base->name])) {
            return new Value(sprintf('$%s[%s]', $base->name, $this->keyText($node->dim)));
        }

        return $this->expr($base);
    }

    private function keyText(?Node $dim): string
    {
        return $dim instanceof Scalar\String_ ? sprintf("'%s'", $dim->value) : '...';
    }

    private function property(Expr\PropertyFetch $node): ?Value
    {
        $this->expr($node->var);
        if (!$node->name instanceof Node\Identifier) {
            return null;
        }

        return $this->properties[strtolower($node->name->toString())] ?? null;
    }

    private function binary(Expr\BinaryOp\Concat $node): ?Value
    {
        return self::join($this->expr($node->left), $this->expr($node->right));
    }

    private function interpolated(Scalar\InterpolatedString $node): ?Value
    {
        $value = null;
        foreach ($node->parts as $part) {
            if ($part instanceof Expr) {
                $value = self::join($value, $this->expr($part));
            }
        }

        return $value;
    }

    private function cast(Expr\Cast $node): ?Value
    {
        $value = $this->expr($node->expr);

        return $value?->sanitizedBy(['*']);
    }

    private function ternary(Expr\Ternary $node): ?Value
    {
        $this->expr($node->cond);

        return self::join($this->expr($node->if), $this->expr($node->else));
    }

    private function new(Expr\New_ $node): ?Value
    {
        if (!$node->class instanceof Node\Name) {
            $chosen = $node->class instanceof Expr ? $this->expr($node->class) : null;
            if ($chosen !== null) {
                $this->report('code', $chosen, 'new $class', $node);
            }
        }

        return $this->children($node);
    }

    private function shellExec(Expr\ShellExec $node): ?Value
    {
        $value = null;
        foreach ($node->parts as $part) {
            if ($part instanceof Expr) {
                $value = self::join($value, $this->expr($part));
            }
        }
        $this->sink($value, 'command', 'the backtick operator', $node);

        return null;
    }

    private function construct(Expr $node, Expr $inner, string $class, string $name): ?Value
    {
        $value = $this->expr($inner);
        $this->sink($value, $class, $name, $node);
        if ($class === 'code' || $class === 'command') {
            $this->obfuscation($inner, $name, $node);
        }

        return null;
    }

    private static function includeName(Expr\Include_ $node): string
    {
        return match ($node->type) {
            Expr\Include_::TYPE_REQUIRE => 'require',
            Expr\Include_::TYPE_REQUIRE_ONCE => 'require_once',
            Expr\Include_::TYPE_INCLUDE_ONCE => 'include_once',
            default => 'include',
        };
    }

    // ---- calls ----------------------------------------------------------

    private function call(Expr\FuncCall $node): ?Value
    {
        // `$handler($x)` where the handler itself is untrusted.
        if (!$node->name instanceof Node\Name) {
            $chosen = $this->expr($node->name);
            if ($chosen !== null) {
                $this->report('code', $chosen, 'a variable function', $node);
            }

            return $this->children($node);
        }

        $name = $this->names->globalFunction($node);
        if ($name === null) {
            return $this->children($node);
        }

        $args = $this->arguments($node);

        // Escaping, real and imagined.
        if (isset(Vocabulary::SANITIZERS[$name])) {
            $value = self::joinAll($args);

            return $value?->sanitizedBy(Vocabulary::SANITIZERS[$name]);
        }
        if (isset(Vocabulary::FALSE_FRIENDS[$name])) {
            $value = self::joinAll($args);

            return $value?->warnedBy(Vocabulary::FALSE_FRIENDS[$name]);
        }
        if (isset(Vocabulary::DECODERS[$name])) {
            return self::joinAll($args);
        }
        if ($name === 'filter_var' || $name === 'filter_input') {
            return $this->filter($node, $name, $args);
        }

        // `php://input` is the raw request body: a source, not a file read.
        if (($name === 'file_get_contents' || $name === 'fopen') && $this->readsRequestBody($node)) {
            return new Value("file_get_contents('php://input')");
        }

        // A call that leaks the environment is reported as that, once. Also
        // reporting its path argument as traversal says the same line twice
        // and buries the finding that matters.
        if ($this->exfiltration($name, $node, $args)) {
            $this->helper($name, $node, $args);

            return null;
        }

        if (isset(Vocabulary::SINKS[$name])) {
            [$class, $indexes] = Vocabulary::SINKS[$name];
            foreach ($indexes === [] ? array_keys($args) : $indexes as $index) {
                if (!isset($args[$index])) {
                    continue;
                }
                $argNode = $node->args[$index]->value ?? $node;
                if ($class === 'sql') {
                    $this->sqlSink($args[$index], $name, $argNode, $node);
                } else {
                    // A path built onto a literal http:// is a request the
                    // server makes, not a file it opens.
                    $actual = $class === 'path' && self::isRemote($argNode) ? 'ssrf' : $class;
                    $this->sink($args[$index], $actual, $name, $node);
                }
            }
            if ($class === 'code' || $class === 'command') {
                $this->obfuscation($node, $name, $node);
            }
        }

        $this->helper($name, $node, $args);

        if (isset(Vocabulary::SOURCE_CALLS[$name])) {
            return new Value($name . '()');
        }
        if (isset(Vocabulary::SECRET_CALLS[$name])) {
            return new Value($name . '()');
        }

        // An unknown call ends the chain rather than guessing.
        return null;
    }

    /**
     * `filter_var($x, FILTER_VALIDATE_INT)` really does validate.
     * `filter_var($x)` with no filter is the default, which does nothing.
     *
     * @param array<int, Value|null> $args
     */
    private function filter(Expr\FuncCall $node, string $name, array $args): ?Value
    {
        $index = $name === 'filter_input' ? 2 : 1;
        $filter = $node->args[$index]->value ?? null;
        $text = $filter !== null ? $this->snippet->text($filter) : '';
        $validates = str_contains($text, 'FILTER_VALIDATE') || str_contains($text, 'FILTER_SANITIZE');

        if ($name === 'filter_input') {
            $source = new Value('filter_input()');

            return $validates ? $source->sanitizedBy(['*']) : $source;
        }
        $value = self::joinAll($args);

        return $validates ? $value?->sanitizedBy(['*']) : $value;
    }

    /** @return array<int, Value|null> */
    private function arguments(Expr\FuncCall|Expr\MethodCall|Expr\NullsafeMethodCall|Expr\StaticCall $node): array
    {
        $out = [];
        foreach ($node->args as $index => $arg) {
            $out[$index] = $arg instanceof Node\Arg ? $this->expr($arg->value) : null;
        }

        return $out;
    }

    /** @param array<int, Value|null> $values */
    private static function joinAll(array $values): ?Value
    {
        $out = null;
        foreach ($values as $value) {
            $out = self::join($out, $value);
        }

        return $out;
    }

    private function method(Expr\MethodCall|Expr\NullsafeMethodCall $node): ?Value
    {
        if (!$node->name instanceof Node\Identifier) {
            $chosen = $node->name instanceof Expr ? $this->expr($node->name) : null;
            if ($chosen !== null) {
                $this->report('code', $chosen, 'a variable method name', $node);
            }

            return $this->children($node);
        }

        $method = strtolower($node->name->toString());
        $args = $this->arguments($node);

        // A query on something known to hold a connection.
        if (in_array($method, Handles::QUERY_METHODS, true) && Handles::isHandle($node->var, $this->handles)) {
            // $wpdb->prepare() is the safe form and never a finding.
            if ($method !== 'prepare' || !$this->isWpdb($node->var)) {
                foreach ($args as $index => $value) {
                    if ($value !== null && $index === 0) {
                        $this->sqlSink($value, $this->receiverName($node) . '->' . $method, $node->args[0]->value ?? $node, $node);
                    }
                }
            }

            return null;
        }
        if ($method === 'real_escape_string' || $method === 'quote' || $method === 'escape_string') {
            return self::joinAll($args)?->sanitizedBy(['sql']);
        }
        if ($method === 'prepare' && $this->isWpdb($node->var)) {
            return self::joinAll($args)?->sanitizedBy(['sql']);
        }

        // Request objects, Laravel and Symfony alike.
        if ($this->isRequest($node->var) && isset(Vocabulary::REQUEST_METHODS[$method])) {
            return new Value($this->receiverName($node) . '->' . $method . '()');
        }

        $this->expr($node->var);

        return null;
    }

    private function staticCall(Expr\StaticCall $node): ?Value
    {
        if (!$node->class instanceof Node\Name || !$node->name instanceof Node\Identifier) {
            return $this->children($node);
        }
        $class = strtolower(Names::shortName(ltrim($node->class->toString(), '\\')));
        $method = strtolower($node->name->toString());
        $args = $this->arguments($node);

        if ($class === 'db' && in_array($method, ['select', 'insert', 'update', 'delete', 'statement', 'raw', 'unprepared'], true)) {
            if (isset($args[0]) && $args[0] !== null) {
                $this->sqlSink($args[0], 'DB::' . $method, $node->args[0]->value ?? $node, $node);
            }

            return null;
        }
        if ($class === 'input' && in_array($method, ['get', 'all', 'only', 'post'], true)) {
            return new Value('Input::' . $method . '()');
        }

        return self::joinAll($args);
    }

    private function isWpdb(Expr $receiver): bool
    {
        return $receiver instanceof Expr\Variable
            && is_string($receiver->name)
            && strtolower($receiver->name) === 'wpdb';
    }

    private function isRequest(Expr $receiver): bool
    {
        if ($receiver instanceof Expr\Variable && is_string($receiver->name)) {
            return isset(Vocabulary::REQUEST_RECEIVERS[strtolower($receiver->name)]);
        }
        if ($receiver instanceof Expr\PropertyFetch && $receiver->name instanceof Node\Identifier) {
            return isset(Vocabulary::REQUEST_RECEIVERS[strtolower($receiver->name->toString())]);
        }
        // Symfony: $request->query->get(), $request->headers->get()
        if ($receiver instanceof Expr\MethodCall || $receiver instanceof Expr\FuncCall) {
            $text = strtolower($this->snippet->text($receiver));

            return str_starts_with($text, 'request(');
        }

        return false;
    }

    private function receiverName(Expr\MethodCall|Expr\NullsafeMethodCall $node): string
    {
        $text = $this->snippet->text($node->var, 40);

        return $text === '' ? '$object' : $text;
    }

    // ---- reporting ------------------------------------------------------

    private function sink(?Value $value, string $class, string $name, Node $node): void
    {
        if ($value === null || $value->isSafeFor('*') || $value->isSafeFor($class)) {
            return;
        }
        $this->report($class, $value, $name, $node);
    }

    /**
     * A SQL sink, judged where the value actually lands.
     *
     * @param Node $queryNode the expression that builds the statement
     */
    private function sqlSink(Value $value, string $name, Node $queryNode, Node $at): void
    {
        if ($value->isSafeFor('*')) {
            return;
        }

        $contexts = [];
        foreach (Sql::holes($queryNode) as [, $context]) {
            $contexts[] = $context;
        }
        // The riskiest landing place decides: one bare hole is enough.
        $context = Sql::CONTEXT_UNKNOWN;
        foreach ([Sql::CONTEXT_IDENTIFIER, Sql::CONTEXT_BARE, Sql::CONTEXT_QUOTED] as $candidate) {
            if (in_array($candidate, $contexts, true)) {
                $context = $candidate;
                break;
            }
        }

        if ($value->isSafeFor('sql')) {
            // Escaped and quoted is the one combination that is actually safe.
            if ($context === Sql::CONTEXT_QUOTED || $context === Sql::CONTEXT_UNKNOWN) {
                return;
            }
            $this->report('sql', $value, $name, $at, Sql::explain($context) . ', so escaping it did not help');

            return;
        }

        $this->report('sql', $value, $name, $at, Sql::explain($context));
    }

    private function report(string $class, Value $value, string $sink, Node $node, string $detail = ''): void
    {
        $notes = array_filter([$detail, ...$value->warnings]);
        $this->flows[] = new Flow(
            Vocabulary::KIND_LABEL[$class] ?? $class,
            $value->origin,
            $sink,
            $this->file,
            $node->getStartLine(),
            $this->snippet->column($node),
            $this->snippet->text($node),
            implode('; ', $notes),
            null,
            $this->depth === 0 && !$this->probing,
        );
    }

    /**
     * A decoder wrapped around a code or command sink.
     *
     * `eval(base64_decode($x))` is not a coding style. It is the shape every
     * PHP web shell has had for twenty years, and it is worth saying so whether
     * or not the analysis can prove where the string came from.
     */
    private function obfuscation(Node $inner, string $sink, Node $at): void
    {
        $found = null;
        $walk = function (Node $node) use (&$walk, &$found): void {
            if ($found !== null) {
                return;
            }
            if ($node instanceof Expr\FuncCall && $node->name instanceof Node\Name) {
                $name = strtolower(ltrim($node->name->toString(), '\\'));
                if (isset(Vocabulary::DECODERS[$name])) {
                    $found = $name;

                    return;
                }
            }
            foreach ($node->getSubNodeNames() as $key) {
                $sub = $node->{$key};
                foreach (is_array($sub) ? $sub : [$sub] as $child) {
                    if ($child instanceof Node) {
                        $walk($child);
                    }
                }
            }
        };
        $walk($inner);

        if ($found === null) {
            return;
        }
        $this->flows[] = new Flow(
            Vocabulary::KIND_LABEL['obfuscation'],
            $found . '()',
            $sink,
            $this->file,
            $at->getStartLine(),
            $this->snippet->column($at),
            $this->snippet->text($at),
            'a decoded string is executed - this is the shape of a web shell',
            null,
            $this->depth === 0 && !$this->probing,
        );
    }

    /**
     * Secrets leaving the machine.
     *
     * The precision rule is what keeps this usable: sending one named value to
     * a service is how every API client on earth authenticates, and is never
     * reported. Sending the whole environment is not.
     *
     * @param array<int, Value|null> $args
     */
    private function exfiltration(string $name, Expr\FuncCall $node, array $args): bool
    {
        if (!isset(Vocabulary::EGRESS[$name])) {
            return false;
        }
        foreach ($node->args as $arg) {
            if (!$arg instanceof Node\Arg) {
                continue;
            }
            $bulk = $this->bulkSecret($arg->value);
            if ($bulk !== null) {
                $this->flows[] = new Flow(
                    Vocabulary::KIND_LABEL['exfiltration'],
                    $bulk,
                    $name,
                    $this->file,
                    $node->getStartLine(),
                    $this->snippet->column($node),
                    $this->snippet->text($node),
                    'the whole set, not one named value',
                    null,
                    $this->depth === 0 && !$this->probing,
                );

                return true;
            }
        }

        return false;
    }

    /** Does this expression start with a literal remote URL? */
    private static function isRemote(Node $node): bool
    {
        while ($node instanceof Expr\BinaryOp\Concat) {
            $node = $node->left;
        }
        if ($node instanceof Scalar\InterpolatedString) {
            $first = $node->parts[0] ?? null;
            $text = $first instanceof Node\InterpolatedStringPart ? $first->value : '';
        } elseif ($node instanceof Scalar\String_) {
            $text = $node->value;
        } else {
            return false;
        }

        return (bool) preg_match('#^(https?|ftps?|ssh2)://#i', $text);
    }

    /** `file_get_contents('php://input')` - the raw request body. */
    private function readsRequestBody(Expr\FuncCall $node): bool
    {
        $arg = $node->args[0] ?? null;

        return $arg instanceof Node\Arg
            && $arg->value instanceof Scalar\String_
            && stripos($arg->value->value, 'php://input') === 0;
    }

    /** The name of a bulk secret read inside this expression, if there is one. */
    private function bulkSecret(Node $node): ?string
    {
        if ($node instanceof Expr\Variable && is_string($node->name) && isset(Vocabulary::BULK_SECRETS[$node->name])) {
            return '$' . $node->name;
        }
        if ($node instanceof Expr\ArrayDimFetch) {
            // One named key is the safe, ordinary case. Stop here.
            return null;
        }
        if ($node instanceof Expr\FuncCall && $node->name instanceof Node\Name) {
            $name = strtolower(ltrim($node->name->toString(), '\\'));
            if ($name === 'getenv' && $node->args === []) {
                return 'getenv()';
            }
            if (isset(Vocabulary::SECRET_CALLS[$name])) {
                return $name . '()';
            }
        }
        foreach ($node->getSubNodeNames() as $key) {
            $sub = $node->{$key};
            foreach (is_array($sub) ? $sub : [$sub] as $child) {
                if ($child instanceof Node\Arg) {
                    $child = $child->value;
                }
                if ($child instanceof Node) {
                    $found = $this->bulkSecret($child);
                    if ($found !== null) {
                        return $found;
                    }
                }
            }
        }

        return null;
    }

    /**
     * A tainted argument handed to a project function that sinks it.
     *
     * @param array<int, Value|null> $args
     */
    private function helper(string $name, Expr\FuncCall $node, array $args): void
    {
        foreach ($this->helpers->sinksOf($name) as $index => [$class, $sink]) {
            $value = $args[$index] ?? null;
            if ($value === null || $value->isSafeFor('*') || $value->isSafeFor($class)) {
                continue;
            }
            $this->flows[] = new Flow(
                Vocabulary::KIND_LABEL[$class] ?? $class,
                $value->origin,
                $sink,
                $this->file,
                $node->getStartLine(),
                $this->snippet->column($node),
                $this->snippet->text($node),
                implode('; ', $value->warnings),
                $name,
                $this->depth === 0 && !$this->probing,
            );
        }
    }
}
