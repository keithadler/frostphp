<?php

declare(strict_types=1);

namespace Frost\Extract;

use Frost\Source;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Scalar;
use PhpParser\NodeFinder;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;

/**
 * The AST to `Usage` records: what can this file do?
 *
 * This answers a question of fact, not a question of danger. `exec("ls")` is
 * a capability; `exec($_GET['c'])` is a bug, and the bug is Taint's question.
 * Keeping them apart is what lets a policy be written once and stay quiet.
 */
final class Extractor extends NodeVisitorAbstract
{
    /** @var list<Usage> */
    private array $uses = [];

    private Names $names;

    private Snippet $snippet;

    /** Depth of enclosing function, closure, arrow function or method bodies. */
    private int $depth = 0;

    /** @var array{vars: array<string,true>, props: array<string,true>} */
    private array $handles = ['vars' => [], 'props' => []];

    /** Ancestors of the node being inspected, nearest last. @var list<Node> */
    private array $stack = [];

    /** @param list<array{int, int}> $shifts */
    private function __construct(private readonly string $file, string $code, array $shifts = [])
    {
        $this->names = new Names();
        $this->snippet = new Snippet($code, $shifts);
    }

    /**
     * @return array{list<Usage>, string} the uses, and the PHP version that parsed the file
     *
     * @throws \PhpParser\Error
     */
    public static function run(string $file, string $raw, ?string $pin = null): array
    {
        [$code, $shifts] = Source::prepare($raw, $file);
        [$stmts, $version] = Source::parse($code, $pin);

        if (Source::isVacuous($stmts, $code)) {
            throw new \PhpParser\Error('holds PHP but no PHP could be read from it - check the open tags');
        }

        $extractor = new self($file, $code, $shifts);
        $extractor->bladeRawOutput($raw);
        $extractor->handles = Handles::find($stmts);
        $extractor->predeclare($stmts);

        $traverser = new NodeTraverser();
        $traverser->addVisitor($extractor);
        $traverser->traverse($stmts);

        return [$extractor->uses, $version];
    }

    /** Blade's unescaped print, which conversion turns into an ordinary echo. */
    private function bladeRawOutput(string $raw): void
    {
        if (!\Frost\Blade::isBlade($this->file)) {
            return;
        }
        foreach (\Frost\Blade::rawOutputs($raw) as [$line, $column]) {
            $this->uses[] = new Usage('response.raw', $this->file, $line, $column, '{!! ... !!}', true);
        }
    }

    /**
     * A function declared anywhere in the file shadows the global one
     * everywhere in it, including above its own declaration - PHP hoists
     * top-level declarations - so the shadow list is built before the walk.
     *
     * @param list<Node> $stmts
     */
    private function predeclare(array $stmts): void
    {
        foreach ((new NodeFinder())->findInstanceOf($stmts, Node\Stmt\Function_::class) as $fn) {
            /** @var Node\Stmt\Function_ $fn */
            $this->names->declareFunction($fn->name->toString());
        }
    }

    public function enterNode(Node $node): null
    {
        if ($node instanceof Node\Stmt\Namespace_) {
            $this->names->enterNamespace($node->name);
        } elseif ($node instanceof Node\Stmt\Use_) {
            foreach ($node->uses as $use) {
                $this->names->addUse($use, $node->type);
            }
        } elseif ($node instanceof Node\Stmt\GroupUse) {
            foreach ($node->uses as $use) {
                $this->names->addUse($use, $node->type === Node\Stmt\Use_::TYPE_UNKNOWN ? $use->type : $node->type);
            }
        } elseif ($this->isBody($node)) {
            $this->depth++;
        } else {
            $this->inspect($node);
        }

        $this->stack[] = $node;

        return null;
    }

    public function leaveNode(Node $node): null
    {
        array_pop($this->stack);
        if ($this->isBody($node)) {
            $this->depth--;
        }

        return null;
    }

    /** The node $levels above the one being inspected. */
    private function ancestor(int $levels = 1): ?Node
    {
        return $this->stack[count($this->stack) - $levels] ?? null;
    }

    private function isBody(Node $node): bool
    {
        return $node instanceof Node\Stmt\Function_
            || $node instanceof Node\Stmt\ClassMethod
            || $node instanceof Expr\Closure
            || $node instanceof Expr\ArrowFunction;
    }

    private function add(string $capability, Node $node): void
    {
        $this->uses[] = new Usage(
            $capability,
            $this->file,
            $node->getStartLine(),
            $this->snippet->column($node),
            $this->snippet->text($node),
            $this->depth === 0,
        );
    }

    private function inspect(Node $node): void
    {
        // ---- language constructs, which are not function calls ----------
        if ($node instanceof Expr\Eval_) {
            $this->add('codegen.eval', $node);

            return;
        }
        if ($node instanceof Expr\ShellExec) {
            $this->add('process.backtick', $node);

            return;
        }
        if ($node instanceof Expr\Include_) {
            // `include 'config.php'` is modularity. `include $page` is a
            // choice of code made at runtime, which is the capability.
            if (!$this->isLiteral($node->expr)) {
                $this->add('include.dynamic', $node);
            }
            $scheme = self::leadingLiteral($node->expr);
            if ($scheme !== null) {
                $this->schemeOf($scheme, $node);
            }

            return;
        }
        // `$$name` and `${$expr}`: the variable written to is chosen by data.
        if ($node instanceof Expr\Variable && !is_string($node->name)) {
            $this->add('scope.variable', $node);

            return;
        }
        if ($node instanceof Expr\New_) {
            $this->newExpression($node);

            return;
        }
        if ($node instanceof Expr\StaticCall) {
            $this->staticCall($node);

            return;
        }
        if ($node instanceof Expr\MethodCall) {
            $this->methodCall($node);

            return;
        }
        if ($node instanceof Scalar\String_) {
            if (!$this->isDataAboutSchemes()) {
                $this->schemeOf($node->value, $node);
            }

            return;
        }
        if ($node instanceof Expr\FuncCall) {
            $this->funcCall($node);
        }
    }

    /**
     * Is this literal describing a wrapper rather than opening one?
     *
     * `fopen('php://temp', 'w')` uses one. `strpos($p, 'phar://') === 0` and
     * `$schemes = ['php://', 'data://']` are a check and a table - the string
     * is the subject, not the path. Without this distinction every security
     * tool's own vocabulary reports itself, which is how it was noticed.
     */
    private function isDataAboutSchemes(): bool
    {
        $parent = $this->ancestor();

        // A comparison, or a list of names.
        if ($parent instanceof Expr\BinaryOp && !$parent instanceof Expr\BinaryOp\Concat) {
            return true;
        }
        if ($parent instanceof Node\ArrayItem || $parent instanceof Node\MatchArm) {
            return true;
        }
        // An argument to something that inspects strings rather than opening them.
        if ($parent instanceof Node\Arg) {
            $call = $this->ancestor(2);
            if ($call instanceof Expr\FuncCall && $call->name instanceof Node\Name) {
                return isset(Functions::INSPECTORS[strtolower(ltrim($call->name->toString(), '\\'))]);
            }
        }

        return false;
    }

    private function funcCall(Expr\FuncCall $node): void
    {
        // A variable function - $handler($x) - dispatches on data.
        if (!$node->name instanceof Node\Name) {
            $this->add('codegen.dynamic', $node);

            return;
        }

        $name = $this->names->globalFunction($node);
        if ($name === null) {
            return;
        }

        if (isset(Functions::SIMPLE[$name])) {
            $this->add(Functions::SIMPLE[$name], $node);
            if (isset(Functions::PATH_ARGS[$name]) || $name === 'curl_init') {
                $this->remoteArg($name, $node);
            }

            return;
        }

        match ($name) {
            'fopen' => $this->fopen($node),
            'file_get_contents' => $this->fileGetContents($node),
            'assert' => $this->assert($node),
            'preg_replace' => $this->pregReplace($node),
            'parse_str' => $this->parseStr($node),
            'libxml_disable_entity_loader' => $this->entityLoader($node),
            'simplexml_load_file', 'simplexml_load_string' => $this->simplexml($node),
            default => null,
        };
    }

    private function fopen(Expr\FuncCall $node): void
    {
        $mode = $this->stringArg($node, 1) ?? 'r';
        $writes = (bool) preg_match('/[waxc+]/i', $mode);
        $this->add($writes ? 'filesystem.write' : 'filesystem.read', $node);
        $this->remoteArg('fopen', $node);
    }

    private function fileGetContents(Expr\FuncCall $node): void
    {
        // The scheme decides what this really is. With no literal to read,
        // it is a file read, and Taint decides whether the path is a bug.
        $arg = $node->args[0] ?? null;
        $leading = $arg instanceof Node\Arg ? self::leadingLiteral($arg->value) : null;
        $scheme = $leading === null ? null : Functions::scheme($leading);
        if ($scheme === 'network.url') {
            $this->add('network.url', $node);

            return;
        }
        // A wrapper path is reported on the literal itself; anything else is
        // an ordinary read.
        if ($scheme === null) {
            $this->add('filesystem.read', $node);
        }
    }

    /**
     * `assert("$a > $b")` evaluated its argument as code until PHP 8. Only a
     * string can do that, so a boolean expression - the modern, safe use, and
     * the overwhelming majority - never fires.
     */
    private function assert(Expr\FuncCall $node): void
    {
        $first = $node->args[0] ?? null;
        if (!$first instanceof Node\Arg) {
            return;
        }
        $isString = $first->value instanceof Scalar\String_
            || $first->value instanceof Scalar\InterpolatedString
            || $first->value instanceof Expr\BinaryOp\Concat;
        if ($isString) {
            $this->add('codegen.assert', $node);
        }
    }

    /** `preg_replace('/x/e', ...)` ran the replacement as code. Removed in PHP 7, still in old files. */
    private function pregReplace(Expr\FuncCall $node): void
    {
        $pattern = $this->stringArg($node, 0);
        if ($pattern === null || strlen($pattern) < 2) {
            return;
        }
        $delimiter = $pattern[0];
        $closing = match ($delimiter) { '(' => ')', '[' => ']', '{' => '}', '<' => '>', default => $delimiter };
        $end = strrpos($pattern, $closing);
        if ($end === false || $end === 0) {
            return;
        }
        if (str_contains(substr($pattern, $end + 1), 'e')) {
            $this->add('codegen.preg', $node);
        }
    }

    /** `parse_str($s)` with no result array writes straight into the local scope. */
    private function parseStr(Expr\FuncCall $node): void
    {
        if (count($node->args) < 2) {
            $this->add('scope.parse_str', $node);
        }
    }

    private function entityLoader(Expr\FuncCall $node): void
    {
        $arg = $node->args[0] ?? null;
        $isFalse = $arg instanceof Node\Arg
            && $arg->value instanceof Expr\ConstFetch
            && strtolower($arg->value->name->toString()) === 'false';
        if ($isFalse) {
            $this->add('deserialize.xml', $node);
        }
    }

    /** XML with entity substitution turned on is a document that can read files. */
    private function simplexml(Expr\FuncCall $node): void
    {
        foreach ($node->args as $arg) {
            if (!$arg instanceof Node\Arg) {
                continue;
            }
            $text = $this->snippet->text($arg->value);
            if (str_contains($text, 'LIBXML_NOENT')) {
                $this->add('deserialize.xml', $node);

                return;
            }
        }
    }

    private function newExpression(Expr\New_ $node): void
    {
        if (!$node->class instanceof Node\Name) {
            // `new $class` picks the class from data.
            $this->add('codegen.dynamic', $node);

            return;
        }
        $short = strtolower(Names::shortName(ltrim($node->class->toString(), '\\')));
        match ($short) {
            'phar', 'phardata' => $this->add('deserialize.phar', $node),
            'ffi' => $this->add('native.ffi', $node),
            'splfileobject' => $this->add('filesystem.read', $node),
            'pdo', 'mysqli', 'sqlite3' => $this->add('database.connect', $node),
            default => null,
        };
    }

    private function staticCall(Expr\StaticCall $node): void
    {
        if (!$node->class instanceof Node\Name || !$node->name instanceof Node\Identifier) {
            return;
        }
        $class = strtolower(Names::shortName(ltrim($node->class->toString(), '\\')));
        $method = strtolower($node->name->toString());

        if ($class === 'ffi' && in_array($method, ['cdef', 'load', 'scope'], true)) {
            $this->add('native.ffi', $node);

            return;
        }
        if ($class === 'phar' && in_array($method, ['loadphar', 'mapphar', 'mount'], true)) {
            $this->add('deserialize.phar', $node);

            return;
        }
        // The Laravel query facade: DB::select/statement/raw all run SQL.
        if ($class === 'db' && in_array($method, ['select', 'insert', 'update', 'delete', 'statement', 'raw', 'unprepared'], true)) {
            $this->add('database.query', $node);
        }
    }

    private function methodCall(Expr\MethodCall $node): void
    {
        if (!$node->name instanceof Node\Identifier) {
            // `$obj->$method()` picks the method from data.
            $this->add('codegen.dynamic', $node);

            return;
        }
        $method = strtolower($node->name->toString());
        if (isset(\Frost\Taint\Vocabulary::RAW_SQL_METHODS[$method])) {
            $this->add('database.query', $node);

            return;
        }
        if (in_array($method, Handles::QUERY_METHODS, true) && Handles::isHandle($node->var, $this->handles)) {
            $this->add('database.query', $node);
        }
    }

    /**
     * A wrapper scheme in a literal is a use of that wrapper.
     *
     * `network.url` is deliberately not reported here. An `https://` string is
     * the commonest kind of text in a codebase - it is in every doc block,
     * deprecation notice and error message - and none of those reach the
     * network. A URL becomes a network capability only where it is handed to
     * something that fetches it, which `remoteArg` decides.
     */
    private function schemeOf(string $value, Node $node): ?string
    {
        $capability = Functions::scheme($value);
        if ($capability !== null && $capability !== 'network.url') {
            $this->add($capability, $node);
        }

        return $capability;
    }

    /** A literal remote URL in the path argument of something that fetches it. */
    private function remoteArg(string $name, Expr\FuncCall $node): bool
    {
        $found = false;
        foreach (Functions::PATH_ARGS[$name] ?? [0] as $index) {
            $arg = $node->args[$index] ?? null;
            if (!$arg instanceof Node\Arg) {
                continue;
            }
            $leading = self::leadingLiteral($arg->value);
            if ($leading !== null && Functions::scheme($leading) === 'network.url') {
                $this->add('network.url', $node);
                $found = true;
            }
        }

        return $found;
    }

    /**
     * The literal text an expression begins with.
     *
     * A URL is very rarely a whole string literal - it is
     * `"https://api.example.com/v1/" . $path` - and the scheme, which is the
     * part that decides whether this is a file or a request, is always in the
     * literal at the front.
     */
    private static function leadingLiteral(Node $node): ?string
    {
        while ($node instanceof Expr\BinaryOp\Concat) {
            $node = $node->left;
        }
        if ($node instanceof Scalar\String_) {
            return $node->value;
        }
        if ($node instanceof Scalar\InterpolatedString) {
            $first = $node->parts[0] ?? null;

            return $first instanceof Node\InterpolatedStringPart ? $first->value : null;
        }

        return null;
    }

    private function stringArg(Expr\FuncCall $node, int $index): ?string
    {
        $arg = $node->args[$index] ?? null;

        return $arg instanceof Node\Arg && $arg->value instanceof Scalar\String_
            ? $arg->value->value
            : null;
    }

    /**
     * Is this path fixed at the time the file was written?
     *
     * `dirname(__FILE__) . '/../lib/db.inc'` is the idiom every PHP codebase
     * older than 5.3 uses for its own includes - `__DIR__` did not exist yet -
     * and there is no data in it anywhere. Calling that a runtime choice of
     * code would put an `include.dynamic` line on half the files in a legacy
     * tree and teach everyone to ignore the capability, which is the one that
     * actually matters when it is real.
     */
    private function isLiteral(Node $node): bool
    {
        if ($node instanceof Scalar\String_ || $node instanceof Scalar\MagicConst) {
            return true;
        }
        // 'dir/' . 'file.php' is still a literal; 'dir/' . $x is not.
        if ($node instanceof Expr\BinaryOp\Concat) {
            return $this->isLiteral($node->left) && $this->isLiteral($node->right);
        }
        if ($node instanceof Expr\ConstFetch) {
            return true;
        }
        // dirname(__FILE__), dirname(__DIR__, 2), realpath(__DIR__ . '/..')
        if ($node instanceof Expr\FuncCall && $node->name instanceof Node\Name) {
            $name = strtolower(ltrim($node->name->toString(), '\\'));
            if (in_array($name, ['dirname', 'realpath', 'basename'], true)) {
                $first = $node->args[0] ?? null;

                return $first instanceof Node\Arg && $this->isLiteral($first->value);
            }
        }

        return false;
    }
}
