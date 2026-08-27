<?php

declare(strict_types=1);

namespace Frost\Taint;

use Frost\Extract\Names;
use Frost\Extract\Snippet;
use Frost\Source;
use PhpParser\Node;
use PhpParser\Node\Stmt;
use PhpParser\NodeFinder;

/**
 * What a project's own functions do with their arguments.
 *
 * Real code extracts the dangerous line into a helper, and the danger does not
 * stop being danger because it moved one function away:
 *
 *     function run_command($cmd) { return shell_exec($cmd); }
 *     run_command($_GET['c']);
 *
 * What a helper does is discovered by running the ordinary analysis over its
 * body with one parameter marked tainted and nothing else - never by pattern
 * matching its name - so a helper can never drift from what a direct call
 * would have reported, and only the parameter that actually reaches the sink
 * counts.
 *
 * PHP makes the cross-file half of this easy in a way Python does not: a
 * function name is global, one namespace for the whole request, so a helper
 * defined in `includes/db.inc` and called from `admin/edit.php` needs no
 * import graph to resolve. It is the same name.
 *
 * Methods need more care, because a method name belongs to nobody. `$obj->run()`
 * could be any `run` in the codebase, so it is never resolved - that would be a
 * guess. Only calls whose class is known from the syntax are followed:
 * `$this->run()`, `self::run()`, `static::run()` and `Foo::run()`. Those are
 * resolved against the enclosing class and then up its `extends` chain and
 * through its traits, so a helper inherited from a base controller is found and
 * an unrelated class with a method of the same name is not.
 */
final class Helpers
{
    /**
     * @param array<string, array<int, array{string, string}>> $table   function name => sinks
     * @param array<string, array<int, array{string, string}>> $methods class::method => sinks
     * @param array<string, list<string>>                      $bases   class => parents and traits
     */
    public function __construct(
        private array $table = [],
        private array $methods = [],
        private array $bases = [],
    ) {
    }

    /**
     * Probe every function declared in these files.
     *
     * @param array<string, string> $sources file => code
     */
    public static function build(array $sources, ?string $pin = null): self
    {
        $table = [];
        $methods = [];
        $bases = [];

        foreach ($sources as $file => $raw) {
            [$code, $shifts] = Source::prepare($raw, is_string($file) ? $file : null);
            try {
                [$stmts] = Source::parse($code, $pin);
            } catch (\PhpParser\Error) {
                continue;
            }
            $snippet = new Snippet($code, $shifts);
            $finder = new NodeFinder();

            foreach ($finder->findInstanceOf($stmts, Stmt\Function_::class) as $function) {
                /** @var Stmt\Function_ $function */
                $found = self::probeAll($function, $snippet);
                if ($found !== []) {
                    $table[strtolower($function->name->toString())] = $found;
                }
            }

            foreach ($finder->findInstanceOf($stmts, Stmt\ClassLike::class) as $class) {
                /** @var Stmt\ClassLike $class */
                if ($class->name === null) {
                    continue; // an anonymous class has no name to resolve against
                }
                $owner = strtolower($class->name->toString());
                $bases[$owner] = self::basesOf($class);

                foreach ($class->getMethods() as $method) {
                    $found = self::probeAll($method, $snippet);
                    if ($found !== []) {
                        $methods[$owner . '::' . strtolower($method->name->toString())] = $found;
                    }
                }
            }
        }

        return new self($table, $methods, $bases);
    }

    /**
     * The classes a class inherits behaviour from: its parent and its traits.
     *
     * @return list<string>
     */
    private static function basesOf(Stmt\ClassLike $class): array
    {
        $out = [];
        if ($class instanceof Stmt\Class_ && $class->extends !== null) {
            $out[] = strtolower(Names::shortName(ltrim($class->extends->toString(), '\\')));
        }
        foreach ($class->stmts as $stmt) {
            if ($stmt instanceof Stmt\TraitUse) {
                foreach ($stmt->traits as $trait) {
                    $out[] = strtolower(Names::shortName(ltrim($trait->toString(), '\\')));
                }
            }
        }

        return $out;
    }

    /**
     * @return array<int, array{string, string}>
     */
    private static function probeAll(Node\FunctionLike $function, Snippet $snippet): array
    {
        $found = [];
        foreach (array_keys($function->getParams()) as $index) {
            foreach (Analyzer::probe($function, $index, $snippet) as $flow) {
                // The first sink a parameter reaches is enough to report the
                // call site; listing every one of them would say the same
                // thing several times over.
                $found[$index] ??= [self::classOf($flow->kind), $flow->sink];
            }
        }

        return $found;
    }

    private static function classOf(string $label): string
    {
        $flipped = array_flip(Vocabulary::KIND_LABEL);

        return $flipped[$label] ?? $label;
    }

    /** @return array<int, array{string, string}> */
    public function sinksOf(string $function): array
    {
        return $this->table[$function] ?? [];
    }

    /**
     * What a method does with its arguments, looked up through inheritance.
     *
     * @param list<string> $seen guards a cycle in a malformed hierarchy
     *
     * @return array<int, array{string, string}>
     */
    public function methodSinks(string $class, string $method, array $seen = []): array
    {
        $class = strtolower($class);
        $method = strtolower($method);
        if (in_array($class, $seen, true)) {
            return [];
        }
        if (isset($this->methods[$class . '::' . $method])) {
            return $this->methods[$class . '::' . $method];
        }
        foreach ($this->bases[$class] ?? [] as $base) {
            $found = $this->methodSinks($base, $method, [...$seen, $class]);
            if ($found !== []) {
                return $found;
            }
        }

        return [];
    }

    public function isEmpty(): bool
    {
        return $this->table === [] && $this->methods === [];
    }
}
