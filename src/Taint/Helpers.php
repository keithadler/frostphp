<?php

declare(strict_types=1);

namespace Frost\Taint;

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
 */
final class Helpers
{
    /** @var array<string, array<int, array{string, string}>> */
    private array $table = [];

    /** @param array<string, array<int, array{string, string}>> $table */
    public function __construct(array $table = [])
    {
        $this->table = $table;
    }

    /**
     * Probe every function declared in these files.
     *
     * @param array<string, string> $sources file => code
     */
    public static function build(array $sources, ?string $pin = null): self
    {
        $table = [];
        foreach ($sources as $raw) {
            [$code, $shifts] = Source::prepare($raw);
            try {
                [$stmts] = Source::parse($code, $pin);
            } catch (\PhpParser\Error) {
                continue;
            }
            $snippet = new Snippet($code, $shifts);
            foreach ((new NodeFinder())->findInstanceOf($stmts, Stmt\Function_::class) as $function) {
                /** @var Stmt\Function_ $function */
                $name = strtolower($function->name->toString());
                $found = self::probeAll($function, $snippet);
                if ($found !== []) {
                    $table[$name] = $found;
                }
            }
        }

        return new self($table);
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

    public function isEmpty(): bool
    {
        return $this->table === [];
    }
}
