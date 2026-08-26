<?php

declare(strict_types=1);

namespace Frost\Extract;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Name;

/**
 * Deciding whether a name really refers to the thing.
 *
 * This is the whole difference between a linter people keep and one they turn
 * off. In PHP the traps are specific:
 *
 *     system($cmd)                  the global function - fires
 *     $logger->system($cmd)         a method on an object - never fires
 *     Registry::system($cmd)        a static call - never fires
 *     namespace App; system($cmd)   still the global function: PHP falls back
 *                                   to the global namespace for unqualified
 *                                   function calls, so this one does fire
 *     namespace App; function system() {...} system($cmd)
 *                                   now it does not: the namespace declares it
 *     use function App\exec; exec($x)
 *                                   not the global exec - the import wins
 *
 * The fallback rule is the one a naive matcher gets backwards in both
 * directions: it either reports every namespaced call as global (wrong when
 * the namespace defines its own) or none of them (wrong almost always, since
 * the fallback is what PHP actually does).
 */
final class Names
{
    private string $namespace = '';

    /** @var array<string, string> lowercased alias => fully qualified function */
    private array $functionAliases = [];

    /** @var array<string, string> lowercased alias => fully qualified class */
    private array $classAliases = [];

    /** @var array<string, true> lowercased names of functions declared in this file */
    private array $declared = [];

    public function enterNamespace(?Name $name): void
    {
        $this->namespace = $name === null ? '' : $name->toString();
        $this->functionAliases = [];
        $this->classAliases = [];
    }

    public function addUse(Node\Stmt\UseUse|Node\UseItem $use, int $type): void
    {
        $alias = strtolower($use->getAlias()->toString());
        $target = $use->name->toString();
        if ($type === Node\Stmt\Use_::TYPE_FUNCTION) {
            $this->functionAliases[$alias] = $target;
        } elseif ($type === Node\Stmt\Use_::TYPE_NORMAL) {
            $this->classAliases[$alias] = $target;
        }
    }

    public function declareFunction(string $name): void
    {
        $this->declared[strtolower($name)] = true;
    }

    /**
     * The global function this call node invokes, lowercased - or null if it
     * does not invoke one.
     */
    public function globalFunction(Node $node): ?string
    {
        if (!$node instanceof Expr\FuncCall) {
            return null;
        }
        // A variable function - $fn() - is a capability of its own, not a
        // known callee. Resolving it would be a guess.
        if (!$node->name instanceof Name) {
            return null;
        }

        $name = $node->name;
        $lower = strtolower($name->toString());

        if ($name->isFullyQualified()) {
            return ltrim($lower, '\\');
        }

        $first = strtolower($name->getFirst());
        if (isset($this->functionAliases[$first])) {
            $full = $this->functionAliases[$first];
            $rest = array_slice($name->getParts(), 1);

            return strtolower(ltrim($full . ($rest === [] ? '' : '\\' . implode('\\', $rest)), '\\'));
        }

        // Qualified but not aliased: App\Sub\system() is App's, never global.
        if (count($name->getParts()) > 1) {
            return null;
        }

        // Unqualified inside a namespace that declares its own: the namespaced
        // one wins, exactly as PHP resolves it.
        //
        // Only inside a namespace. In the global namespace a file cannot
        // declare `function exec()` at all - PHP fatals on the redeclaration -
        // so a declaration there is always of a name the engine does not own,
        // and the name must still come back so the helper table can be looked
        // up under it.
        if ($this->namespace !== '' && isset($this->declared[$lower])) {
            return null;
        }

        // Unqualified, unshadowed: PHP falls back to the global function.
        return $lower;
    }

    /** The class a `new` or static call names, fully qualified and lowercased. */
    public function className(Name|Expr $name): ?string
    {
        if (!$name instanceof Name) {
            return null;
        }
        $lower = strtolower($name->toString());
        if ($name->isFullyQualified()) {
            return ltrim($lower, '\\');
        }
        $first = strtolower($name->getFirst());
        if (isset($this->classAliases[$first])) {
            $full = $this->classAliases[$first];
            $rest = array_slice($name->getParts(), 1);

            return strtolower(ltrim($full . ($rest === [] ? '' : '\\' . implode('\\', $rest)), '\\'));
        }
        if ($this->namespace !== '' && count($name->getParts()) === 1) {
            // Could be App\Foo or \Foo; PHP resolves classes to the current
            // namespace with no fallback, so report the namespaced one and let
            // the caller compare against a short name too.
            return strtolower($this->namespace . '\\' . $name->toString());
        }

        return $lower;
    }

    /** The trailing segment of a class name, for matching well-known short names. */
    public static function shortName(string $fullyQualified): string
    {
        $at = strrpos($fullyQualified, '\\');

        return $at === false ? $fullyQualified : substr($fullyQualified, $at + 1);
    }
}
