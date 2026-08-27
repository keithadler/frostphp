<?php

declare(strict_types=1);

namespace Frost\Taint;

/**
 * One claim that a value goes somewhere it should not.
 *
 * A Flow is not a capability. `mysqli_query($db, "SELECT 1")` is a capability
 * and belongs in the policy; `mysqli_query($db, "SELECT $id")` where `$id` came
 * from the query string is a bug and fails the build on its own.
 */
final class Flow
{
    public function __construct(
        public readonly string $kind,     // sql, command, code, inclusion, html, path, header, ...
        public readonly string $source,   // "$_GET['id']"
        public readonly string $sink,     // "mysqli_query"
        public readonly string $file,
        public readonly int $line,
        public readonly int $column,
        public readonly string $expression,
        public readonly string $detail = '',
        public readonly ?string $via = null,
        public readonly bool $topLevel = false,
    ) {
    }

    public function message(): string
    {
        $text = sprintf('%s -> %s', $this->source, $this->sink);
        if ($this->via !== null) {
            // A plain function is written `run()`; a method already carries its
            // receiver, as `$this->run` or `Foo::run`.
            $text .= str_contains($this->via, '>') || str_contains($this->via, ':')
                ? sprintf(' (via %s)', $this->via)
                : sprintf(' (via %s())', $this->via);
        }
        $text .= sprintf('  <- %s', $this->kind);
        if ($this->detail !== '') {
            $text .= sprintf(': %s', $this->detail);
        }

        return $text;
    }
}
