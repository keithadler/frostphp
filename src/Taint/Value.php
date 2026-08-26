<?php

declare(strict_types=1);

namespace Frost\Taint;

/**
 * An untrusted value, and what has been done to it since.
 *
 * Sanitizing is per destination, never global, and that distinction is the
 * whole reason this class exists rather than a boolean. In the code this tool
 * was built to read, the same request value is escaped for one destination and
 * then used in another:
 *
 *     $name = mysqli_real_escape_string($db, $_GET['name']);
 *     $sql  = "SELECT * FROM u WHERE n = '$name'";   // safe
 *     echo "Hello $name";                            // still cross-site scripting
 *
 * A tool with one `sanitized` flag calls the second line clean. It is not.
 */
final class Value
{
    /**
     * @param array<string, true> $safeFor sink classes this value is escaped for
     * @param list<string>        $warnings things done to it that only look like escaping
     */
    public function __construct(
        public readonly string $origin,
        public readonly array $safeFor = [],
        public readonly array $warnings = [],
    ) {
    }

    public function warnedBy(string $warning): self
    {
        return in_array($warning, $this->warnings, true)
            ? $this
            : new self($this->origin, $this->safeFor, [...$this->warnings, $warning]);
    }

    public function isSafeFor(string $class): bool
    {
        return isset($this->safeFor[$class]);
    }

    /** @param list<string> $classes */
    public function sanitizedBy(array $classes): self
    {
        $safe = $this->safeFor;
        foreach ($classes as $class) {
            $safe[$class] = true;
        }

        return new self($this->origin, $safe, $this->warnings);
    }

    /**
     * Two values joined - by concatenation, or by two branches meeting.
     *
     * The result is only safe where both parts are safe: a query built from one
     * escaped value and one raw one is not an escaped query.
     */
    public function merge(self $other): self
    {
        return new self(
            $this->origin,
            array_intersect_key($this->safeFor, $other->safeFor),
            array_values(array_unique([...$this->warnings, ...$other->warnings])),
        );
    }
}
