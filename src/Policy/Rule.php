<?php

declare(strict_types=1);

namespace Frost\Policy;

/** One line of a policy: a grant or a prohibition, and the reason someone wrote it. */
final class Rule
{
    public function __construct(
        public readonly string $capability,
        public readonly ?string $glob,
        public readonly string $note,
        public readonly int $line,
        public readonly bool $forbid = false,
        public readonly ?string $until = null,
        public readonly ?string $source = null,
    ) {
    }

    public function appliesTo(string $path): bool
    {
        return $this->glob === null || Glob::match($this->glob, str_replace('\\', '/', $path));
    }

    public function expired(string $today): bool
    {
        return $this->until !== null && $today > $this->until;
    }

    /** Days from $today until the grant lapses; negative once it has. */
    public function daysLeft(string $today): ?int
    {
        if ($this->until === null) {
            return null;
        }
        $from = new \DateTimeImmutable($today . ' 00:00:00Z');
        $to = new \DateTimeImmutable($this->until . ' 00:00:00Z');

        return (int) $from->diff($to)->format('%r%a');
    }

    /** How this rule reads back, for a denial message. */
    public function describe(): string
    {
        $verb = $this->forbid ? 'forbid' : 'may use';
        $text = $verb . ' ' . $this->capability;
        if ($this->glob !== null) {
            $text .= sprintf(' in "%s"', $this->glob);
        }
        if ($this->until !== null) {
            $text .= ' until ' . $this->until;
        }

        return $text;
    }
}
