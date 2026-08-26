<?php

declare(strict_types=1);

namespace Frost\Report;

/** A denial or a taint flow, ready to be printed in any format. */
final class Finding
{
    public const DENIED = 'denied';
    public const TAINT = 'taint';

    public function __construct(
        public readonly string $kind,
        public readonly string $code,
        public readonly string $file,
        public readonly int $line,
        public readonly int $column,
        public readonly string $message,
        public readonly string $expression,
    ) {
    }

    public function ruleId(): string
    {
        return 'frostphp/' . $this->code;
    }

    /**
     * Stable across line moves: a finding that slides down the file when
     * someone adds an import is not a new finding, and a baseline that says
     * otherwise is a baseline people stop trusting.
     */
    public function fingerprint(): string
    {
        return substr(hash('sha256', $this->file . "\0" . $this->code . "\0" . $this->expression), 0, 16);
    }
}
