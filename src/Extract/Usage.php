<?php

declare(strict_types=1);

namespace Frost\Extract;

/**
 * One capability, used once, somewhere.
 *
 * `$topLevel` is PHP's answer to "when does this run". A statement outside any
 * function or method body runs the moment the file is included - and in PHP a
 * file is included by the web server on a request, or by Composer's autoloader
 * before a single line of application code. A socket opened there has already
 * been opened; nobody called it.
 */
final class Usage
{
    public function __construct(
        public readonly string $capability,
        public readonly string $file,
        public readonly int $line,
        public readonly int $column,
        public readonly string $expression,
        public readonly bool $topLevel = false,
    ) {
    }
}
