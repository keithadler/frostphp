<?php

declare(strict_types=1);

namespace Frost;

use Frost\Extract\Usage;
use Frost\Taint\Flow;

/** Everything one pass over a tree learned. */
final class Analysis
{
    /**
     * @param list<Usage>              $uses
     * @param list<Flow>               $flows
     * @param list<string>             $errors
     * @param array<string, array<int, list<string>>> $marks
     * @param array<string, int>       $versions how many files each dialect read
     */
    public function __construct(
        public readonly array $uses = [],
        public readonly array $flows = [],
        public readonly array $errors = [],
        public readonly array $marks = [],
        public readonly int $files = 0,
        public readonly array $versions = [],
    ) {
    }

    /** Files that only the legacy dialect could read - a useful thing to know. */
    public function legacyFiles(): int
    {
        $out = 0;
        foreach ($this->versions as $version => $count) {
            if (version_compare($version, '8.0', '<')) {
                $out += $count;
            }
        }

        return $out;
    }
}
