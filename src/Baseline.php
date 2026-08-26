<?php

declare(strict_types=1);

namespace Frost;

use Frost\Report\Finding;

/**
 * Today's findings, recorded so that only new ones fail.
 *
 * This is how a policy gets adopted on a codebase with twenty years of history
 * instead of being declared impossible. The debt is written down, it stops
 * growing, and it is visible in the diff when someone pays a piece of it off.
 */
final class Baseline
{
    /** @param array<string, true> $fingerprints */
    private function __construct(private readonly array $fingerprints)
    {
    }

    public static function load(string $path): self
    {
        $lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false) {
            return new self([]);
        }
        $out = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            // Each line is `<fingerprint>  # <capability> <file>:<line>`; the
            // trailing note is there for the human reading the diff, not for us.
            $fingerprint = strtok($line, " \t");
            if ($fingerprint !== false && $fingerprint !== '') {
                $out[$fingerprint] = true;
            }
        }

        return new self($out);
    }

    /** @param list<Finding> $findings */
    public static function write(string $path, array $findings): bool
    {
        $lines = ["# frostphp baseline - findings present when the gate went up.", '# Delete a line to make that finding fail again.', ''];
        $seen = [];
        foreach ($findings as $finding) {
            $seen[$finding->fingerprint()] = sprintf('%s  # %s %s:%d', $finding->fingerprint(), $finding->code, $finding->file, $finding->line);
        }
        ksort($seen);

        return file_put_contents($path, implode("\n", [...$lines, ...array_values($seen)]) . "\n") !== false;
    }

    public function has(Finding $finding): bool
    {
        return isset($this->fingerprints[$finding->fingerprint()]);
    }

    /**
     * @param list<Finding> $findings
     *
     * @return list<Finding>
     */
    public function filter(array $findings): array
    {
        return array_values(array_filter($findings, fn (Finding $f): bool => !$this->has($f)));
    }

    public function count(): int
    {
        return count($this->fingerprints);
    }
}
