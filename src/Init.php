<?php

declare(strict_types=1);

namespace Frost;

/**
 * A policy that grants exactly what the code does today.
 *
 * The first check passes, which is the point: adoption is one command, not a
 * week of triage. Then someone reads the file and deletes the lines that
 * should never have been true, and the check starts refusing them. Every line
 * carries a note saying where the capability was found, so the person deleting
 * has something to go on.
 */
final class Init
{
    public static function fromAnalysis(Analysis $analysis, string $name = 'app'): string
    {
        /** @var array<string, list<string>> $where */
        $where = [];
        foreach ($analysis->uses as $use) {
            $where[$use->capability][] = $use->file . ':' . $use->line;
        }
        ksort($where);

        $lines = [sprintf('policy "%s"', $name)];
        $lines[] = sprintf('-- Written by `frostphp init` from %d file%s.', $analysis->files, $analysis->files === 1 ? '' : 's');
        $lines[] = '-- Every line below is something the code already does. Delete the ones';
        $lines[] = '-- that were never a decision; the check will start refusing them.';
        $lines[] = '';

        if ($where === []) {
            $lines[] = '-- Nothing found. The code reaches for nothing, and this policy grants';
            $lines[] = '-- nothing, which is the strongest position there is.';

            return implode("\n", $lines) . "\n";
        }

        $width = max(array_map(static fn (string $c): int => strlen($c), array_keys($where))) + 8;

        foreach ($where as $capability => $places) {
            $count = count($places);
            $note = sprintf(
                '%d use%s, e.g. %s',
                $count,
                $count === 1 ? '' : 's',
                $places[0]
            );
            $lines[] = sprintf('%-' . $width . 's -- %s', 'may use ' . $capability, $note);
        }

        $flows = count($analysis->flows);
        if ($flows > 0) {
            $lines[] = '';
            $lines[] = sprintf('-- %d taint flow%s were also found. A policy cannot grant those away:', $flows, $flows === 1 ? '' : 's');
            $lines[] = '-- they are bugs, not capabilities. Run `frostphp <paths>` to see them.';
        }

        return implode("\n", $lines) . "\n";
    }
}
