<?php

declare(strict_types=1);

namespace Frost;

use Frost\Policy\Policy;
use Frost\Report\Finding;
use Frost\Taint\Vocabulary;

/** Turning an analysis and a policy into the list of things that fail the build. */
final class Check
{
    /**
     * @param array<string, list<array{int, int}>>|null $changed
     *
     * @return list<Finding>
     */
    public static function findings(
        Analysis $analysis,
        Policy $policy,
        ?string $today = null,
        ?array $changed = null,
    ): array {
        $today ??= date('Y-m-d');
        $out = [];

        $uses = $analysis->uses;
        usort($uses, static fn ($a, $b): int => [$a->file, $a->line, $a->column] <=> [$b->file, $b->line, $b->column]);

        foreach ($uses as $use) {
            [$allowed, $rule] = $policy->verdict($use->capability, $use->file, $today);
            if ($allowed) {
                continue;
            }
            if (Suppress::covers($analysis->marks[$use->file] ?? [], $use->line, $use->capability)) {
                continue;
            }
            if ($changed !== null && !Changed::touches($changed, $use->file, $use->line)) {
                continue;
            }

            $message = $rule === null
                ? sprintf('%s denied by default (no rule grants it)', $use->capability)
                : ($rule->forbid
                    ? sprintf('%s denied by "%s" (line %d)%s', $use->capability, $rule->describe(), $rule->line, $rule->note === '' ? '' : ': ' . $rule->note)
                    : sprintf('%s: the grant on line %d lapsed on %s', $use->capability, $rule->line, (string) $rule->until));

            $out[] = new Finding(Finding::DENIED, $use->capability, $use->file, $use->line, $use->column, $message, $use->expression);
        }

        $flows = $analysis->flows;
        usort($flows, static fn ($a, $b): int => [$a->file, $a->line, $a->column] <=> [$b->file, $b->line, $b->column]);

        foreach ($flows as $flow) {
            $code = self::codeOf($flow->kind);
            if (Suppress::covers($analysis->marks[$flow->file] ?? [], $flow->line, 'taint.' . $code)) {
                continue;
            }
            if ($changed !== null && !Changed::touches($changed, $flow->file, $flow->line)) {
                continue;
            }
            $out[] = new Finding(Finding::TAINT, 'taint.' . $code, $flow->file, $flow->line, $flow->column, $flow->message(), $flow->expression);
        }

        usort($out, static fn ($a, $b): int => [$a->file, $a->line, $a->column] <=> [$b->file, $b->line, $b->column]);

        return $out;
    }

    private static function codeOf(string $label): string
    {
        $flipped = array_flip(Vocabulary::KIND_LABEL);

        return $flipped[$label] ?? 'flow';
    }
}
