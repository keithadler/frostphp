<?php

declare(strict_types=1);

namespace Frost\Policy;

use Frost\Capabilities;

/**
 * What this project may do, in plain words.
 *
 *     policy "billing"
 *     may use the network in "src/Clients/*"   -- vendor SDKs
 *     forbid unserialize                       -- use JSON
 *     may use shell commands until 2026-09-01  -- migration script
 *
 * Everything not granted is denied, which is the whole idea.
 */
final class Policy
{
    /** @param list<Rule> $rules @param list<string> $extends */
    public function __construct(
        public string $name = 'unnamed',
        public array $rules = [],
        public ?string $path = null,
        public array $extends = [],
    ) {
    }

    /**
     * Decide one capability in one file.
     *
     * A `forbid` beats a `may use`, so a family can be granted and one member
     * carved out of it. An expired grant does not grant: the exception someone
     * gave themselves in March stops holding the door open in December, and the
     * denial says which line lapsed rather than pretending nobody wrote one.
     *
     * @return array{bool, Rule|null}
     */
    public function verdict(string $capability, string $file, ?string $today = null): array
    {
        $today ??= date('Y-m-d');
        $grant = null;
        $lapsed = null;

        foreach ($this->rules as $rule) {
            if (!$rule->appliesTo($file) || !Capabilities::covers($rule->capability, $capability)) {
                continue;
            }
            if ($rule->forbid) {
                return [false, $rule];
            }
            if ($rule->expired($today)) {
                $lapsed ??= $rule;
                continue;
            }
            $grant ??= $rule;
        }

        return $grant !== null ? [true, $grant] : [false, $lapsed];
    }

    /**
     * Grants with an `until` that has passed or is close, with days left.
     *
     * @return list<array{Rule, int}>
     */
    public function expiring(?string $today = null, int $within = 14): array
    {
        $today ??= date('Y-m-d');
        $out = [];
        foreach ($this->rules as $rule) {
            $days = $rule->daysLeft($today);
            if ($days !== null && $days <= $within) {
                $out[] = [$rule, $days];
            }
        }

        return $out;
    }

    /** The policy in English, for someone who does not write PHP to sign off. */
    public function summary(): string
    {
        $lines = [sprintf('Policy "%s"', $this->name), ''];
        if ($this->rules === []) {
            $lines[] = 'Grants nothing. Every capability is denied.';

            return implode("\n", $lines) . "\n";
        }

        $granted = array_filter($this->rules, static fn (Rule $r): bool => !$r->forbid);
        $forbidden = array_filter($this->rules, static fn (Rule $r): bool => $r->forbid);

        if ($granted !== []) {
            $lines[] = 'This code may:';
            foreach ($granted as $rule) {
                $lines[] = '  ' . self::sentence($rule);
            }
        }
        if ($forbidden !== []) {
            $lines[] = '';
            $lines[] = 'This code may never:';
            foreach ($forbidden as $rule) {
                $lines[] = '  ' . self::sentence($rule);
            }
        }
        $lines[] = '';
        $lines[] = 'Everything else is denied.';

        return implode("\n", $lines) . "\n";
    }

    private static function sentence(Rule $rule): string
    {
        $family = explode('.', $rule->capability)[0];
        $what = $rule->capability === '*'
            ? 'do anything'
            : (Capabilities::FAMILY_SUMMARY[$rule->capability]
                ?? sprintf('%s (%s)', $rule->capability, Capabilities::TRIGGERS[$rule->capability] ?? $family));

        $text = $what;
        if ($rule->glob !== null) {
            $text .= sprintf(' - only in %s', $rule->glob);
        }
        if ($rule->until !== null) {
            $text .= sprintf(' - only until %s', $rule->until);
        }
        if ($rule->note !== '') {
            $text .= sprintf(' [%s]', $rule->note);
        }

        return $text;
    }
}
