#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * docs/CAPABILITIES.md, generated from the taxonomy so it cannot drift.
 * CI runs this and fails if the committed file differs.
 */

require __DIR__ . '/../vendor/autoload.php';

use Frost\Capabilities;

$lines = [
    '# Capabilities',
    '',
    'Generated from `src/Capabilities.php` by `php scripts/gen_docs.php`. Do not edit by hand.',
    '',
    'A policy may name a **family** (`may use the network`) or a single **member**',
    '(`may use network.curl`). A family grant covers its members; a member grant does',
    'not cover the family. Everything not granted is denied.',
    '',
];

foreach (Capabilities::FAMILIES as $family) {
    $lines[] = sprintf('## `%s`', $family);
    $lines[] = '';
    $lines[] = ucfirst(Capabilities::FAMILY_SUMMARY[$family] ?? '') . '.';
    $lines[] = '';
    $lines[] = '| code | fires on | grant it with |';
    $lines[] = '| --- | --- | --- |';

    $phrases = array_keys(array_filter(Capabilities::PHRASES, static fn (string $c): bool => $c === $family));
    sort($phrases);
    $lines[] = sprintf(
        '| `%s` | *the whole family* | `may use %s`%s |',
        $family,
        $family,
        $phrases === [] ? '' : ', ' . implode(', ', array_map(static fn (string $p): string => sprintf('`may use %s`', $p), $phrases))
    );

    foreach (Capabilities::membersOf($family) as $member) {
        $memberPhrases = array_keys(array_filter(Capabilities::PHRASES, static fn (string $c): bool => $c === $member));
        sort($memberPhrases);
        $lines[] = sprintf(
            '| `%s` | %s | `may use %s`%s |',
            $member,
            str_replace('|', '\|', Capabilities::TRIGGERS[$member] ?? ''),
            $member,
            $memberPhrases === [] ? '' : ', ' . implode(', ', array_map(static fn (string $p): string => sprintf('`may use %s`', $p), $memberPhrases))
        );
    }
    $lines[] = '';
}

$lines[] = '## Refusing one';
$lines[] = '';
$lines[] = 'Any code above can be refused outright with `forbid <code>`. A `forbid` beats a';
$lines[] = '`may use`, so a family can be granted and one member carved out of it, and an';
$lines[] = 'inherited `forbid` cannot be granted away by a policy that `extends` it.';
$lines[] = '';

$text = implode("\n", $lines);
$target = dirname(__DIR__) . '/docs/CAPABILITIES.md';

if (in_array('--check', $argv, true)) {
    $current = is_file($target) ? (string) file_get_contents($target) : '';
    if ($current !== $text) {
        fwrite(STDERR, "docs/CAPABILITIES.md is out of date. Run: php scripts/gen_docs.php\n");
        exit(1);
    }
    echo "docs/CAPABILITIES.md is up to date\n";
    exit(0);
}

file_put_contents($target, $text);
echo "wrote docs/CAPABILITIES.md\n";
