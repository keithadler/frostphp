#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * The false-positive guard.
 *
 * Accuracy is the product, so it is enforced rather than claimed. Every engine
 * change runs over pinned, real packages and the findings must not move. Loosen
 * a rule by accident and this prints the new lines as a diff and exits 1.
 *
 *     php scripts/corpus.php            check
 *     php scripts/corpus.php --update   record, after reading every added line
 *
 * Adding a line here is a claim that the new finding is true. Open the file in
 * corpus/.cache and confirm it before you record it.
 */

require __DIR__ . '/../vendor/autoload.php';

use Frost\Extract\Usage;
use Frost\Runner;
use Frost\Taint\Flow;

$root = dirname(__DIR__);
$cache = $root . '/corpus/.cache';
$expectedFile = $root . '/corpus/expected.txt';
$update = in_array('--update', $argv, true);

$manifest = json_decode((string) file_get_contents($root . '/corpus/manifest.json'), true);
if (!is_array($manifest)) {
    fwrite(STDERR, "corpus: manifest.json is unreadable\n");
    exit(2);
}

if (!is_dir($cache . '/vendor')) {
    @mkdir($cache, 0o777, true);
    file_put_contents($cache . '/composer.json', json_encode(
        ['require' => $manifest, 'config' => ['audit' => ['abandoned' => 'ignore']]],
        JSON_PRETTY_PRINT
    ));
    fwrite(STDERR, "corpus: installing " . count($manifest) . " pinned packages...\n");
    // frostphp: allow process.exec -- the corpus fetches its own pinned inputs
    exec(sprintf('composer install -d %s --no-interaction -q 2>&1', escapeshellarg($cache)), $out, $status);
    if ($status !== 0 || !is_dir($cache . '/vendor')) {
        fwrite(STDERR, "corpus: composer install failed:\n" . implode("\n", $out) . "\n");
        exit(2);
    }
}

$started = microtime(true);
$analysis = Runner::analyze([$cache . '/vendor'], vendor: true);
$elapsed = microtime(true) - $started;

$lines = [];
foreach ($analysis->uses as $use) {
    $lines[] = sprintf('%s %s %s', relative($use->file, $cache), $use->capability, normalise($use->expression));
}
foreach ($analysis->flows as $flow) {
    $lines[] = sprintf('%s FLOW %s', relative($flow->file, $cache), $flow->message());
}
sort($lines);

$bytes = 0;
foreach (\Frost\Discover::files([$cache . '/vendor'], \Frost\Discover::EXTENSIONS, true) as $file) {
    $bytes += (int) filesize($file);
}

$summary = sprintf(
    "%d files, %.1f MB, %d findings, %.1fs",
    $analysis->files,
    $bytes / 1_048_576,
    count($lines),
    $elapsed
);

if ($update) {
    file_put_contents($expectedFile, implode("\n", $lines) . "\n");
    echo $summary, ": recorded\n";
    exit(0);
}

$expected = is_file($expectedFile)
    ? array_values(array_filter(explode("\n", (string) file_get_contents($expectedFile)), static fn (string $l): bool => $l !== ''))
    : [];

$added = array_values(array_diff($lines, $expected));
$removed = array_values(array_diff($expected, $lines));

if ($added === [] && $removed === []) {
    echo $summary, ": unchanged\n";
    if ($analysis->errors !== []) {
        fwrite(STDERR, sprintf("corpus: %d files could not be parsed\n", count($analysis->errors)));
        exit(2);
    }
    exit(0);
}

echo $summary, ": CHANGED\n\n";
foreach ($added as $line) {
    echo '  + ', $line, "\n";
}
foreach ($removed as $line) {
    echo '  - ', $line, "\n";
}
echo "\nEvery added line is a claim that the finding is true. Open the file in\n";
echo "corpus/.cache and check it. If it is real, record it with --update.\n";
exit(1);

function relative(string $path, string $cache): string
{
    return str_replace($cache . '/vendor/', '', $path);
}

/** Expression text is kept short and whitespace-flat so the diff stays readable. */
function normalise(string $expression): string
{
    $flat = (string) preg_replace('/\s+/', ' ', $expression);

    return strlen($flat) > 80 ? substr($flat, 0, 77) . '...' : $flat;
}
