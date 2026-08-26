<?php

declare(strict_types=1);

namespace Frost\Tests;

use PHPUnit\Framework\TestCase;

/**
 * The false-positive guard, as a test.
 *
 * Skipped when the pinned packages have not been fetched, so a clone without
 * network still runs green - but CI fetches them, and there the finding count
 * may not move by accident.
 */
final class CorpusTest extends TestCase
{
    public function testTheCorpusIsUnchanged(): void
    {
        $root = __DIR__ . '/..';
        if (!is_dir($root . '/corpus/.cache/vendor')) {
            self::markTestSkipped('corpus not fetched; run `php scripts/corpus.php`');
        }

        $output = [];
        $status = 0;
        exec(sprintf('php %s 2>&1', escapeshellarg($root . '/scripts/corpus.php')), $output, $status);
        self::assertSame(0, $status, implode("\n", $output));
    }
}
