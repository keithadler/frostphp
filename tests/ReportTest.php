<?php

declare(strict_types=1);

namespace Frost\Tests;

use Frost\Report\Finding;
use Frost\Report\Report;
use PHPUnit\Framework\TestCase;

final class ReportTest extends TestCase
{
    /** @return list<Finding> */
    private function findings(): array
    {
        return [
            new Finding(Finding::DENIED, 'process.exec', 'src/a.php', 12, 4, 'process.exec denied by default', "shell_exec('ls')"),
            new Finding(Finding::TAINT, 'taint.sql', 'src/b.php', 30, 0, "\$_GET['id'] -> mysql_query", 'mysql_query($sql)'),
        ];
    }

    public function testText(): void
    {
        $text = Report::text($this->findings(), 2);
        self::assertStringContainsString('src/a.php:12:4:', $text);
        self::assertStringContainsString('2 files, 1 denied, 1 taint flow', $text);
    }

    public function testTextPluralisesHonestly(): void
    {
        self::assertStringContainsString('1 file, 0 denied', Report::text([], 1));
    }

    public function testJson(): void
    {
        $decoded = json_decode(Report::emit('json', $this->findings(), 2), true);
        self::assertCount(2, $decoded['findings']);
        self::assertSame('frostphp/taint.sql', $decoded['findings'][1]['rule']);
        self::assertMatchesRegularExpression('/^[0-9a-f]{16}$/', $decoded['findings'][0]['fingerprint']);
    }

    public function testSarifMarksFlowsAsErrorsAndDenialsAsWarnings(): void
    {
        $decoded = json_decode(Report::emit('sarif', $this->findings(), 2), true);
        $results = $decoded['runs'][0]['results'];
        self::assertSame('warning', $results[0]['level']);
        self::assertSame('error', $results[1]['level']);
        // SARIF columns are 1-based; ours are 0-based.
        self::assertSame(5, $results[0]['locations'][0]['physicalLocation']['region']['startColumn']);
    }

    public function testGithubAnnotations(): void
    {
        $text = Report::emit('github', $this->findings(), 2);
        self::assertStringContainsString('::warning file=src/a.php,line=12,col=5::', $text);
        self::assertStringContainsString('::error file=src/b.php', $text);
    }

    /** A finding that slides down the file is not a new finding. */
    public function testTheFingerprintIgnoresTheLineNumber(): void
    {
        $a = new Finding(Finding::DENIED, 'process.exec', 'a.php', 10, 0, 'm', "shell_exec('ls')");
        $b = new Finding(Finding::DENIED, 'process.exec', 'a.php', 99, 8, 'm', "shell_exec('ls')");
        self::assertSame($a->fingerprint(), $b->fingerprint());

        $different = new Finding(Finding::DENIED, 'process.exec', 'a.php', 10, 0, 'm', "shell_exec('id')");
        self::assertNotSame($a->fingerprint(), $different->fingerprint());
    }

    public function testAnnotationsCannotBreakOutOfTheirLine(): void
    {
        $nasty = [new Finding(Finding::DENIED, 'x.y', 'a.php', 1, 0, "one\ntwo", '100%')];
        $text = Report::emit('github', $nasty, 1);
        self::assertSame(1, substr_count($text, "\n"));
        self::assertStringContainsString('100%25', $text);
    }
}
