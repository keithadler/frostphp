<?php

declare(strict_types=1);

namespace Frost\Tests;

use Frost\Cli\Main;
use PHPUnit\Framework\TestCase;

final class CliTest extends TestCase
{
    use Helper;

    /** @param list<string> $argv @return array{int, string, string} */
    private function cli(array $argv): array
    {
        $out = fopen('php://memory', 'r+');
        $err = fopen('php://memory', 'r+');
        $code = Main::run($argv, $out, $err);
        rewind($out);
        rewind($err);

        return [$code, (string) stream_get_contents($out), (string) stream_get_contents($err)];
    }

    private function project(): string
    {
        return $this->tree([
            'frostphp.policy' => "policy \"t\"\nmay use the file system\n",
            'src/ok.php' => "<?php\nfile_get_contents('/etc/motd');\n",
            'src/bad.php' => "<?php\nshell_exec('ls');\n",
        ]);
    }

    public function testACleanTreeExitsZero(): void
    {
        $root = $this->tree([
            'frostphp.policy' => "policy \"t\"\nmay use the file system\n",
            'src/ok.php' => "<?php\nfile_get_contents('/etc/motd');\n",
        ]);
        [$code, $out] = $this->cli([$root]);
        self::assertSame(Main::OK, $code);
        self::assertStringContainsString('0 denied', $out);
    }

    public function testADenialExitsOneAndNamesTheReason(): void
    {
        [$code, $out] = $this->cli([$this->project()]);
        self::assertSame(Main::FOUND, $code);
        self::assertStringContainsString('process.exec denied by default (no rule grants it)', $out);
        self::assertStringContainsString("shell_exec('ls')", $out);
    }

    public function testAForbidNamesThePolicyLine(): void
    {
        $root = $this->tree([
            'frostphp.policy' => "policy \"t\"\nmay use everything\nforbid process.exec -- nothing here shells out\n",
            'a.php' => "<?php\nshell_exec('ls');\n",
        ]);
        [$code, $out] = $this->cli([$root]);
        self::assertSame(Main::FOUND, $code);
        self::assertStringContainsString('nothing here shells out', $out);
    }

    public function testNoPolicyIsAnErrorThatSaysWhatToDo(): void
    {
        $root = $this->tree(['a.php' => "<?php\n"]);
        [$code, , $err] = $this->cli([$root]);
        self::assertSame(Main::ERROR, $code);
        self::assertStringContainsString('frostphp init', $err);
    }

    public function testAFileThatCannotBeParsedIsAnErrorNotSilence(): void
    {
        $root = $this->tree([
            'frostphp.policy' => "policy \"t\"\n",
            'broken.php' => "<?php\nfunction ( {\n",
        ]);
        [$code, , $err] = $this->cli([$root]);
        self::assertSame(Main::ERROR, $code);
        self::assertStringContainsString('syntax error', $err);
    }

    public function testInitThenCheckIsClean(): void
    {
        $root = $this->tree([
            'src/a.php' => "<?php\nshell_exec('ls');\nfile_get_contents('/etc/motd');\n",
        ]);
        [$code, $policy] = $this->cli(['init', $root]);
        self::assertSame(Main::OK, $code);
        file_put_contents($root . '/frostphp.policy', $policy);

        [$code, $out] = $this->cli([$root]);
        self::assertSame(Main::OK, $code, 'the policy init wrote must pass: ' . $out);
    }

    public function testTheBaselineHidesOldFindingsAndNotNewOnes(): void
    {
        $root = $this->project();
        $baseline = $root . '/baseline.txt';

        [$code] = $this->cli([$root, '--baseline', $baseline, '--update-baseline']);
        self::assertSame(Main::OK, $code);

        [$code, $out] = $this->cli([$root, '--baseline', $baseline]);
        self::assertSame(Main::OK, $code, 'recorded findings stop failing: ' . $out);

        file_put_contents($root . '/src/new.php', "<?php\nunserialize(\$x);\n");
        [$code, $out] = $this->cli([$root, '--baseline', $baseline]);
        self::assertSame(Main::FOUND, $code);
        self::assertStringContainsString('deserialize.unserialize', $out);
    }

    public function testAnInlineSuppressionNeedsACapabilityAndAReason(): void
    {
        $root = $this->tree([
            'frostphp.policy' => "policy \"t\"\n",
            'a.php' => "<?php\nshell_exec('ls'); // frostphp: allow process.exec -- vetted, fixed argv\n",
            'b.php' => "<?php\nshell_exec('ls'); // frostphp: allow process.exec\n",
        ]);
        [$code, $out] = $this->cli([$root]);
        self::assertSame(Main::FOUND, $code);
        self::assertStringNotContainsString('a.php', $out, 'a reasoned suppression applies');
        self::assertStringContainsString('b.php', $out, 'one without a reason does not');
    }

    public function testFormats(): void
    {
        $root = $this->project();

        [, $json] = $this->cli([$root, '--format', 'json']);
        $decoded = json_decode($json, true);
        self::assertIsArray($decoded);
        self::assertSame('frostphp/process.exec', $decoded['findings'][0]['rule']);

        [, $sarif] = $this->cli([$root, '--format', 'sarif']);
        $decoded = json_decode($sarif, true);
        self::assertSame('2.1.0', $decoded['version']);
        self::assertSame('frostphp', $decoded['runs'][0]['tool']['driver']['name']);

        [, $github] = $this->cli([$root, '--format', 'github']);
        self::assertStringContainsString('::warning file=', $github);
    }

    public function testAnUnknownFormatIsRefused(): void
    {
        [$code, , $err] = $this->cli(['.', '--format', 'yaml']);
        self::assertSame(Main::ERROR, $code);
        self::assertStringContainsString('unknown format', $err);
    }

    public function testAnExpiringGrantWarnsBeforeItLapses(): void
    {
        $root = $this->tree([
            'frostphp.policy' => "policy \"t\"\nmay use process.exec until 2026-01-10\n",
            'a.php' => "<?php\nshell_exec('ls');\n",
        ]);
        [$code, , $err] = $this->cli([$root, '--today', '2026-01-05']);
        self::assertSame(Main::OK, $code);
        self::assertStringContainsString('lapses in 5 days', $err);

        [$code, $out] = $this->cli([$root, '--today', '2026-02-01']);
        self::assertSame(Main::FOUND, $code);
        self::assertStringContainsString('lapsed on 2026-01-10', $out);
    }

    public function testAuditNeedsNoPolicy(): void
    {
        $root = $this->tree(['a.php' => "<?php\nsystem(\$_GET['c']);\n"]);
        [$code, $out] = $this->cli(['audit', $root]);
        self::assertSame(Main::OK, $code);
        self::assertStringContainsString('WHAT THIS CODE CAN DO', $out);
        self::assertStringContainsString('command injection', $out);
    }

    public function testExplainAndCapabilities(): void
    {
        [$code, $out] = $this->cli(['explain', 'unserialize']);
        self::assertSame(Main::OK, $code);
        self::assertStringContainsString('forbid deserialize.unserialize', $out);

        [$code, $out] = $this->cli(['capabilities']);
        self::assertSame(Main::OK, $code);
        self::assertStringContainsString('include', $out);

        [$code] = $this->cli(['explain', 'telepathy']);
        self::assertSame(Main::ERROR, $code);
    }

    public function testSummary(): void
    {
        $root = $this->tree(['frostphp.policy' => "policy \"t\"\nmay use the network\n"]);
        [$code, $out] = $this->cli(['summary', $root]);
        self::assertSame(Main::OK, $code);
        self::assertStringContainsString('This code may:', $out);
    }

    public function testVersionAndHelp(): void
    {
        [$code, $out] = $this->cli(['--version']);
        self::assertSame(Main::OK, $code);
        self::assertStringContainsString('frostphp', $out);

        [$code, $out] = $this->cli(['--help']);
        self::assertSame(Main::OK, $code);
        self::assertStringContainsString('deny-by-default', $out);
    }

    public function testNoTaintReportsCapabilitiesOnly(): void
    {
        $root = $this->tree([
            'frostphp.policy' => "policy \"t\"\nmay use everything\n",
            'a.php' => "<?php\nsystem(\$_GET['c']);\n",
        ]);
        [$code, $out] = $this->cli([$root, '--no-taint']);
        self::assertSame(Main::OK, $code);
        self::assertStringNotContainsString('injection', $out);
    }
}
