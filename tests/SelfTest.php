<?php

declare(strict_types=1);

namespace Frost\Tests;

use Frost\Check;
use Frost\Policy\Parser;
use Frost\Runner;
use PHPUnit\Framework\TestCase;

/**
 * frostphp against its own policy, and its own documentation.
 *
 * A tool that cannot pass the gate it ships is not making a serious claim
 * about the gate.
 */
final class SelfTest extends TestCase
{
    private const ROOT = __DIR__ . '/..';

    public function testFrostphpPassesItsOwnPolicy(): void
    {
        $analysis = Runner::analyze([self::ROOT . '/src', self::ROOT . '/bin', self::ROOT . '/scripts']);
        self::assertSame([], $analysis->errors);

        $policy = Parser::load(self::ROOT . '/frostphp.policy');
        $findings = Check::findings($analysis, $policy);

        $described = array_map(
            static fn ($f): string => sprintf('%s:%d %s', basename($f->file), $f->line, $f->message),
            $findings
        );
        self::assertSame([], $described);
    }

    public function testTheCapabilityDocumentationIsCurrent(): void
    {
        $output = [];
        $status = 0;
        exec(sprintf('php %s --check 2>&1', escapeshellarg(self::ROOT . '/scripts/gen_docs.php')), $output, $status);
        self::assertSame(0, $status, implode("\n", $output));
    }
}
