<?php

declare(strict_types=1);

namespace Frost\Tests;

use Frost\Blade;
use Frost\Extract\Extractor;
use Frost\Taint\Analyzer;
use Frost\Taint\Helpers;
use PHPUnit\Framework\TestCase;

/**
 * Blade templates.
 *
 * A `.blade.php` file is not PHP: without conversion it parses as one long run
 * of text, and a Laravel application's whole view layer reports clean because
 * none of it was read. Every test here asserts a *positive* finding, because
 * "did not error" is exactly the wrong thing to check for this bug.
 */
final class BladeTest extends TestCase
{
    use Helper;

    private const FILE = 'resources/views/show.blade.php';

    /** @return list<string> */
    private function bladeCapabilities(string $code): array
    {
        [$uses] = Extractor::run(self::FILE, $code);

        return array_values(array_unique(array_map(static fn ($u): string => $u->capability, $uses)));
    }

    /** @return list<\Frost\Taint\Flow> */
    private function bladeFlows(string $code): array
    {
        $helpers = Helpers::build([self::FILE => $code]);
        [$flows] = Analyzer::run(self::FILE, $code, $helpers);

        return $flows;
    }

    public function testRawOutputOfUntrustedInputIsCrossSiteScripting(): void
    {
        $flows = $this->bladeFlows("<div>{!! \$_GET['html'] !!}</div>\n");
        self::assertCount(1, $flows);
        self::assertSame('cross-site scripting', $flows[0]->kind);
    }

    /** `{{ }}` escapes, and frostphp knows Laravel's escaper, so it stays quiet. */
    public function testEscapedOutputIsSilent(): void
    {
        self::assertSame([], $this->bladeFlows("<div>{{ \$_GET['name'] }}</div>\n"));
    }

    public function testPhpBlocksAreRealCode(): void
    {
        $code = "<div>\n@php\n  system(\$_GET['c']);\n@endphp\n</div>\n";
        self::assertContains('process.exec', $this->bladeCapabilities($code));

        $flows = $this->bladeFlows($code);
        self::assertCount(1, $flows);
        self::assertSame('command injection', $flows[0]->kind);
        self::assertSame(3, $flows[0]->line);
    }

    public function testTheInlinePhpDirective(): void
    {
        $code = "@php(\$x = \$_GET['c'])\n<p>{!! \$x !!}</p>\n";
        $flows = $this->bladeFlows($code);
        self::assertCount(1, $flows);
        self::assertSame('cross-site scripting', $flows[0]->kind);
    }

    public function testUnescapedOutputIsACapabilityInItsOwnRight(): void
    {
        // Even with nothing untrusted in sight, the view asked to skip escaping.
        self::assertContains('response.raw', $this->bladeCapabilities("<p>{!! \$body !!}</p>\n"));
        self::assertSame([], $this->bladeCapabilities("<p>{{ \$body }}</p>\n"));
    }

    public function testCommentsAndVerbatimBlocksRenderNothing(): void
    {
        self::assertSame([], $this->bladeCapabilities("{{-- {!! \$evil !!} --}}\n"));
        self::assertSame([], $this->bladeCapabilities("@verbatim {!! \$evil !!} @endverbatim\n"));
        self::assertSame([], $this->bladeFlows("{{-- {!! \$_GET['x'] !!} --}}\n"));
    }

    public function testEscapedBracesPrintLiterally(): void
    {
        self::assertSame([], $this->bladeCapabilities("<code>@{!! not a block !!}</code>\n"));
    }

    /** Control directives are left as text; the output they guard is not. */
    public function testDirectivesDoNotBreakTheFileOrSwallowTheOutput(): void
    {
        $code = "@extends('layout')\n@section('body')\n@foreach (\$rows as \$r)\n"
            . "  <li>{!! \$_GET['x'] !!}</li>\n@endforeach\n@endsection\n";
        $flows = $this->bladeFlows($code);
        self::assertCount(1, $flows);
        self::assertSame(4, $flows[0]->line);
    }

    public function testLinesAndColumnsSurviveConversion(): void
    {
        $code = "<div>\n\n  <div>{!! \$_GET['html'] !!}</div>\n";
        $flows = $this->bladeFlows($code);
        self::assertCount(1, $flows);
        self::assertSame(3, $flows[0]->line);
        // `  <div>{!! ` - two spaces, `<div>`, `{!!`, a space: column 11.
        self::assertSame(11, $flows[0]->column);
    }

    public function testAPlainPhpFileIsNotTreatedAsBlade(): void
    {
        self::assertFalse(Blade::isBlade('src/Controller.php'));
        self::assertTrue(Blade::isBlade('resources/views/x.blade.php'));
        self::assertTrue(Blade::isBlade('Resources/Views/X.Blade.PHP'));
    }

    public function testAnUnclosedBlockDoesNotThrow(): void
    {
        // Half-written templates exist; they must not take the run down.
        self::assertSame([], $this->bladeCapabilities("<p>{{ \$x\n"));
        self::assertSame([], $this->bladeFlows("<p>{!! \$_GET['x']\n"));
    }
}
