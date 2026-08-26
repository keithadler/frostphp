<?php

declare(strict_types=1);

namespace Frost\Tests;

use Frost\Runner;
use Frost\Source;
use PHPUnit\Framework\TestCase;

/**
 * PHP 5 source on a PHP 8 runtime.
 *
 * This is the case frostphp is most often pointed at and the one where a
 * mistake is invisible, because the failure mode is not an error - it is a
 * green run over a file nobody read.
 */
final class LegacyTest extends TestCase
{
    use Helper;

    public function testSyntaxOnlyPhpFiveAccepts(): void
    {
        // Curly-brace string offsets: removed in PHP 8, everywhere in old code.
        $code = "<?php\n\$s = \$_GET['s'];\n\$c = \$s{0};\nsystem(\$s);\n";
        self::assertContains('process.exec', $this->capabilities($code));
        self::assertContains('command injection', $this->kinds($code));
    }

    public function testSyntaxOnlyPhpEightAccepts(): void
    {
        $code = "<?php\n\$r = match(\$x) { 1 => 'a', default => 'b' };\nsystem(\$r);\n";
        self::assertContains('process.exec', $this->capabilities($code));
    }

    /**
     * The dangerous one. PHP's tokenizer ignores `<?` unless short_open_tag is
     * on, and then the whole file is inert HTML: no error, no findings, exit 0.
     */
    public function testShortOpenTagsAreReadNotSilentlySkipped(): void
    {
        $code = "<?\nfunction go(\$c) { system(\$c); }\ngo(\$_GET['c']);\n?>";
        self::assertContains('process.exec', $this->capabilities($code));
        self::assertContains('command injection', $this->kinds($code));
    }

    public function testShortEchoTagsAreASink(): void
    {
        $code = "<h1><?= \$_GET['t'] ?></h1>\n";
        self::assertContains('cross-site scripting', $this->kinds($code));
    }

    public function testAspTagsAreReadToo(): void
    {
        $code = "<%\nsystem(\$_GET['c']);\n%>";
        self::assertContains('command injection', $this->kinds($code));
    }

    public function testLineNumbersSurviveTagRewriting(): void
    {
        $code = "<?\n\n\nsystem(\$_GET['c']);\n";
        $uses = $this->uses($code);
        self::assertCount(1, $uses);
        self::assertSame(4, $uses[0]->line, 'rewriting must not move any line');
    }

    public function testColumnsSurviveTagRewriting(): void
    {
        // The call starts at column 3 in the original: `<? system(...)`.
        $code = "<? system(\$c);";
        $uses = $this->uses($code);
        self::assertCount(1, $uses);
        self::assertSame(3, $uses[0]->column);
    }

    public function testAFileOfPhpThatYieldsNoPhpIsAnError(): void
    {
        // A tag form nothing can read must fail loudly rather than pass clean.
        $this->expectException(\PhpParser\Error::class);
        $this->uses("<?xml version=\"1.0\"?>\n<root><?bogus system('x'); ?></root>");
    }

    public function testPhpFourStyleClassesAndConstructors(): void
    {
        $code = "<?php\nclass DB {\n  var \$link;\n  function DB(\$h) { \$this->link = mysql_connect(\$h); }\n}\n";
        self::assertContains('database.connect', $this->capabilities($code));
    }

    public function testRemovedFunctionsAreStillRecognised(): void
    {
        self::assertContains('codegen.create_function', $this->capabilities($this->php('$f = create_function("$a", "return $a;");')));
        self::assertContains('scope.extract', $this->capabilities($this->php('import_request_variables("gp");')));
        self::assertContains('database.query', $this->capabilities($this->php('mysql_query($sql);')));
        self::assertContains('response.session', $this->capabilities($this->php('session_register("user");')));
    }

    public function testTheDialectUsedIsReported(): void
    {
        $root = $this->tree([
            'old.php' => "<?php\n\$s = 'ab';\necho \$s{0};\n",
            'new.php' => "<?php\necho match(1) { default => 'x' };\n",
        ]);
        $analysis = Runner::analyze([$root]);
        self::assertSame(2, $analysis->files);
        self::assertSame(1, $analysis->legacyFiles());
    }

    public function testPinningTheParserRefusesTheOtherDialect(): void
    {
        [$stmts] = Source::parse("<?php \$s = 'ab'; echo \$s{0};", '5.6');
        self::assertNotSame([], $stmts);

        $this->expectException(\PhpParser\Error::class);
        Source::parse("<?php \$s = 'ab'; echo \$s{0};", '8.5');
    }

    /**
     * A `<?` inside a PHP string is two characters, not a tag. Rewriting it
     * corrupts the file - which is exactly what happened to this tool's own
     * source the first time round, and the file then stopped parsing.
     */
    public function testTagsInsideStringsAndCommentsAreLeftAlone(): void
    {
        $code = "<?php\n\$open = '<?';\n\$also = \"<% and ?>\";\n// a comment mentioning <?\nsystem(\$_GET['c']);\n";
        [$prepared] = Source::prepare($code);
        self::assertStringContainsString("'<?'", $prepared, 'the string must survive verbatim');
        self::assertContains('command injection', $this->kinds($code));
    }

    public function testAClosingTagInsideAStringDoesNotEndTheBlock(): void
    {
        $code = "<?php\necho \"?>\";\nsystem(\$_GET['c']);\n";
        self::assertContains('command injection', $this->kinds($code));
    }

    public function testHeredocsAreSteppedOverWhole(): void
    {
        $code = "<?php\n\$t = <<<HTML\n  <? not a tag ?>\nHTML;\nsystem(\$_GET['c']);\n";
        self::assertContains('command injection', $this->kinds($code));
    }

    public function testRealTemplateAlternationIsStillRead(): void
    {
        $code = "<? \$a = 1; ?>\n<p>markup</p>\n<? system(\$_GET['c']); ?>\n";
        self::assertContains('command injection', $this->kinds($code));
    }

    public function testFrostphpCanReadItsOwnSource(): void
    {
        $analysis = Runner::analyze([__DIR__ . '/../src']);
        self::assertSame([], $analysis->errors, 'the tool must be able to read itself');
        self::assertGreaterThan(20, $analysis->files);
    }

    public function testIncFilesAndTemplatesAreDiscovered(): void
    {
        $root = $this->tree([
            'lib/db.inc' => "<?php system(\$_GET['a']);\n",
            'views/x.phtml' => "<?php echo \$_GET['b']; ?>\n",
            'skip.txt' => "<?php system(\$_GET['c']);\n",
        ]);
        $analysis = Runner::analyze([$root]);
        self::assertSame(2, $analysis->files, '.inc and .phtml are read, .txt is not');
        self::assertCount(2, $analysis->flows);
    }
}
