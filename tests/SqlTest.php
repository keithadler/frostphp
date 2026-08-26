<?php

declare(strict_types=1);

namespace Frost\Tests;

use Frost\Taint\Sql;
use PHPUnit\Framework\TestCase;

/**
 * The escaping matrix.
 *
 * This is the part of frostphp that says something other tools do not, and it
 * is the part most likely to be wrong, so every cell of the matrix is pinned:
 * escaped or not, crossed with quoted, bare and identifier positions.
 */
final class SqlTest extends TestCase
{
    use Helper;

    private const ESCAPE = '$v = mysqli_real_escape_string($db, $_GET["v"]);';

    public function testUnescapedIsAlwaysInjection(): void
    {
        $cases = [
            'quoted' => '$v = $_GET["v"]; mysqli_query($db, "SELECT * FROM t WHERE n = \'$v\'");',
            'bare' => '$v = $_GET["v"]; mysqli_query($db, "SELECT * FROM t WHERE id = $v");',
            'identifier' => '$v = $_GET["v"]; mysqli_query($db, "SELECT * FROM t ORDER BY $v");',
            'concatenated' => '$v = $_GET["v"]; mysqli_query($db, "SELECT * FROM t WHERE id = " . $v);',
        ];
        foreach ($cases as $name => $code) {
            self::assertContains('SQL injection', $this->kinds($this->php($code)), $name . ' must be reported');
        }
    }

    /** Escaped and quoted is the one safe combination, and must be silent. */
    public function testEscapedInsideQuotesIsSafe(): void
    {
        $code = $this->php(self::ESCAPE . ' mysqli_query($db, "SELECT * FROM t WHERE n = \'$v\'");');
        self::assertSame([], $this->kinds($code));
    }

    public function testEscapedOutsideQuotesIsStillInjection(): void
    {
        $code = $this->php(self::ESCAPE . ' mysqli_query($db, "SELECT * FROM t WHERE id = $v");');
        $flows = $this->flows($code);
        self::assertCount(1, $flows);
        self::assertStringContainsString('outside quotes', $flows[0]->detail);
        self::assertStringContainsString('escaping it did not help', $flows[0]->detail);
    }

    public function testEscapedIntoAnIdentifierPositionIsStillInjection(): void
    {
        foreach (['ORDER BY', 'GROUP BY', 'LIMIT', 'FROM'] as $keyword) {
            $code = $this->php(self::ESCAPE . sprintf(' mysqli_query($db, "SELECT * FROM t %s $v");', $keyword));
            $flows = $this->flows($code);
            self::assertCount(1, $flows, $keyword . ' must be reported');
            self::assertStringContainsString('identifier', $flows[0]->detail, $keyword);
        }
    }

    public function testIntvalIsSafeEvenBare(): void
    {
        $code = $this->php('$v = intval($_GET["v"]); mysqli_query($db, "SELECT * FROM t LIMIT $v");');
        self::assertSame([], $this->kinds($code));
    }

    public function testAddslashesIsNotASanitiserAndTheReportSaysWhy(): void
    {
        $code = $this->php('$v = addslashes($_GET["v"]); mysql_query("SELECT * FROM t WHERE n = \'$v\'");');
        $flows = $this->flows($code);
        self::assertCount(1, $flows);
        self::assertStringContainsString('addslashes does not stop SQL injection', $flows[0]->detail);
    }

    public function testAPreparedStatementWithABoundParameterIsSafe(): void
    {
        $safe = $this->php('$s = mysqli_prepare($db, "SELECT * FROM u WHERE n = ?"); mysqli_stmt_bind_param($s, "s", $_GET["n"]);');
        self::assertSame([], $this->kinds($safe));

        // But a query string built from input is injection whatever you call it.
        $unsafe = $this->php('mysqli_prepare($db, "SELECT * FROM u WHERE n = \'" . $_GET["n"] . "\'");');
        self::assertContains('SQL injection', $this->kinds($unsafe));
    }

    public function testWpdbPrepareIsTheSafeFormAndIsNeverReported(): void
    {
        $safe = $this->php('global $wpdb; $wpdb->query($wpdb->prepare("SELECT * FROM t WHERE id = %d", $_GET["id"]));');
        self::assertSame([], $this->kinds($safe));

        $unsafe = $this->php('global $wpdb; $wpdb->query("SELECT * FROM t WHERE id = " . $_GET["id"]);');
        self::assertContains('SQL injection', $this->kinds($unsafe));
    }

    public function testLaravelRawQueries(): void
    {
        self::assertContains('SQL injection', $this->kinds($this->php('DB::select("SELECT * FROM t WHERE n = " . $_GET["n"]);')));
    }

    public function testQuoteContextReading(): void
    {
        self::assertSame(Sql::CONTEXT_QUOTED, Sql::contextAfter("SELECT * FROM t WHERE n = '"));
        self::assertSame(Sql::CONTEXT_BARE, Sql::contextAfter('SELECT * FROM t WHERE id = '));
        self::assertSame(Sql::CONTEXT_IDENTIFIER, Sql::contextAfter('SELECT * FROM t ORDER BY '));
        self::assertSame(Sql::CONTEXT_UNKNOWN, Sql::contextAfter(''));
        // A closed pair leaves us outside again.
        self::assertSame(Sql::CONTEXT_BARE, Sql::contextAfter("SELECT * FROM t WHERE a = 'x' AND b = "));
        // An escaped quote does not open anything.
        self::assertSame(Sql::CONTEXT_BARE, Sql::contextAfter("SELECT * FROM t WHERE a = 'x\\'y' AND b = "));
    }

    public function testTheRiskiestHoleDecides(): void
    {
        // One quoted hole and one bare hole: the bare one must win.
        $code = $this->php(
            '$a = mysqli_real_escape_string($db, $_GET["a"]);'
            . ' mysqli_query($db, "SELECT * FROM t WHERE n = \'$a\' AND id = $a");'
        );
        $flows = $this->flows($code);
        self::assertCount(1, $flows);
        self::assertStringContainsString('outside quotes', $flows[0]->detail);
    }
}
