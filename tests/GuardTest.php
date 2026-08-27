<?php

declare(strict_types=1);

namespace Frost\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Checks that prove what a value is.
 *
 * The negatives here matter more than the positives. A guard that vouches too
 * easily does not make frostphp quieter, it makes it wrong - and wrong in the
 * one direction that cannot be noticed, because the missing finding leaves no
 * trace. Every check that constrains nothing must keep the flow.
 */
final class GuardTest extends TestCase
{
    use Helper;

    // ---- checks that really do constrain the value ----------------------

    public function testAnAllowlistLookup(): void
    {
        $code = $this->php('$m = ["a" => 1]; $n = $_GET["n"]; if (isset($m[$n])) { new $n(); }');
        self::assertSame([], $this->kinds($code));

        $inHelper = $this->php(
            'function g($n) { $m = ["a" => 1]; if (isset($m[$n])) { return new $n(); } return false; }'
            . ' g($_GET["c"]);'
        );
        self::assertSame([], $this->kinds($inHelper));
    }

    public function testInArrayAndArrayKeyExists(): void
    {
        self::assertSame([], $this->kinds($this->php('$n = $_GET["n"]; if (in_array($n, ["a","b"], true)) { system($n); }')));
        self::assertSame([], $this->kinds($this->php('$n = $_GET["n"]; if (array_key_exists($n, $m)) { system($n); }')));
    }

    /** The early return: everything after it runs only when the check passed. */
    public function testAGuardClauseCoversWhatFollowsIt(): void
    {
        self::assertSame([], $this->kinds($this->php('$n = $_GET["n"]; if (!isset($m[$n])) { return; } system($n);')));
        self::assertSame([], $this->kinds($this->php('$n = $_GET["n"]; if (!in_array($n, $ok)) { wp_die(); } system($n);')));
        self::assertSame([], $this->kinds($this->php('$n = $_GET["n"]; if (!isset($m[$n])) { throw new Exception("no"); } system($n);')));
    }

    public function testComparisonAgainstALiteral(): void
    {
        self::assertSame([], $this->kinds($this->php('$n = $_GET["n"]; if ($n === "ls") { system($n); }')));
        self::assertSame([], $this->kinds($this->php('$n = $_GET["n"]; if ("ls" == $n) { system($n); }')));
        self::assertSame([], $this->kinds($this->php('$n = $_GET["n"]; if ($n === "a" || $n === "b") { system($n); }')));
    }

    public function testAnAnchoredPattern(): void
    {
        self::assertSame([], $this->kinds($this->php('$n = $_GET["n"]; if (preg_match("/^[a-z]+$/", $n)) { system($n); }')));
        self::assertSame([], $this->kinds($this->php('$n = $_GET["n"]; if (ctype_alnum($n)) { system($n); }')));
    }

    public function testASwitchCasePinsTheValue(): void
    {
        self::assertSame([], $this->kinds($this->php('$n = $_GET["n"]; switch ($n) { case "ls": system($n); break; }')));
    }

    // ---- checks that constrain nothing, and must not vouch --------------

    public function testATruthinessTestProvesNothing(): void
    {
        self::assertContains('command injection', $this->kinds($this->php('$n = $_GET["n"]; if ($n) { system($n); }')));
        self::assertContains('command injection', $this->kinds($this->php('$n = $_GET["n"]; if (strlen($n) < 10) { system($n); }')));
    }

    /**
     * An unanchored pattern says the value contains something somewhere. It
     * says nothing whatever about the rest of it, which is where the payload
     * goes.
     */
    public function testAnUnanchoredPatternProvesNothing(): void
    {
        self::assertContains('command injection', $this->kinds($this->php('$n = $_GET["n"]; if (preg_match("/[a-z]+/", $n)) { system($n); }')));
        self::assertContains('command injection', $this->kinds($this->php('$n = $_GET["n"]; if (preg_match("/^[a-z]+$/m", $n)) { system($n); }')));
    }

    /** `isset($_GET['n'])` proves the request has an `n`, not that `n` is safe. */
    public function testIssetOnTheSuperglobalItselfProvesNothing(): void
    {
        self::assertContains('command injection', $this->kinds($this->php('if (isset($_GET["n"])) { system($_GET["n"]); }')));
        self::assertContains('command injection', $this->kinds($this->php('$n = $_GET["n"]; if (isset($n)) { system($n); }')));
    }

    public function testAGuardCoversOnlyTheBranchItGuards(): void
    {
        $code = $this->php('$n = $_GET["n"]; if (isset($m[$n])) { echo "ok"; } system($n);');
        self::assertContains('command injection', $this->kinds($code));
    }

    /** Without an exit, the code after a negated check is reached either way. */
    public function testANegatedCheckThatFallsThroughDoesNotCover(): void
    {
        $code = $this->php('$n = $_GET["n"]; if (!isset($m[$n])) { $n = "safe"; } system($n);');
        self::assertContains('command injection', $this->kinds($code));
    }

    public function testAGuardOnOneVariableSaysNothingAboutAnother(): void
    {
        $code = $this->php('$a = $_GET["a"]; $b = $_GET["b"]; if (isset($m[$a])) { system($b); }');
        self::assertContains('command injection', $this->kinds($code));
    }
}
