<?php

declare(strict_types=1);

namespace Frost\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Laravel, Symfony and WordPress.
 *
 * Most PHP is written inside one of these, so a rule that only knows the
 * language and not the framework is a rule that stays quiet on most code. The
 * quiet blocks matter as much as the positives: a method called `query` on an
 * unknown object is not a query, and a request object is not every object.
 */
final class FrameworkTest extends TestCase
{
    use Helper;

    // ---- Symfony --------------------------------------------------------

    /**
     * Symfony reads request data through a bag, so the receiver of the
     * accessor is a property of the request rather than the request itself.
     */
    public function testSymfonyParameterBags(): void
    {
        self::assertContains('command injection', $this->kinds($this->php('system($request->query->get("c"));')));
        self::assertContains('cross-site scripting', $this->kinds($this->php('echo $request->headers->get("X");')));
        self::assertContains('SQL injection', $this->kinds($this->php('$db = new PDO($d); $db->query("SELECT * FROM t WHERE a = " . $request->request->get("a"));')));
        self::assertContains('command injection', $this->kinds($this->php('system($this->request->query->get("c"));')));
    }

    /** A bag on something that is not a request is somebody else's object. */
    public function testABagOnAnUnrelatedObjectIsNotARequest(): void
    {
        self::assertSame([], $this->kinds($this->php('echo $report->query->get("x");')));
        self::assertSame([], $this->kinds($this->php('echo $builder->headers->get("x");')));
    }

    // ---- Laravel --------------------------------------------------------

    public function testLaravelRawQueryBuilders(): void
    {
        foreach (['whereRaw', 'orWhereRaw', 'havingRaw', 'selectRaw', 'orderByRaw', 'groupByRaw'] as $method) {
            $code = $this->php(sprintf('DB::table("u")->%s("id = " . $_GET["id"]);', $method));
            self::assertContains('SQL injection', $this->kinds($code), $method . ' must be reported');
        }
    }

    public function testLaravelFacadeAndRequestHelper(): void
    {
        self::assertContains('SQL injection', $this->kinds($this->php('DB::select("SELECT * FROM u WHERE n = " . $_GET["n"]);')));
        self::assertContains('SQL injection', $this->kinds($this->php('DB::statement("DROP " . $_GET["t"]);')));
        self::assertContains('command injection', $this->kinds($this->php('system(request()->input("c"));')));
    }

    /**
     * `statement` and `unprepared` are real Laravel methods with names far too
     * ordinary to match on an unknown receiver. frostphp's own recursive tree
     * walk, `$this->statement($child)`, was reported as SQL until this was
     * pinned.
     */
    public function testOrdinaryMethodNamesAreNotQueryBuilders(): void
    {
        self::assertSame([], $this->kinds($this->php('$this->statement($_GET["x"]);')));
        self::assertSame([], $this->kinds($this->php('$parser->statement($_GET["x"]);')));
        self::assertSame([], $this->capabilities($this->php('$walker->statement($node);')));
    }

    public function testLaravelEscaper(): void
    {
        self::assertSame([], $this->kinds($this->php('echo e($_GET["m"]);')));
    }

    // ---- WordPress ------------------------------------------------------

    public function testWordpressEscapersAndPrepare(): void
    {
        self::assertSame([], $this->kinds($this->php('echo esc_html($_GET["m"]);')));
        self::assertSame([], $this->kinds($this->php('echo esc_attr($_GET["m"]);')));
        self::assertContains('SQL injection', $this->kinds($this->php('global $wpdb; $wpdb->get_results("SELECT * FROM t WHERE a = " . $_GET["a"]);')));
    }

    /** esc_html protects markup and nothing else. */
    public function testWordpressEscapersAreStillPerDestination(): void
    {
        self::assertContains('command injection', $this->kinds($this->php('system(esc_html($_GET["c"]));')));
    }

    // ---- helpers on methods --------------------------------------------

    public function testATaintedArgumentIntoAMethodOfThisClass(): void
    {
        $code = $this->php(
            'class C { private function run($c) { shell_exec($c); }'
            . ' public function go() { $this->run($_GET["c"]); } }'
        );
        $flows = $this->flows($code);
        self::assertCount(1, $flows);
        self::assertSame('$this->run', $flows[0]->via);
        self::assertStringContainsString('via $this->run', $flows[0]->message());
    }

    public function testAHelperInheritedFromABaseClass(): void
    {
        $code = $this->php(
            'class Base { protected function run($c) { shell_exec($c); } }'
            . ' class Child extends Base { function go() { $this->run($_GET["c"]); } }'
        );
        self::assertContains('command injection', $this->kinds($code));
    }

    public function testAHelperReachedThroughATrait(): void
    {
        $code = $this->php(
            'trait Runs { function run($c) { shell_exec($c); } }'
            . ' class C { use Runs; function go() { $this->run($_GET["c"]); } }'
        );
        self::assertContains('command injection', $this->kinds($code));
    }

    public function testStaticCallsNameTheirClass(): void
    {
        $self = $this->php('class C { static function run($c) { shell_exec($c); } static function go() { self::run($_GET["c"]); } }');
        self::assertContains('command injection', $this->kinds($self));

        $named = $this->php('class C { static function run($c) { shell_exec($c); } } C::run($_GET["c"]);');
        self::assertContains('command injection', $this->kinds($named));
    }

    /**
     * The class of an arbitrary receiver is not knowable from the syntax, so it
     * is never guessed. Otherwise one class's dangerous `run` is attributed to
     * every unrelated `run` in the codebase.
     */
    public function testAMethodOnAnUnknownObjectIsNotResolved(): void
    {
        $code = $this->php(
            'class Runner { function run($c) { shell_exec($c); } }'
            . ' function go($thing) { $thing->run($_GET["c"]); }'
        );
        self::assertSame([], $this->kinds($code));
    }

    public function testOnlyTheParameterThatReachesTheSinkCountsForMethodsToo(): void
    {
        $code = $this->php(
            'class C { function run($safe, $cmd) { shell_exec($cmd); }'
            . ' function go() { $this->run($_GET["a"], "ls"); } }'
        );
        self::assertSame([], $this->kinds($code));
    }
}
