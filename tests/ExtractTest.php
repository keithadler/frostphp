<?php

declare(strict_types=1);

namespace Frost\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Capability extraction, and - at least as important - the look-alikes that
 * must stay quiet. Every positive here is paired with the shape that would
 * make a text matcher fire and must not make this one fire.
 */
final class ExtractTest extends TestCase
{
    use Helper;

    public function testTheObviousConstructs(): void
    {
        self::assertContains('codegen.eval', $this->capabilities($this->php('eval($x);')));
        self::assertContains('process.backtick', $this->capabilities($this->php('$o = `ls`;')));
        self::assertContains('process.exec', $this->capabilities($this->php('shell_exec($c);')));
        self::assertContains('deserialize.unserialize', $this->capabilities($this->php('unserialize($b);')));
        self::assertContains('native.ffi', $this->capabilities($this->php('FFI::cdef($d);')));
        self::assertContains('scope.extract', $this->capabilities($this->php('extract($a);')));
    }

    public function testAMethodOfTheSameNameIsNotTheFunction(): void
    {
        $quiet = $this->php('$logger->system("boot"); $r->exec(); Registry::system($c); $a->unserialize($x);');
        self::assertSame([], $this->capabilities($quiet));
    }

    public function testAnAliasIsFollowedAndAQualifiedNameIsNot(): void
    {
        self::assertContains('process.exec', $this->capabilities($this->php('\system("ls");')));

        $namespaced = "<?php\nnamespace App\\Sub;\nOther\\system('x');\n";
        self::assertSame([], $this->capabilities($namespaced));
    }

    /** PHP falls back to the global function for an unqualified name. So must we. */
    public function testAnUnqualifiedNameInANamespaceStillReachesTheGlobalFunction(): void
    {
        $code = "<?php\nnamespace App;\nsystem('ls');\n";
        self::assertContains('process.exec', $this->capabilities($code));
    }

    /** Unless that namespace declares its own, which PHP resolves first. */
    public function testANamespacedDeclarationShadowsTheGlobalFunction(): void
    {
        $code = "<?php\nnamespace App;\nfunction system(\$x) { return \$x; }\nsystem('ls');\n";
        self::assertNotContains('process.exec', $this->capabilities($code));
    }

    public function testAnImportedFunctionIsNotTheGlobalOne(): void
    {
        $code = "<?php\nnamespace App;\nuse function App\\Util\\exec;\nexec('ls');\n";
        self::assertNotContains('process.exec', $this->capabilities($code));
    }

    public function testIncludeIsOnlyACapabilityWhenTheFileIsChosenAtRuntime(): void
    {
        self::assertContains('include.dynamic', $this->capabilities($this->php('include $page;')));
        self::assertContains('include.dynamic', $this->capabilities($this->php('require "views/" . $p;')));

        // Modularity, not a capability.
        self::assertSame([], $this->capabilities($this->php('include "config.php";')));
        self::assertSame([], $this->capabilities($this->php('require_once __DIR__ . "/lib.php";')));
        self::assertSame([], $this->capabilities($this->php('require dirname(__FILE__) . "/../lib/db.inc";')));
        self::assertSame([], $this->capabilities($this->php('require dirname(dirname(__FILE__)) . "/a.php";')));
    }

    public function testFopenModeDecidesReadFromWrite(): void
    {
        self::assertContains('filesystem.read', $this->capabilities($this->php('fopen($f, "r");')));
        self::assertContains('filesystem.write', $this->capabilities($this->php('fopen($f, "w");')));
        self::assertContains('filesystem.write', $this->capabilities($this->php('fopen($f, "a+");')));
    }

    public function testASchemeChangesWhatAPathIs(): void
    {
        self::assertContains('network.url', $this->capabilities($this->php('file_get_contents("https://x.invalid/a");')));
        self::assertContains('network.url', $this->capabilities($this->php('file_get_contents("https://x.invalid/" . $p);')));
        self::assertContains('filesystem.wrapper', $this->capabilities($this->php('file_get_contents("php://input");')));
        self::assertContains('filesystem.read', $this->capabilities($this->php('file_get_contents($path);')));
    }

    /**
     * A scheme is a capability where it is used as a path, and data anywhere
     * else. Otherwise every table of wrapper names - including this tool's own
     * - reports itself.
     */
    public function testASchemeOutsideAPathPositionIsJustAString(): void
    {
        // A path assigned to a variable is still a path, and is a use.
        self::assertContains('filesystem.wrapper', $this->capabilities($this->php('$x = "php://input";')));

        // A check, a comparison and a table are about wrappers, not uses of one.
        self::assertSame([], $this->capabilities($this->php('if (stripos($v, "phar://") === 0) { return; }')));
        self::assertSame([], $this->capabilities($this->php('if ($v === "php://input") { return; }')));
        self::assertSame([], $this->capabilities($this->php('$schemes = ["php://", "phar://"];')));
        self::assertSame([], $this->capabilities($this->php('$v = str_replace("phar://", "", $p);')));
    }

    /**
     * PHP deserializes a phar's metadata on any path operation, so a stat call
     * on a phar:// path is a deserializer, not a stat call.
     */
    public function testAPharPathIsADeserializerEvenOnAStatCall(): void
    {
        self::assertContains('deserialize.phar', $this->capabilities($this->php('file_exists("phar://a.phar/b");')));
        self::assertContains('deserialize.phar', $this->capabilities($this->php('getimagesize("phar://up.phar/x");')));
        self::assertContains('deserialize.phar', $this->capabilities($this->php('include "phar://a.phar/run.php";')));
    }

    public function testAssertOnlyFiresOnAString(): void
    {
        self::assertContains('codegen.assert', $this->capabilities($this->php('assert("$a > $b");')));
        self::assertNotContains('codegen.assert', $this->capabilities($this->php('assert($a instanceof Foo);')));
        self::assertNotContains('codegen.assert', $this->capabilities($this->php('assert($x > 1);')));
    }

    public function testPregReplaceOnlyFiresOnTheEvalModifier(): void
    {
        self::assertContains('codegen.preg', $this->capabilities($this->php('preg_replace("/a/e", $r, $s);')));
        self::assertContains('codegen.preg', $this->capabilities($this->php('preg_replace("#a#ie", $r, $s);')));
        self::assertNotContains('codegen.preg', $this->capabilities($this->php('preg_replace("/a/i", $r, $s);')));
        self::assertNotContains('codegen.preg', $this->capabilities($this->php('preg_replace("/e/", $r, $s);')));
        self::assertNotContains('codegen.preg', $this->capabilities($this->php('preg_replace($pattern, $r, $s);')));
    }

    public function testParseStrOnlyFiresWhenItWritesIntoScope(): void
    {
        self::assertContains('scope.parse_str', $this->capabilities($this->php('parse_str($q);')));
        self::assertNotContains('scope.parse_str', $this->capabilities($this->php('parse_str($q, $out);')));
    }

    public function testDynamicDispatchIsItsOwnCapability(): void
    {
        self::assertContains('codegen.dynamic', $this->capabilities($this->php('$fn($a);')));
        self::assertContains('codegen.dynamic', $this->capabilities($this->php('$o->$m();')));
        self::assertContains('codegen.dynamic', $this->capabilities($this->php('new $class();')));
        self::assertContains('codegen.dynamic', $this->capabilities($this->php('call_user_func($cb, $a);')));

        self::assertSame([], $this->capabilities($this->php('$o->method(); new Foo(); strlen($a);')));
    }

    public function testAQueryCountsOnlyOnAKnownConnection(): void
    {
        $known = $this->php('$db = new PDO("sqlite::memory:"); $db->query("SELECT 1");');
        self::assertContains('database.query', $this->capabilities($known));

        $unknown = $this->php('$builder->query(); $this->finder->exec();');
        self::assertSame([], $this->capabilities($unknown));
    }

    public function testWordpressGlobalCountsAsAConnection(): void
    {
        self::assertContains('database.query', $this->capabilities($this->php('global $wpdb; $wpdb->get_results($sql);')));
    }

    public function testTopLevelIsSeparatedFromInsideAFunction(): void
    {
        $code = $this->php('fsockopen($h, 80); function later() { fsockopen($h, 80); }');
        $uses = $this->uses($code);
        self::assertCount(2, $uses);
        self::assertTrue($uses[0]->topLevel, 'module level runs on include');
        self::assertFalse($uses[1]->topLevel, 'a function body does not');
    }

    public function testAMethodBodyIsNotTopLevel(): void
    {
        $code = $this->php('class A { public function go() { shell_exec($c); } }');
        $uses = $this->uses($code);
        self::assertCount(1, $uses);
        self::assertFalse($uses[0]->topLevel);
    }

    public function testTheReportCarriesTheSourceAsWritten(): void
    {
        $uses = $this->uses($this->php('unserialize($_COOKIE["u"]);'));
        self::assertSame('unserialize($_COOKIE["u"])', $uses[0]->expression);
        self::assertSame(2, $uses[0]->line);
    }

    public function testABrokenFileIsAnErrorNotSilence(): void
    {
        $this->expectException(\PhpParser\Error::class);
        $this->uses("<?php\nfunction ( { \n");
    }
}
