<?php

declare(strict_types=1);

namespace Frost\Tests;

use Frost\Policy\Glob;
use Frost\Policy\Parser;
use Frost\Policy\PolicyError;
use PHPUnit\Framework\TestCase;

final class PolicyTest extends TestCase
{
    use Helper;

    public function testEverythingNotGrantedIsDenied(): void
    {
        $policy = Parser::parse('policy "x"');
        [$allowed, $rule] = $policy->verdict('process.exec', 'a.php');
        self::assertFalse($allowed);
        self::assertNull($rule);
    }

    public function testAGrantByPhraseOrByCode(): void
    {
        $policy = Parser::parse("policy \"x\"\nmay use shell commands\nmay use network.curl");
        self::assertTrue($policy->verdict('process.exec', 'a.php')[0]);
        self::assertTrue($policy->verdict('network.curl', 'a.php')[0]);
        self::assertFalse($policy->verdict('network.socket', 'a.php')[0]);
    }

    public function testAFamilyGrantCoversMembersButNotTheOtherWayRound(): void
    {
        $family = Parser::parse("policy \"x\"\nmay use the network");
        self::assertTrue($family->verdict('network.socket', 'a.php')[0]);

        $member = Parser::parse("policy \"x\"\nmay use network.curl");
        self::assertFalse($member->verdict('network.socket', 'a.php')[0]);
    }

    public function testForbidBeatsMayUse(): void
    {
        $policy = Parser::parse("policy \"x\"\nmay use the network\nforbid network.socket -- no raw sockets");
        self::assertTrue($policy->verdict('network.curl', 'a.php')[0]);

        [$allowed, $rule] = $policy->verdict('network.socket', 'a.php');
        self::assertFalse($allowed);
        self::assertNotNull($rule);
        self::assertSame('no raw sockets', $rule->note);
    }

    public function testAGrantCanBeScopedToAGlob(): void
    {
        $policy = Parser::parse("policy \"x\"\nmay use deserialize.unserialize in \"src/legacy/*\"");
        self::assertTrue($policy->verdict('deserialize.unserialize', 'src/legacy/old.php')[0]);
        self::assertFalse($policy->verdict('deserialize.unserialize', 'src/new.php')[0]);
    }

    public function testAGrantCanExpire(): void
    {
        $policy = Parser::parse("policy \"x\"\nmay use process.exec until 2026-01-01");
        self::assertTrue($policy->verdict('process.exec', 'a.php', '2025-12-31')[0]);

        [$allowed, $rule] = $policy->verdict('process.exec', 'a.php', '2026-06-01');
        self::assertFalse($allowed, 'a lapsed grant does not grant');
        self::assertNotNull($rule, 'but the denial still names the line that lapsed');
        self::assertSame('2026-01-01', $rule->until);
    }

    public function testExpiringGrantsAreListedBeforeTheyLapse(): void
    {
        $policy = Parser::parse("policy \"x\"\nmay use process.exec until 2026-01-10");
        self::assertCount(1, $policy->expiring('2026-01-01'));
        self::assertSame(9, $policy->expiring('2026-01-01')[0][1]);
        self::assertSame([], $policy->expiring('2025-11-01'));
    }

    public function testExtendsMergesABaseAndAnInheritedForbidCannotBeGrantedAway(): void
    {
        $root = $this->tree([
            'base.policy' => "policy \"base\"\nforbid deserialize.unserialize -- never\n",
            'app/frostphp.policy' => "extends \"../base.policy\"\npolicy \"app\"\nmay use deserialize.unserialize\n",
        ]);
        $policy = Parser::load($root . '/app/frostphp.policy');
        self::assertFalse($policy->verdict('deserialize.unserialize', 'a.php')[0]);
    }

    public function testCircularExtendsIsAnError(): void
    {
        $root = $this->tree([
            'a.policy' => "extends \"b.policy\"\npolicy \"a\"\n",
            'b.policy' => "extends \"a.policy\"\npolicy \"b\"\n",
        ]);
        $this->expectException(PolicyError::class);
        Parser::load($root . '/a.policy');
    }

    public function testAPolicyThatDoesNotParseIsAnError(): void
    {
        $this->expectException(PolicyError::class);
        Parser::parse("policy \"x\"\nmay possibly use the network");
    }

    public function testAnUnknownCapabilityIsAnError(): void
    {
        $this->expectExceptionMessageMatches('/unknown capability/');
        Parser::parse("policy \"x\"\nmay use telepathy");
    }

    public function testABadDateIsAnError(): void
    {
        $this->expectExceptionMessageMatches('/bad date/');
        Parser::parse("policy \"x\"\nmay use process.exec until 2026-13-45");
    }

    public function testCommentsAndBlankLines(): void
    {
        $policy = Parser::parse("-- a note\npolicy \"x\"\n\nmay use the network -- why\n");
        self::assertSame('x', $policy->name);
        self::assertCount(1, $policy->rules);
        self::assertSame('why', $policy->rules[0]->note);
    }

    public function testTheSummaryReadsAsEnglish(): void
    {
        $policy = Parser::parse("policy \"billing\"\nmay use the network -- vendor SDK\nforbid codegen.eval");
        $summary = $policy->summary();
        self::assertStringContainsString('This code may:', $summary);
        self::assertStringContainsString('This code may never:', $summary);
        self::assertStringContainsString('vendor SDK', $summary);
        self::assertStringContainsString('Everything else is denied.', $summary);
    }

    public function testGlobs(): void
    {
        self::assertTrue(Glob::match('src/*.php', 'src/a.php'));
        self::assertFalse(Glob::match('src/*.php', 'src/sub/a.php'));
        self::assertTrue(Glob::match('src/**/*.php', 'src/sub/deep/a.php'));
        self::assertTrue(Glob::match('src/**/*.php', 'src/a.php'), '** must also match zero directories');
        self::assertTrue(Glob::match('src/?.php', 'src/a.php'));
        self::assertFalse(Glob::match('src/?.php', 'src/ab.php'));
        // `*` stops at a separator, so reaching into a subtree needs `**`.
        self::assertFalse(Glob::match('*legacy*', 'app/legacy/x.php'));
        self::assertTrue(Glob::match('**/legacy/**', 'app/legacy/x.php'));
        self::assertTrue(Glob::match('app/legacy/**', 'app/legacy/deep/x.php'));
        // A dot in the pattern is a literal dot, not "any character".
        self::assertFalse(Glob::match('a.php', 'axphp'));
    }
}
