<?php

declare(strict_types=1);

namespace Frost\Tests;

use Frost\Capabilities;
use PHPUnit\Framework\TestCase;

/**
 * The taxonomy is the contract. If the extractor can emit a code the policy
 * language cannot name, a project has a capability it is unable to grant, and
 * the only way out is `may use everything`.
 */
final class CapabilitiesTest extends TestCase
{
    /** Every code the extractor emits must be nameable in a policy. */
    public function testEveryEmittedCodeIsInTheTaxonomy(): void
    {
        $sources = glob(__DIR__ . '/../src/Extract/*.php') ?: [];
        $emitted = [];
        foreach ($sources as $file) {
            $code = (string) file_get_contents($file);
            preg_match_all("/->add\('([a-z_]+\.[a-z_]+)'/", $code, $m);
            $emitted = [...$emitted, ...$m[1]];
            preg_match_all("/=> '([a-z_]+\.[a-z_]+)'/", $code, $m);
            $emitted = [...$emitted, ...$m[1]];
        }
        $emitted = array_values(array_unique($emitted));
        self::assertNotEmpty($emitted, 'found no capability codes in the extractor');

        foreach ($emitted as $code) {
            self::assertContains($code, Capabilities::MEMBER_CODES, sprintf('%s is emitted but not in the taxonomy', $code));
        }
    }

    /** And every code in the taxonomy must be documented. */
    public function testEveryCodeHasATrigger(): void
    {
        foreach (Capabilities::MEMBER_CODES as $code) {
            self::assertArrayHasKey($code, Capabilities::TRIGGERS, $code . ' has no trigger text');
        }
        foreach (Capabilities::FAMILIES as $family) {
            self::assertArrayHasKey($family, Capabilities::FAMILY_SUMMARY, $family . ' has no summary');
            self::assertNotEmpty(Capabilities::membersOf($family), $family . ' has no members');
        }
    }

    public function testEveryMemberBelongsToAKnownFamily(): void
    {
        foreach (Capabilities::MEMBER_CODES as $code) {
            $family = explode('.', $code)[0];
            self::assertContains($family, Capabilities::FAMILIES, $code . ' has no family');
        }
    }

    public function testEveryPhraseResolvesToARealCode(): void
    {
        foreach (Capabilities::PHRASES as $phrase => $code) {
            if ($code === '*') {
                continue;
            }
            self::assertContains($code, Capabilities::known(), sprintf('phrase "%s" points at "%s"', $phrase, $code));
        }
    }

    public function testAFamilyGrantCoversItsMembersButNotTheReverse(): void
    {
        self::assertTrue(Capabilities::covers('network', 'network.curl'));
        self::assertTrue(Capabilities::covers('*', 'process.exec'));
        self::assertFalse(Capabilities::covers('network.curl', 'network'));
        self::assertFalse(Capabilities::covers('network.curl', 'network.socket'));
        // A prefix that is not a family boundary must not match.
        self::assertFalse(Capabilities::covers('net', 'network.curl'));
    }

    public function testResolveAcceptsPhrasesAndCodes(): void
    {
        self::assertSame('process', Capabilities::resolve('shell commands'));
        self::assertSame('process', Capabilities::resolve('  SHELL   Commands '));
        self::assertSame('deserialize.unserialize', Capabilities::resolve('deserialize.unserialize'));
        self::assertNull(Capabilities::resolve('whatever i feel like'));
    }

    public function testExplainNamesTheGrantAndTheRefusal(): void
    {
        $text = (string) Capabilities::explain('deserialize.unserialize');
        self::assertStringContainsString('may use deserialize.unserialize', $text);
        self::assertStringContainsString('forbid deserialize.unserialize', $text);
        self::assertStringContainsString('unserialize(...)', $text);

        $family = (string) Capabilities::explain('the network');
        self::assertStringContainsString('Members:', $family);
        self::assertNull(Capabilities::explain('nonsense'));
    }
}
