<?php

declare(strict_types=1);

namespace Frost\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Not every key of a superglobal came from the client.
 *
 * Treating `$_SERVER` and `$_FILES` as uniformly untrusted is the easy thing
 * to do and it puts findings on `header($_SERVER['SERVER_PROTOCOL'] . ' 200
 * OK')`, which is in a great many codebases and is not a bug.
 */
final class SourcesTest extends TestCase
{
    use Helper;

    public function testServerKeysTheClientControls(): void
    {
        foreach (['HTTP_HOST', 'HTTP_USER_AGENT', 'HTTP_X_FORWARDED_FOR', 'QUERY_STRING', 'REQUEST_URI', 'PHP_SELF', 'PATH_INFO'] as $key) {
            $code = $this->php(sprintf('system($_SERVER["%s"]);', $key));
            self::assertContains('command injection', $this->kinds($code), $key . ' is attacker-controlled');
        }
    }

    public function testServerKeysTheServerControls(): void
    {
        foreach (['SERVER_PROTOCOL', 'DOCUMENT_ROOT', 'REMOTE_ADDR', 'SCRIPT_FILENAME', 'SERVER_PORT'] as $key) {
            $code = $this->php(sprintf('header($_SERVER["%s"] . " 200 OK");', $key));
            self::assertSame([], $this->kinds($code), $key . ' comes from the server, not the request');
        }
    }

    /**
     * SERVER_NAME is deliberately still untrusted: with `UseCanonicalName Off`
     * Apache fills it from the Host header.
     */
    public function testServerNameStaysUntrusted(): void
    {
        self::assertContains('header injection', $this->kinds($this->php('header("Location: " . $_SERVER["SERVER_NAME"]);')));
    }

    public function testUploadedFileKeys(): void
    {
        // PHP invented the temporary path; nobody chose it.
        self::assertSame([], $this->kinds($this->php('unlink($_FILES["f"]["tmp_name"]);')));
        self::assertSame([], $this->kinds($this->php('$s = $_FILES["f"]["size"]; echo $s;')));

        // The browser sent the name and the type.
        self::assertContains('path traversal', $this->kinds($this->php('unlink("/up/" . $_FILES["f"]["name"]);')));
        self::assertContains('cross-site scripting', $this->kinds($this->php('echo $_FILES["f"]["type"];')));
    }

    /**
     * setcookie() URL-encodes its value, so a newline in it never reaches the
     * response. setrawcookie() does not, which is the whole difference.
     */
    public function testSetcookieEncodesItsValueAndSetrawcookieDoesNot(): void
    {
        self::assertSame([], $this->kinds($this->php('setcookie("lang", $_GET["l"], 0);')));
        self::assertContains('header injection', $this->kinds($this->php('setrawcookie("lang", $_GET["l"], 0);')));
        self::assertContains('header injection', $this->kinds($this->php('setcookie($_GET["name"], "1", 0);')));
    }

    /** A finding inside a loop is one finding, not one per pass of the analysis. */
    public function testALoopBodyIsReportedOnce(): void
    {
        $code = $this->php('foreach ($rows as $r) { echo $_GET["m"]; }');
        self::assertCount(1, $this->flows($code));

        $while = $this->php('$c = $_GET["c"]; while ($x) { system($c); }');
        self::assertCount(1, $this->flows($while));
    }
}
