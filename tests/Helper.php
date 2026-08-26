<?php

declare(strict_types=1);

namespace Frost\Tests;

use Frost\Extract\Extractor;
use Frost\Extract\Usage;
use Frost\Taint\Analyzer;
use Frost\Taint\Flow;
use Frost\Taint\Helpers;

trait Helper
{
    /** @return list<Usage> */
    protected function uses(string $code, ?string $pin = null): array
    {
        [$uses] = Extractor::run('test.php', $code, $pin);

        return $uses;
    }

    /** @return list<string> */
    protected function capabilities(string $code, ?string $pin = null): array
    {
        return array_values(array_unique(array_map(
            static fn (Usage $u): string => $u->capability,
            $this->uses($code, $pin)
        )));
    }

    /** @return list<Flow> */
    protected function flows(string $code): array
    {
        $helpers = Helpers::build(['test.php' => $code]);
        [$flows] = Analyzer::run('test.php', $code, $helpers);

        return $flows;
    }

    /** @return list<string> */
    protected function kinds(string $code): array
    {
        return array_map(static fn (Flow $f): string => $f->kind, $this->flows($code));
    }

    protected function php(string $body): string
    {
        return "<?php\n" . $body . "\n";
    }

    /** Write a throwaway tree and hand back its path. @param array<string, string> $files */
    protected function tree(array $files): string
    {
        $root = sys_get_temp_dir() . '/frostphp-test-' . bin2hex(random_bytes(6));
        foreach ($files as $relative => $contents) {
            $path = $root . '/' . $relative;
            @mkdir(dirname($path), 0o777, true);
            file_put_contents($path, $contents);
        }
        register_shutdown_function(static function () use ($root): void {
            $it = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::CHILD_FIRST
            );
            foreach ($it as $entry) {
                $entry->isDir() ? @rmdir($entry->getPathname()) : @unlink($entry->getPathname());
            }
            @rmdir($root);
        });

        return $root;
    }
}
