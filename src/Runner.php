<?php

declare(strict_types=1);

namespace Frost;

use Frost\Extract\Extractor;
use Frost\Taint\Analyzer;
use Frost\Taint\Helpers;
use PhpParser\Error as ParseError;

/**
 * One pass over a set of paths.
 *
 * Every file is read once and analysed twice - for capabilities, and for
 * flows - with the helper table built in between, because a helper defined in
 * one file and called from another is the ordinary shape of a PHP application
 * and stopping at the file boundary would miss most of them.
 */
final class Runner
{
    /**
     * @param list<string> $paths
     * @param list<string> $extensions
     */
    public static function analyze(
        array $paths,
        ?string $pin = null,
        array $extensions = Discover::EXTENSIONS,
        bool $vendor = false,
        bool $taint = true,
    ): Analysis {
        $files = Discover::files($paths, $extensions, $vendor);

        $sources = [];
        $errors = [];
        foreach ($files as $file) {
            $code = @file_get_contents($file);
            if ($code === false) {
                $errors[] = sprintf('%s: cannot be read', $file);
                continue;
            }
            $sources[$file] = $code;
        }

        $uses = [];
        $marks = [];
        $versions = [];
        $parsed = [];

        foreach ($sources as $file => $code) {
            try {
                [$found, $version] = Extractor::run($file, $code, $pin);
            } catch (ParseError $e) {
                $errors[] = sprintf('%s:%d: syntax error: %s', $file, $e->getStartLine(), $e->getRawMessage());
                continue;
            }
            $uses = [...$uses, ...$found];
            $marks[$file] = Suppress::marks($code);
            $versions[$version] = ($versions[$version] ?? 0) + 1;
            $parsed[$file] = $code;
        }

        $flows = [];
        if ($taint && $parsed !== []) {
            $helpers = Helpers::build($parsed, $pin);
            foreach ($parsed as $file => $code) {
                try {
                    [$found] = Analyzer::run($file, $code, $helpers, $pin);
                    $flows = [...$flows, ...$found];
                } catch (ParseError) {
                    // Already reported by the extraction pass above.
                    continue;
                }
            }
        }

        return new Analysis($uses, $flows, $errors, $marks, count($parsed), $versions, count($files));
    }
}
