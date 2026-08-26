<?php

declare(strict_types=1);

namespace Frost\Cli;

use Frost\Discover;
use Frost\Source;

/** The command line, parsed. */
final class Options
{
    /** @var list<string> */
    public array $paths = [];

    public string $command = 'check';

    public string $format = 'text';

    public ?string $policy = null;

    public ?string $baseline = null;

    public bool $updateBaseline = false;

    public ?string $diff = null;

    public ?string $php = null;

    /** @var list<string> */
    public array $extensions = Discover::EXTENSIONS;

    public bool $vendor = false;

    public bool $noTaint = false;

    public string $name = 'app';

    public ?string $today = null;

    /** @var list<string> */
    public array $arguments = [];

    public const COMMANDS = ['check', 'init', 'audit', 'deps', 'explain', 'capabilities', 'summary', 'version', 'help'];

    /**
     * @param list<string> $argv
     *
     * @throws UsageError
     */
    public static function parse(array $argv): self
    {
        $options = new self();
        $rest = [];

        for ($i = 0; $i < count($argv); $i++) {
            $arg = $argv[$i];
            $next = static function () use ($argv, &$i, $arg): string {
                $value = $argv[++$i] ?? null;
                if ($value === null) {
                    throw new UsageError(sprintf('%s needs a value', $arg));
                }

                return $value;
            };

            match (true) {
                $arg === '--format' => $options->format = $next(),
                str_starts_with($arg, '--format=') => $options->format = substr($arg, 9),
                $arg === '--policy' => $options->policy = $next(),
                str_starts_with($arg, '--policy=') => $options->policy = substr($arg, 9),
                $arg === '--baseline' => $options->baseline = $next(),
                str_starts_with($arg, '--baseline=') => $options->baseline = substr($arg, 11),
                $arg === '--update-baseline' => $options->updateBaseline = true,
                $arg === '--diff' => $options->diff = $next(),
                str_starts_with($arg, '--diff=') => $options->diff = substr($arg, 7),
                $arg === '--php' => $options->php = $next(),
                str_starts_with($arg, '--php=') => $options->php = substr($arg, 6),
                $arg === '--ext' => $options->extensions = self::extensions($next()),
                str_starts_with($arg, '--ext=') => $options->extensions = self::extensions(substr($arg, 6)),
                $arg === '--include-vendor' => $options->vendor = true,
                $arg === '--no-taint' => $options->noTaint = true,
                $arg === '--name' => $options->name = $next(),
                str_starts_with($arg, '--name=') => $options->name = substr($arg, 7),
                $arg === '--today' => $options->today = $next(),
                str_starts_with($arg, '--today=') => $options->today = substr($arg, 8),
                $arg === '-h', $arg === '--help' => $options->command = 'help',
                $arg === '-V', $arg === '--version' => $options->command = 'version',
                str_starts_with($arg, '-') => throw new UsageError(sprintf('unknown option %s', $arg)),
                default => $rest[] = $arg,
            };
        }

        if ($options->command === 'help' || $options->command === 'version') {
            return $options;
        }

        if ($rest !== [] && in_array($rest[0], self::COMMANDS, true)) {
            $options->command = array_shift($rest);
        }
        $options->arguments = $rest;
        $options->paths = $rest === [] ? ['.'] : $rest;

        if (!in_array($options->format, ['text', 'json', 'sarif', 'github'], true)) {
            throw new UsageError(sprintf('unknown format "%s" (text, json, sarif, github)', $options->format));
        }
        if ($options->php !== null && !Source::supports($options->php)) {
            throw new UsageError(sprintf('unknown PHP version "%s"', $options->php));
        }
        if ($options->today !== null && preg_match('/^\d{4}-\d{2}-\d{2}$/', $options->today) !== 1) {
            throw new UsageError('--today needs a YYYY-MM-DD date');
        }

        return $options;
    }

    /** @return list<string> */
    private static function extensions(string $raw): array
    {
        $out = [];
        foreach (explode(',', $raw) as $part) {
            $part = strtolower(trim($part, " \t."));
            if ($part !== '') {
                $out[] = $part;
            }
        }

        return $out === [] ? Discover::EXTENSIONS : $out;
    }
}
