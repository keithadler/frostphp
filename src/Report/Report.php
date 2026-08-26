<?php

declare(strict_types=1);

namespace Frost\Report;

use Frost\Version;

/**
 * Output formats: text for people, json for tooling, sarif for code scanning,
 * github for annotations on the pull request that introduced the line.
 */
final class Report
{
    /** @param list<Finding> $findings */
    public static function emit(string $format, array $findings, int $files, int $errors = 0): string
    {
        return match ($format) {
            'json' => self::json($findings, $files),
            'sarif' => self::sarif($findings, $files),
            'github' => self::github($findings),
            default => self::text($findings, $files, $errors),
        };
    }

    /** @param list<Finding> $findings */
    public static function text(array $findings, int $files, int $errors = 0): string
    {
        $out = '';
        foreach ($findings as $f) {
            $out .= sprintf(
                "%s:%d:%d: %s: %s\n",
                $f->file,
                $f->line,
                $f->column,
                $f->message,
                $f->expression
            );
        }
        $denied = self::count($findings, Finding::DENIED);
        $flows = self::count($findings, Finding::TAINT);

        $tail = sprintf("\n%d file%s, %d denied", $files, $files === 1 ? '' : 's', $denied);
        if ($flows > 0) {
            $tail .= sprintf(', %d taint flow%s', $flows, $flows === 1 ? '' : 's');
        }
        if ($errors > 0) {
            $tail .= sprintf(', %d error%s', $errors, $errors === 1 ? '' : 's');
        }

        return $out . $tail . "\n";
    }

    /** @param list<Finding> $findings */
    private static function json(array $findings, int $files): string
    {
        $payload = [
            'version' => Version::VERSION,
            'files' => $files,
            'findings' => array_map(static fn (Finding $f): array => [
                'kind' => $f->kind,
                'rule' => $f->ruleId(),
                'file' => $f->file,
                'line' => $f->line,
                'column' => $f->column,
                'message' => $f->message,
                'expression' => $f->expression,
                'fingerprint' => $f->fingerprint(),
            ], $findings),
        ];

        return json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
    }

    /** @param list<Finding> $findings */
    private static function sarif(array $findings, int $files): string
    {
        $rules = [];
        $results = [];
        foreach ($findings as $f) {
            $level = $f->kind === Finding::TAINT ? 'error' : 'warning';
            $rules[$f->ruleId()] ??= [
                'id' => $f->ruleId(),
                'shortDescription' => ['text' => $f->code],
                'defaultConfiguration' => ['level' => $level],
            ];
            $results[] = [
                'ruleId' => $f->ruleId(),
                'level' => $level,
                'message' => ['text' => $f->message . ': ' . $f->expression],
                'locations' => [[
                    'physicalLocation' => [
                        'artifactLocation' => ['uri' => $f->file],
                        'region' => ['startLine' => max($f->line, 1), 'startColumn' => max($f->column + 1, 1)],
                    ],
                ]],
                'partialFingerprints' => ['frostphp/v1' => $f->fingerprint()],
            ];
        }

        return json_encode([
            '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json',
            'version' => '2.1.0',
            'runs' => [[
                'tool' => ['driver' => [
                    'name' => 'frostphp',
                    'version' => Version::VERSION,
                    'informationUri' => 'https://github.com/keithadler/frostphp',
                    'rules' => array_values($rules),
                ]],
                'results' => $results,
            ]],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
    }

    /** @param list<Finding> $findings */
    private static function github(array $findings): string
    {
        $out = '';
        foreach ($findings as $f) {
            $level = $f->kind === Finding::TAINT ? 'error' : 'warning';
            $out .= sprintf(
                "::%s file=%s,line=%d,col=%d::%s: %s\n",
                $level,
                $f->file,
                max($f->line, 1),
                max($f->column + 1, 1),
                self::escape($f->message),
                self::escape($f->expression)
            );
        }

        return $out;
    }

    private static function escape(string $text): string
    {
        return str_replace(["\r", "\n", '%'], ['', ' ', '%25'], $text);
    }

    /** @param list<Finding> $findings */
    private static function count(array $findings, string $kind): int
    {
        return count(array_filter($findings, static fn (Finding $f): bool => $f->kind === $kind));
    }
}
