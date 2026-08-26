<?php

declare(strict_types=1);

namespace Frost\Cli;

use Frost\Baseline;
use Frost\Capabilities;
use Frost\Changed;
use Frost\Check;
use Frost\Composer\Deps;
use Frost\Init;
use Frost\Policy\Parser;
use Frost\Policy\Policy;
use Frost\Policy\PolicyError;
use Frost\Report\Report;
use Frost\Runner;
use Frost\Version;

/**
 * The command line.
 *
 * Exit 0 clean, 1 on a finding, 2 on an error. An error is never silence: a
 * file that cannot be parsed is reported and fails, because a security check
 * that quietly skips what it could not read is worse than no check at all.
 */
final class Main
{
    public const OK = 0;
    public const FOUND = 1;
    public const ERROR = 2;

    public const POLICY_FILE = 'frostphp.policy';

    /** @param list<string> $argv */
    public static function run(array $argv, $out = STDOUT, $err = STDERR): int
    {
        try {
            $options = Options::parse($argv);
        } catch (UsageError $e) {
            fwrite($err, 'frostphp: ' . $e->getMessage() . "\n");

            return self::ERROR;
        }

        return match ($options->command) {
            'help' => self::help($out),
            'version' => self::version($out),
            'capabilities' => self::capabilities($out),
            'explain' => self::explain($options, $out, $err),
            'summary' => self::summary($options, $out, $err),
            'init' => self::init($options, $out, $err),
            'audit' => self::audit($options, $out, $err),
            'deps' => self::deps($options, $out, $err),
            default => self::check($options, $out, $err),
        };
    }

    // ---- the gate -------------------------------------------------------

    private static function check(Options $options, $out, $err): int
    {
        $policyPath = $options->policy ?? self::findPolicy($options->paths[0] ?? '.');
        if ($policyPath === null) {
            fwrite($err, "frostphp: no frostphp.policy found.\n");
            fwrite($err, "  Write one with:  frostphp init " . implode(' ', $options->paths) . " > frostphp.policy\n");
            fwrite($err, "  Or audit without one:  frostphp audit " . implode(' ', $options->paths) . "\n");

            return self::ERROR;
        }

        try {
            $policy = Parser::load($policyPath);
        } catch (PolicyError $e) {
            fwrite($err, sprintf("frostphp: %s: %s\n", $policyPath, $e->getMessage()));

            return self::ERROR;
        }

        $analysis = Runner::analyze($options->paths, $options->php, $options->extensions, $options->vendor, !$options->noTaint);

        $changed = $options->diff !== null ? Changed::since($options->diff) : null;
        $findings = Check::findings($analysis, $policy, $options->today, $changed);

        if ($options->updateBaseline) {
            $path = $options->baseline ?? 'frostphp-baseline.txt';
            Baseline::write($path, $findings);
            fwrite($out, sprintf("%d finding%s recorded in %s\n", count($findings), count($findings) === 1 ? '' : 's', $path));

            return self::OK;
        }

        if ($options->baseline !== null) {
            $findings = Baseline::load($options->baseline)->filter($findings);
        }

        fwrite($out, Report::emit($options->format, $findings, $analysis->files, count($analysis->errors)));

        foreach ($analysis->errors as $error) {
            fwrite($err, 'frostphp: ' . $error . "\n");
        }
        self::warnExpiring($policy, $options->today, $err);

        if ($analysis->errors !== []) {
            return self::ERROR;
        }

        return $findings === [] ? self::OK : self::FOUND;
    }

    private static function warnExpiring(Policy $policy, ?string $today, $err): void
    {
        foreach ($policy->expiring($today) as [$rule, $days]) {
            if ($days < 0) {
                fwrite($err, sprintf("frostphp: the grant on policy line %d lapsed %d day%s ago: %s\n", $rule->line, -$days, $days === -1 ? '' : 's', $rule->describe()));
            } else {
                fwrite($err, sprintf("frostphp: the grant on policy line %d lapses in %d day%s: %s\n", $rule->line, $days, $days === 1 ? '' : 's', $rule->describe()));
            }
        }
    }

    // ---- the other commands ---------------------------------------------

    private static function init(Options $options, $out, $err): int
    {
        $analysis = Runner::analyze($options->paths, $options->php, $options->extensions, $options->vendor);
        fwrite($out, Init::fromAnalysis($analysis, $options->name));
        foreach ($analysis->errors as $error) {
            fwrite($err, 'frostphp: ' . $error . "\n");
        }

        return $analysis->errors === [] ? self::OK : self::ERROR;
    }

    /** No policy: what does this code reach for? */
    private static function audit(Options $options, $out, $err): int
    {
        $analysis = Runner::analyze($options->paths, $options->php, $options->extensions, $options->vendor);

        $counts = [];
        $topLevel = [];
        foreach ($analysis->uses as $use) {
            $counts[$use->capability] = ($counts[$use->capability] ?? 0) + 1;
            if ($use->topLevel) {
                $topLevel[$use->capability] = ($topLevel[$use->capability] ?? 0) + 1;
            }
        }
        ksort($counts);

        fwrite($out, sprintf("%d file%s\n", $analysis->files, $analysis->files === 1 ? '' : 's'));
        $legacy = $analysis->legacyFiles();
        if ($legacy > 0) {
            fwrite($out, sprintf("%d of them needed the PHP 5 dialect to parse.\n", $legacy));
        }
        fwrite($out, "\nWHAT THIS CODE CAN DO\n\n");
        if ($counts === []) {
            fwrite($out, "  nothing\n");
        }
        foreach ($counts as $capability => $count) {
            $eager = $topLevel[$capability] ?? 0;
            fwrite($out, sprintf(
                "  %-28s %4d%s\n",
                $capability,
                $count,
                $eager > 0 ? sprintf('   (%d at include time)', $eager) : ''
            ));
        }

        if ($analysis->flows !== []) {
            fwrite($out, "\nWHERE UNTRUSTED INPUT REACHES IT\n\n");
            foreach ($analysis->flows as $flow) {
                fwrite($out, sprintf("  %s:%d  %s\n", $flow->file, $flow->line, $flow->message()));
            }
        }

        foreach ($analysis->errors as $error) {
            fwrite($err, 'frostphp: ' . $error . "\n");
        }

        return self::OK;
    }

    /** What runs at install, and what runs on every request. */
    private static function deps(Options $options, $out, $err): int
    {
        $root = $options->arguments[0] ?? '.';
        $result = Deps::audit($root);

        if ($result['packages'] === 0) {
            fwrite($err, sprintf("frostphp: no installed packages found under %s/vendor\n", rtrim($root, '/')));

            return self::ERROR;
        }

        fwrite($out, sprintf("%d packages, %d files\n", $result['packages'], $result['files']));

        fwrite($out, "\nRUNS AT INSTALL TIME\n\n");
        if ($result['scripts'] === []) {
            fwrite($out, "  nothing\n");
        }
        foreach ($result['scripts'] as [$package, $hook, $command]) {
            fwrite($out, sprintf("  %-28s %-22s %s\n", $package, $hook, $command));
        }

        fwrite($out, "\nRUNS ON EVERY REQUEST, BEFORE YOUR CODE\n");
        fwrite($out, "(composer autoload.files entries, at their top level)\n\n");
        if ($result['eager'] === []) {
            fwrite($out, "  nothing\n");
        }
        foreach ($result['eager'] as [$package, $use]) {
            fwrite($out, sprintf("  %-24s %s %s:%d: %s\n", $package, $use->capability, $use->file, $use->line, $use->expression));
        }

        if ($result['findings'] !== []) {
            fwrite($out, sprintf("\nRUNS WHEN THE FILE IS INCLUDED (%d)\n\n", count($result['findings'])));
            foreach (array_slice($result['findings'], 0, 40) as [$package, $use]) {
                fwrite($out, sprintf("  %-24s %s %s:%d\n", $package, $use->capability, $use->file, $use->line));
            }
            if (count($result['findings']) > 40) {
                fwrite($out, sprintf("  ... and %d more (--format json for all)\n", count($result['findings']) - 40));
            }
        }

        return self::OK;
    }

    private static function summary(Options $options, $out, $err): int
    {
        $path = $options->policy ?? self::findPolicy($options->paths[0] ?? '.');
        if ($path === null) {
            fwrite($err, "frostphp: no frostphp.policy found\n");

            return self::ERROR;
        }
        try {
            fwrite($out, Parser::load($path)->summary());
        } catch (PolicyError $e) {
            fwrite($err, sprintf("frostphp: %s: %s\n", $path, $e->getMessage()));

            return self::ERROR;
        }

        return self::OK;
    }

    private static function explain(Options $options, $out, $err): int
    {
        $what = $options->arguments[0] ?? null;
        if ($what === null) {
            fwrite($err, "frostphp: explain what? try `frostphp capabilities`\n");

            return self::ERROR;
        }
        $text = Capabilities::explain($what);
        if ($text === null) {
            fwrite($err, sprintf("frostphp: no capability called \"%s\". Try `frostphp capabilities`.\n", $what));

            return self::ERROR;
        }
        fwrite($out, $text . "\n");

        return self::OK;
    }

    private static function capabilities($out): int
    {
        foreach (Capabilities::FAMILIES as $family) {
            fwrite($out, sprintf("%s - %s\n", $family, Capabilities::FAMILY_SUMMARY[$family] ?? ''));
            foreach (Capabilities::membersOf($family) as $member) {
                fwrite($out, sprintf("    %-30s %s\n", $member, Capabilities::TRIGGERS[$member] ?? ''));
            }
            fwrite($out, "\n");
        }
        fwrite($out, "A policy may name a family or one member. A family grant covers its\nmembers; a member grant does not cover the family.\n");

        return self::OK;
    }

    private static function version($out): int
    {
        fwrite($out, 'frostphp ' . Version::VERSION . "\n");

        return self::OK;
    }

    private static function help($out): int
    {
        fwrite($out, <<<TEXT
        frostphp - a deny-by-default capability linter for PHP

        USAGE
          frostphp <paths>                 check against the nearest frostphp.policy
          frostphp init <paths>            write a policy granting what the code does today
          frostphp audit <paths>           no policy: what does this code reach for?
          frostphp deps [root]             what runs at install, and on every request
          frostphp summary                 the policy in plain English
          frostphp explain <capability>    what it is, and how to grant it
          frostphp capabilities            the taxonomy

        OPTIONS
          --policy <file>       use this policy instead of searching for one
          --format <f>          text (default), json, sarif, github
          --baseline <file>     report only findings not in the baseline
          --update-baseline     record today's findings instead of failing on them
          --diff <ref>          judge only lines this branch changed
          --php <version>       pin the parser (default: try 8.5, fall back to 5.6)
          --ext <list>          file extensions to read (default: php,phtml,inc,...)
          --include-vendor      do not skip vendor/
          --no-taint            capabilities only, no flow analysis
          --name <name>         the policy name for `init`
          --today <date>        treat this as today, for `until` grants

        EXIT
          0 clean, 1 a finding, 2 an error

        TEXT);

        return self::OK;
    }

    private static function findPolicy(string $start): ?string
    {
        $dir = is_dir($start) ? $start : dirname($start);
        $dir = realpath($dir);
        if ($dir === false) {
            return null;
        }
        while (true) {
            $candidate = $dir . DIRECTORY_SEPARATOR . self::POLICY_FILE;
            if (is_file($candidate)) {
                return $candidate;
            }
            $parent = dirname($dir);
            if ($parent === $dir) {
                return null;
            }
            $dir = $parent;
        }
    }
}
