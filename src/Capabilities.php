<?php

declare(strict_types=1);

namespace Frost;

/**
 * The capability taxonomy: what a PHP program can reach for.
 *
 * Codes are `family.member`. A policy may name a family (`may use the network`)
 * or a single member (`network.curl`). This file is the single source of truth:
 * `frostphp capabilities`, docs/CAPABILITIES.md and the README table are all
 * generated from it, and CapabilitiesTest fails if it drifts from the codes the
 * recognizers actually emit.
 *
 * Three families here exist because PHP has hazards no other language has, and
 * folding them into a generic bucket would lose the point:
 *
 *   include      `include $page` is remote code execution, not modularity.
 *   scope        `extract($_GET)` rewrites the local variables from a request.
 *   filesystem.wrapper   `phar://` makes every file function a deserializer.
 */
final class Capabilities
{
    /** @var list<string> */
    public const FAMILIES = [
        'codegen',
        'process',
        'network',
        'filesystem',
        'include',
        'deserialize',
        'scope',
        'native',
        'env',
        'response',
        'database',
    ];

    /** @var list<string> */
    public const MEMBER_CODES = [
        // codegen: turning data into code
        'codegen.eval',
        'codegen.create_function',
        'codegen.assert',
        'codegen.preg',
        'codegen.dynamic',
        // process: running another program
        'process.exec',
        'process.proc',
        'process.backtick',
        'process.pcntl',
        // network: reaching off the machine
        'network.curl',
        'network.socket',
        'network.url',
        'network.mail',
        'network.dns',
        // filesystem: reading and writing outside memory
        'filesystem.read',
        'filesystem.write',
        'filesystem.delete',
        'filesystem.wrapper',
        // include: choosing code at runtime
        'include.dynamic',
        'include.autoload',
        // deserialize: trusting bytes enough to build objects from them
        'deserialize.unserialize',
        'deserialize.phar',
        'deserialize.yaml',
        'deserialize.xml',
        // scope: rewriting the variable scope from data
        'scope.extract',
        'scope.variable',
        'scope.parse_str',
        // native: leaving the engine
        'native.ffi',
        'native.dl',
        // env: the ambient world
        'env.read',
        'env.write',
        'env.ini',
        // response: controlling what goes back to the browser
        'response.header',
        'response.cookie',
        'response.session',
        // database: talking to a data store
        'database.connect',
        'database.query',
    ];

    /**
     * Plain-English phrases a policy author may write, mapped to a code.
     *
     * These are what makes a policy readable by someone who does not write PHP,
     * which is the person who most needs to sign off on what an application may
     * do.
     *
     * @var array<string, string>
     */
    public const PHRASES = [
        'everything' => '*',
        // codegen
        'code generation' => 'codegen',
        'eval' => 'codegen.eval',
        'dynamic calls' => 'codegen.dynamic',
        'variable functions' => 'codegen.dynamic',
        // process
        'shell commands' => 'process',
        'running programs' => 'process',
        'subprocesses' => 'process.proc',
        // network
        'the network' => 'network',
        'network' => 'network',
        'http requests' => 'network.curl',
        'curl' => 'network.curl',
        'sockets' => 'network.socket',
        'sending mail' => 'network.mail',
        'dns lookups' => 'network.dns',
        // filesystem
        'the file system' => 'filesystem',
        'file access' => 'filesystem',
        'reading files' => 'filesystem.read',
        'writing files' => 'filesystem.write',
        'deleting files' => 'filesystem.delete',
        'stream wrappers' => 'filesystem.wrapper',
        // include
        'dynamic includes' => 'include.dynamic',
        'runtime includes' => 'include.dynamic',
        'autoloaders' => 'include.autoload',
        // deserialize
        'deserialization' => 'deserialize',
        'unserialize' => 'deserialize.unserialize',
        'phar' => 'deserialize.phar',
        'yaml loading' => 'deserialize.yaml',
        'xml entities' => 'deserialize.xml',
        // scope
        'scope injection' => 'scope',
        'extract' => 'scope.extract',
        'variable variables' => 'scope.variable',
        // native
        'native code' => 'native',
        'ffi' => 'native.ffi',
        // env
        'environment variables' => 'env',
        'reading the environment' => 'env.read',
        'writing the environment' => 'env.write',
        'changing php settings' => 'env.ini',
        // response
        'response headers' => 'response.header',
        'setting headers' => 'response.header',
        'cookies' => 'response.cookie',
        'sessions' => 'response.session',
        // database
        'the database' => 'database',
        'database access' => 'database',
        'sql queries' => 'database.query',
        'connecting to a database' => 'database.connect',
    ];

    /** One line per family, for `frostphp capabilities`. @var array<string, string> */
    public const FAMILY_SUMMARY = [
        'codegen' => 'turns data into code: eval, create_function, variable functions',
        'process' => 'runs another program: exec, shell_exec, proc_open, backticks',
        'network' => 'reaches off the machine: curl, sockets, remote URLs, mail',
        'filesystem' => 'opens, writes or removes files, or registers a stream wrapper',
        'include' => 'chooses which file of code to run at runtime',
        'deserialize' => 'builds objects from bytes: unserialize, phar, yaml, XML entities',
        'scope' => 'rewrites the local variables from data: extract, $$name, parse_str',
        'native' => 'leaves the engine: FFI, dl',
        'env' => 'reads or writes the environment, or changes php.ini settings',
        'response' => 'controls the HTTP response: headers, cookies, sessions',
        'database' => 'connects to a data store, or runs a query against one',
    ];

    /** What fires each member code, for `frostphp explain`. @var array<string, string> */
    public const TRIGGERS = [
        'codegen.eval' => 'eval(...)',
        'codegen.create_function' => 'create_function(...)',
        'codegen.assert' => 'assert("...") with a string (evaluated before PHP 8)',
        'codegen.preg' => 'preg_replace with the /e modifier',
        'codegen.dynamic' => '$fn(), $obj->$method(), new $class, call_user_func(...)',
        'process.exec' => 'exec, shell_exec, system, passthru',
        'process.proc' => 'proc_open, popen',
        'process.backtick' => '`command` (the backtick operator)',
        'process.pcntl' => 'pcntl_exec, pcntl_fork',
        'network.curl' => 'curl_init, curl_exec, curl_setopt',
        'network.socket' => 'fsockopen, stream_socket_client, socket_create',
        'network.url' => 'file_get_contents/fopen/readfile on an http, https or ftp URL',
        'network.mail' => 'mail(...)',
        'network.dns' => 'gethostbyname, dns_get_record, checkdnsrr, get_headers',
        'filesystem.read' => 'file_get_contents, fopen, readfile, file, SplFileObject',
        'filesystem.write' => 'file_put_contents, fwrite, copy, rename, mkdir, move_uploaded_file',
        'filesystem.delete' => 'unlink, rmdir',
        'filesystem.wrapper' => 'a php://, data://, zip:// or expect:// path, or stream_wrapper_register',
        'include.dynamic' => 'include / require with anything but a literal path',
        'include.autoload' => 'spl_autoload_register',
        'deserialize.unserialize' => 'unserialize(...)',
        'deserialize.phar' => 'a phar:// path, or new Phar / PharData',
        'deserialize.yaml' => 'yaml_parse, Yaml::parse with PARSE_OBJECT',
        'deserialize.xml' => 'XML parsed with entities enabled (LIBXML_NOENT, libxml_disable_entity_loader(false))',
        'scope.extract' => 'extract(...), import_request_variables(...)',
        'scope.variable' => '$$name or ${$name}',
        'scope.parse_str' => 'parse_str($s) with no result array',
        'native.ffi' => 'FFI::cdef, FFI::load, FFI::scope',
        'native.dl' => 'dl(...)',
        'env.read' => 'getenv, $_ENV, $_SERVER',
        'env.write' => 'putenv',
        'env.ini' => 'ini_set, ini_alter, set_include_path',
        'response.header' => 'header(...), header_remove(...)',
        'response.cookie' => 'setcookie, setrawcookie',
        'response.session' => 'session_start, session_id, session_regenerate_id, session_register',
        'database.connect' => 'new PDO, mysqli_connect, mysql_connect, pg_connect',
        'database.query' => 'PDO::query/exec/prepare, mysqli_query, mysql_query, pg_query',
    ];

    /** Every code a policy may name. @return list<string> */
    public static function known(): array
    {
        return [...self::FAMILIES, ...self::MEMBER_CODES];
    }

    /** The members of a family, in taxonomy order. @return list<string> */
    public static function membersOf(string $family): array
    {
        return array_values(array_filter(
            self::MEMBER_CODES,
            static fn (string $c): bool => str_starts_with($c, $family . '.')
        ));
    }

    /** Resolve a policy phrase or a bare code to a capability code. */
    public static function resolve(string $words): ?string
    {
        $key = strtolower(trim((string) preg_replace('/\s+/', ' ', $words)));

        return self::PHRASES[$key] ?? (in_array($key, self::known(), true) ? $key : null);
    }

    /** Does a granted code cover a used code? `network` covers `network.curl`. */
    public static function covers(string $grant, string $code): bool
    {
        return $grant === '*' || $grant === $code || str_starts_with($code, $grant . '.');
    }

    /** A paragraph about one capability: what it is, what fires it, how to grant it. */
    public static function explain(string $code): ?string
    {
        $resolved = self::resolve($code);
        if ($resolved === null || $resolved === '*') {
            return null;
        }
        $family = explode('.', $resolved)[0];
        $lines = [$resolved, str_repeat('=', strlen($resolved)), ''];

        if (isset(self::FAMILY_SUMMARY[$resolved])) {
            $lines[] = 'Family: ' . self::FAMILY_SUMMARY[$resolved];
            $lines[] = '';
            $lines[] = 'Members:';
            foreach (self::membersOf($resolved) as $member) {
                $lines[] = sprintf('  %-28s %s', $member, self::TRIGGERS[$member] ?? '');
            }
        } else {
            $lines[] = sprintf('Part of `%s`: %s', $family, self::FAMILY_SUMMARY[$family] ?? '');
            $lines[] = '';
            $lines[] = 'Fires on: ' . (self::TRIGGERS[$resolved] ?? 'see docs');
        }

        $phrases = array_keys(array_filter(self::PHRASES, static fn (string $c): bool => $c === $resolved));
        sort($phrases);
        $lines[] = '';
        $lines[] = 'Grant it with:';
        $lines[] = '  may use ' . $resolved;
        foreach ($phrases as $phrase) {
            $lines[] = '  may use ' . $phrase;
        }
        $lines[] = '';
        $lines[] = 'Or refuse it outright:';
        $lines[] = '  forbid ' . $resolved;

        return implode("\n", $lines);
    }
}
