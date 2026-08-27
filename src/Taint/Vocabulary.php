<?php

declare(strict_types=1);

namespace Frost\Taint;

/**
 * Where untrusted values come from, what makes them safe, and where they must
 * not end up.
 *
 * PHP is unusually good to a taint analysis here: the sources are not a guess.
 * `$_GET` is untrusted by definition, in every framework and none, and has been
 * since PHP 4.1. The legacy `$HTTP_*_VARS` aliases are listed beside them
 * because the code that still uses those names is exactly the code most likely
 * to concatenate them into a query.
 */
final class Vocabulary
{
    /** Superglobals and their pre-4.1 aliases. @var array<string, true> */
    public const SUPERGLOBALS = [
        '_GET' => true, '_POST' => true, '_REQUEST' => true, '_COOKIE' => true,
        '_FILES' => true, '_SERVER' => true, '_ENV' => true, 'argv' => true,
        'HTTP_GET_VARS' => true, 'HTTP_POST_VARS' => true, 'HTTP_COOKIE_VARS' => true,
        'HTTP_SERVER_VARS' => true, 'HTTP_POST_FILES' => true, 'HTTP_ENV_VARS' => true,
        'HTTP_RAW_POST_DATA' => true,
    ];

    /**
     * Keys of `$_SERVER` the web server fills in, not the client.
     *
     * `$_SERVER` is not one thing. `HTTP_*`, `QUERY_STRING` and `REQUEST_URI`
     * come off the wire and are attacker-controlled; `REMOTE_ADDR` comes from
     * the TCP connection and `DOCUMENT_ROOT` from the configuration, and no
     * request can change either. Treating the whole array as untrusted puts a
     * header-injection finding on `header($_SERVER['SERVER_PROTOCOL'] . ' 200
     * OK')`, which is in a great many codebases and is not a bug.
     *
     * `SERVER_NAME` is deliberately absent: with `UseCanonicalName Off` Apache
     * fills it from the Host header, so it can be attacker-controlled.
     *
     * @var array<string, true>
     */
    public const TRUSTED_SERVER_KEYS = [
        'SERVER_PROTOCOL' => true, 'SERVER_ADDR' => true, 'SERVER_PORT' => true,
        'SERVER_SOFTWARE' => true, 'SERVER_ADMIN' => true, 'GATEWAY_INTERFACE' => true,
        'DOCUMENT_ROOT' => true, 'SCRIPT_FILENAME' => true, 'SCRIPT_NAME' => true,
        'REMOTE_ADDR' => true, 'REMOTE_PORT' => true,
        'REQUEST_TIME' => true, 'REQUEST_TIME_FLOAT' => true,
    ];

    /**
     * Keys of a `$_FILES` entry that PHP generates rather than the uploader.
     *
     * `name` and `type` are strings the browser sent and are attacker-chosen.
     * `tmp_name` is a path PHP made up, and `size` and `error` are integers it
     * computed, so `unlink($file['tmp_name'])` is not a traversal.
     *
     * @var array<string, true>
     */
    public const TRUSTED_FILE_KEYS = [
        'tmp_name' => true, 'size' => true, 'error' => true, 'full_path' => false,
    ];

    /** Functions that hand back untrusted input. @var array<string, true> */
    public const SOURCE_CALLS = [
        'getallheaders' => true,
        'apache_request_headers' => true,
        'getopt' => true,
        'get_headers' => true,
    ];

    /** Objects whose accessors are request data. @var array<string, true> */
    public const REQUEST_RECEIVERS = [
        'request' => true, 'req' => true, 'input' => true,
    ];

    /**
     * Symfony reaches request data through a bag, not through the request.
     *
     *     $request->query->get('id')      not $request->get('id')
     *     $request->headers->get('X')
     *
     * So the receiver of the accessor is a property of the request, and a rule
     * that only looks at the receiver's own name sees an object called `query`
     * and stays quiet - which is what frostphp did until this was tested.
     *
     * @var array<string, true>
     */
    public const REQUEST_BAGS = [
        'query' => true, 'request' => true, 'headers' => true, 'cookies' => true,
        'attributes' => true, 'files' => true, 'server' => true, 'json' => true,
    ];

    /**
     * Query-builder methods that take SQL rather than a bound value.
     *
     * Unlike `->query()`, these names are unambiguous: `whereRaw` means one
     * thing in Laravel and nothing at all anywhere else, so they can be matched
     * on the method name without knowing the receiver. `Raw` in the name is the
     * framework telling you the escaping is now your problem.
     *
     * @var array<string, true>
     */
    public const RAW_SQL_METHODS = [
        'whereraw' => true, 'orwhereraw' => true, 'havingraw' => true,
        'orhavingraw' => true, 'selectraw' => true, 'orderbyraw' => true,
        'groupbyraw' => true, 'fromraw' => true, 'joinraw' => true,
        // `statement` and `unprepared` are deliberately absent. They are real
        // Laravel query methods, but the names are far too ordinary to match on
        // an unknown receiver - frostphp's own `$this->statement($child)` tree
        // walk was reported as SQL until this list was trimmed. They are still
        // caught on the facade, where the class is known: `DB::statement(...)`.
    ];

    /** Request accessor methods, Laravel and Symfony both. @var array<string, true> */
    public const REQUEST_METHODS = [
        'input' => true, 'query' => true, 'post' => true, 'all' => true, 'only' => true,
        'except' => true, 'get' => true, 'header' => true, 'cookie' => true, 'file' => true,
        'getcontent' => true, 'getquerystring' => true, 'getrequesturi' => true,
    ];

    /**
     * Sanitizers, and the sink classes each one actually makes safe.
     *
     * Read the gaps, not the entries. `htmlspecialchars` is absent from `sql`
     * because it does nothing for a query, and `mysqli_real_escape_string` is
     * absent from `html` for the same reason in reverse. Both mistakes are
     * common and both are exploitable.
     *
     * @var array<string, list<string>>
     */
    public const SANITIZERS = [
        // Numbers are safe everywhere: there is no injection in an integer.
        'intval' => ['*'],
        'floatval' => ['*'],
        'doubleval' => ['*'],
        'abs' => ['*'],
        'round' => ['*'],
        'ceil' => ['*'],
        'floor' => ['*'],
        'md5' => ['*'],
        'sha1' => ['*'],
        'crc32' => ['*'],
        'hash' => ['*'],
        'bin2hex' => ['*'],
        'uniqid' => ['*'],
        // Shell
        'escapeshellarg' => ['command'],
        'escapeshellcmd' => ['command'],
        // SQL - and only in a quoted context; Sql::inspect enforces that.
        'mysql_real_escape_string' => ['sql'],
        'mysql_escape_string' => ['sql'],
        'mysqli_real_escape_string' => ['sql'],
        'mysqli_escape_string' => ['sql'],
        'pg_escape_string' => ['sql'],
        'pg_escape_literal' => ['sql'],
        'pg_escape_identifier' => ['sql'],
        'sqlite_escape_string' => ['sql'],
        'esc_sql' => ['sql'],
        // Markup
        'htmlspecialchars' => ['html'],
        'htmlentities' => ['html'],
        'strip_tags' => ['html'],
        'esc_html' => ['html'],
        'esc_attr' => ['html'],
        'esc_textarea' => ['html'],
        'e' => ['html'],
        'sanitize_text_field' => ['html'],
        'json_encode' => ['html'],
        // Paths
        'basename' => ['path'],
        // URLs and headers
        'urlencode' => ['header', 'path'],
        'rawurlencode' => ['header', 'path'],
        'esc_url' => ['html', 'header'],
        'esc_url_raw' => ['header'],
    ];

    /**
     * Functions that look like sanitizers and are not.
     *
     * `addslashes` is the one that matters. It was the house style of an entire
     * generation of PHP, it is still in the code, and it does not stop SQL
     * injection: it is bypassable on multi-byte connection charsets, and it
     * does nothing at all when the value lands outside quotes - `LIMIT $n`,
     * `ORDER BY $col`, `WHERE id = $id`. frostphp lets taint pass straight
     * through it and says so in the finding.
     *
     * @var array<string, string>
     */
    public const FALSE_FRIENDS = [
        'addslashes' => 'addslashes does not stop SQL injection: it is bypassable on multi-byte charsets and useless outside quotes',
        'addcslashes' => 'addcslashes escapes for C string syntax, not for SQL or HTML',
        'stripslashes' => 'stripslashes removes escaping - it makes a value less safe, not more',
        'quotemeta' => 'quotemeta escapes regex metacharacters only',
        'trim' => 'trim removes whitespace; it validates nothing',
        'strtolower' => 'strtolower changes case; it validates nothing',
        'strtoupper' => 'strtoupper changes case; it validates nothing',
        'ucfirst' => 'ucfirst changes case; it validates nothing',
        'substr' => 'substr shortens a value; it validates nothing',
        'str_replace' => 'str_replace is a blocklist unless you can prove it covers every case',
        'utf8_decode' => 'utf8_decode can turn a safe value back into a dangerous one',
        'mysql_escape_string_deprecated_alias' => 'not a sanitizer',
    ];

    /**
     * Decoders. A decoder inside a code or command sink is the shape of every
     * PHP web shell ever written, taint or no taint.
     *
     * @var array<string, true>
     */
    public const DECODERS = [
        'base64_decode' => true, 'gzinflate' => true, 'gzuncompress' => true,
        'gzdecode' => true, 'str_rot13' => true, 'hex2bin' => true,
        'convert_uudecode' => true, 'strrev' => true, 'pack' => true,
        'urldecode' => true, 'rawurldecode' => true,
    ];

    /**
     * Sinks: function name => [class, argument indexes that matter].
     *
     * An empty index list means every argument.
     *
     * @var array<string, array{string, list<int>}>
     */
    public const SINKS = [
        // running a program
        'exec' => ['command', [0]],
        'shell_exec' => ['command', [0]],
        'system' => ['command', [0]],
        'passthru' => ['command', [0]],
        'proc_open' => ['command', [0]],
        'popen' => ['command', [0]],
        'pcntl_exec' => ['command', [0, 1]],
        // turning data into code
        'create_function' => ['code', [0, 1]],
        'assert' => ['code', [0]],
        'call_user_func' => ['code', [0]],
        'call_user_func_array' => ['code', [0]],
        // SQL
        'mysql_query' => ['sql', [0]],
        'mysql_db_query' => ['sql', [1]],
        'mysql_unbuffered_query' => ['sql', [0]],
        'mysqli_query' => ['sql', [1]],
        'mysqli_real_query' => ['sql', [1]],
        'mysqli_multi_query' => ['sql', [1]],
        'mysqli_prepare' => ['sql', [1]],
        'pg_query' => ['sql', [0, 1]],
        'pg_send_query' => ['sql', [1]],
        'sqlite_query' => ['sql', [0, 1]],
        'sqlite_unbuffered_query' => ['sql', [0, 1]],
        'sqlsrv_query' => ['sql', [1]],
        'oci_parse' => ['sql', [1]],
        'db2_exec' => ['sql', [1]],
        // deserialization
        'unserialize' => ['object', [0]],
        'yaml_parse' => ['object', [0]],
        // the file system
        'file_get_contents' => ['path', [0]],
        'file_put_contents' => ['path', [0]],
        'fopen' => ['path', [0]],
        'readfile' => ['path', [0]],
        'file' => ['path', [0]],
        'unlink' => ['path', [0]],
        'rmdir' => ['path', [0]],
        'mkdir' => ['path', [0]],
        'rename' => ['path', [0, 1]],
        'copy' => ['path', [0, 1]],
        'move_uploaded_file' => ['path', [1]],
        'glob' => ['path', [0]],
        // the response
        'header' => ['header', [0]],
        // setcookie() URL-encodes the value it sends, so a newline in it can
        // never reach the response header. setrawcookie() is the one that does
        // not, and is why the two are listed apart.
        'setcookie' => ['header', [0]],
        'setrawcookie' => ['header', [0, 1]],
        // mail
        'mail' => ['mail', [0, 1, 3, 4]],
        // markup
        'print_r' => ['html', [0]],
        'var_dump' => ['html', []],
        'printf' => ['html', [0]],
        'vprintf' => ['html', [0]],
        // directory services
        'ldap_search' => ['ldap', [2]],
        'ldap_list' => ['ldap', [2]],
        'ldap_read' => ['ldap', [2]],
        // requests made on the server's behalf
        'curl_setopt' => ['ssrf', [2]],
        'fsockopen' => ['ssrf', [0]],
        'stream_socket_client' => ['ssrf', [0]],
        'get_headers' => ['ssrf', [0]],
    ];

    /** How each sink class reads in a report. @var array<string, string> */
    public const KIND_LABEL = [
        'sql' => 'SQL injection',
        'command' => 'command injection',
        'code' => 'code injection',
        'inclusion' => 'file inclusion',
        'object' => 'object injection',
        'path' => 'path traversal',
        'html' => 'cross-site scripting',
        'header' => 'header injection',
        'mail' => 'mail header injection',
        'ldap' => 'LDAP injection',
        'ssrf' => 'server-side request forgery',
        'exfiltration' => 'exfiltration',
        'obfuscation' => 'obfuscated payload',
        'scope' => 'variable overwrite',
    ];

    /** Bulk secret reads - the whole environment, not one named key. @var array<string, true> */
    public const BULK_SECRETS = [
        '_ENV' => true, '_SERVER' => true, 'GLOBALS' => true,
    ];

    /** @var array<string, true> */
    public const SECRET_CALLS = [
        'get_defined_vars' => true, 'php_uname' => true, 'phpinfo' => true,
        'getcwd' => true, 'posix_getpwuid' => true,
    ];

    /** Where exfiltrated data goes. @var array<string, true> */
    public const EGRESS = [
        'curl_setopt' => true, 'curl_exec' => true, 'curl_setopt_array' => true,
        'file_get_contents' => true, 'fsockopen' => true, 'stream_socket_client' => true,
        'mail' => true, 'fwrite' => true, 'get_headers' => true,
    ];
}
