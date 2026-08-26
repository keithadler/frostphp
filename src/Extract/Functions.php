<?php

declare(strict_types=1);

namespace Frost\Extract;

/**
 * The map from a global PHP function to the capability it is.
 *
 * Deliberately weighted towards the PHP that exists rather than the PHP that
 * is taught: `mysql_query`, `create_function`, `import_request_variables` and
 * `ereg` were removed from the language years ago and are still sitting in
 * production files that a modern runtime happily includes. A capability linter
 * that only knows the current manual cannot read the code most in need of a
 * policy.
 */
final class Functions
{
    /** Straightforward name => capability. @var array<string, string> */
    public const SIMPLE = [
        // codegen
        'create_function' => 'codegen.create_function',
        'call_user_func' => 'codegen.dynamic',
        'call_user_func_array' => 'codegen.dynamic',
        'forward_static_call' => 'codegen.dynamic',
        'forward_static_call_array' => 'codegen.dynamic',

        // process
        'exec' => 'process.exec',
        'shell_exec' => 'process.exec',
        'system' => 'process.exec',
        'passthru' => 'process.exec',
        'proc_open' => 'process.proc',
        'popen' => 'process.proc',
        'pcntl_exec' => 'process.pcntl',
        'pcntl_fork' => 'process.pcntl',

        // network
        'curl_init' => 'network.curl',
        'curl_exec' => 'network.curl',
        'curl_setopt' => 'network.curl',
        'curl_setopt_array' => 'network.curl',
        'curl_multi_exec' => 'network.curl',
        'fsockopen' => 'network.socket',
        'pfsockopen' => 'network.socket',
        'stream_socket_client' => 'network.socket',
        'stream_socket_server' => 'network.socket',
        'socket_create' => 'network.socket',
        'socket_connect' => 'network.socket',
        'mail' => 'network.mail',
        'imap_mail' => 'network.mail',
        'gethostbyname' => 'network.dns',
        'gethostbynamel' => 'network.dns',
        'gethostbyaddr' => 'network.dns',
        'dns_get_record' => 'network.dns',
        'checkdnsrr' => 'network.dns',
        'getmxrr' => 'network.dns',
        'get_headers' => 'network.dns',

        // filesystem
        'readfile' => 'filesystem.read',
        'file' => 'filesystem.read',
        'file_put_contents' => 'filesystem.write',
        'fwrite' => 'filesystem.write',
        'fputs' => 'filesystem.write',
        'fputcsv' => 'filesystem.write',
        'copy' => 'filesystem.write',
        'rename' => 'filesystem.write',
        'mkdir' => 'filesystem.write',
        'touch' => 'filesystem.write',
        'symlink' => 'filesystem.write',
        'link' => 'filesystem.write',
        'chmod' => 'filesystem.write',
        'chown' => 'filesystem.write',
        'chgrp' => 'filesystem.write',
        'move_uploaded_file' => 'filesystem.write',
        'unlink' => 'filesystem.delete',
        'rmdir' => 'filesystem.delete',
        'stream_wrapper_register' => 'filesystem.wrapper',
        'stream_wrapper_restore' => 'filesystem.wrapper',
        'stream_wrapper_unregister' => 'filesystem.wrapper',

        // include
        'spl_autoload_register' => 'include.autoload',

        // deserialize
        'unserialize' => 'deserialize.unserialize',
        'yaml_parse' => 'deserialize.yaml',
        'yaml_parse_file' => 'deserialize.yaml',
        'yaml_parse_url' => 'deserialize.yaml',
        'wddx_deserialize' => 'deserialize.unserialize',

        // scope
        'extract' => 'scope.extract',
        'import_request_variables' => 'scope.extract',

        // native
        'dl' => 'native.dl',

        // env
        'getenv' => 'env.read',
        'apache_getenv' => 'env.read',
        'putenv' => 'env.write',
        'apache_setenv' => 'env.write',
        'ini_set' => 'env.ini',
        'ini_alter' => 'env.ini',
        'set_include_path' => 'env.ini',

        // response
        'header' => 'response.header',
        'header_remove' => 'response.header',
        'setcookie' => 'response.cookie',
        'setrawcookie' => 'response.cookie',
        'session_start' => 'response.session',
        'session_id' => 'response.session',
        'session_regenerate_id' => 'response.session',
        'session_set_save_handler' => 'response.session',
        'session_register' => 'response.session',
        'session_unregister' => 'response.session',

        // database: the procedural APIs, which are unambiguous
        'mysql_connect' => 'database.connect',
        'mysql_pconnect' => 'database.connect',
        'mysqli_connect' => 'database.connect',
        'pg_connect' => 'database.connect',
        'pg_pconnect' => 'database.connect',
        'sqlsrv_connect' => 'database.connect',
        'oci_connect' => 'database.connect',
        'oci_pconnect' => 'database.connect',
        'ibm_db2_connect' => 'database.connect',
        'mysql_query' => 'database.query',
        'mysql_db_query' => 'database.query',
        'mysql_unbuffered_query' => 'database.query',
        'mysqli_query' => 'database.query',
        'mysqli_real_query' => 'database.query',
        'mysqli_multi_query' => 'database.query',
        'mysqli_prepare' => 'database.query',
        'pg_query' => 'database.query',
        'pg_query_params' => 'database.query',
        'pg_send_query' => 'database.query',
        'sqlite_query' => 'database.query',
        'sqlite_unbuffered_query' => 'database.query',
        'sqlsrv_query' => 'database.query',
        'oci_parse' => 'database.query',
        'db2_exec' => 'database.query',
    ];

    /**
     * Functions whose capability depends on an argument, handled case by case
     * in the extractor rather than by a lookup.
     *
     * @var array<string, true>
     */
    public const CONTEXTUAL = [
        'fopen' => true,           // mode decides read or write; scheme decides network
        'file_get_contents' => true, // scheme decides filesystem or network
        'assert' => true,          // a string argument was evaluated before PHP 8
        'preg_replace' => true,    // the /e modifier evaluated the replacement
        'parse_str' => true,       // one argument writes into the local scope
        'libxml_disable_entity_loader' => true,
        'simplexml_load_file' => true,
        'simplexml_load_string' => true,
    ];

    /**
     * Functions that take a filesystem path, and which argument it is.
     *
     * The list runs well past the functions that open a file, on purpose. PHP's
     * `phar://` wrapper deserializes the archive's metadata on any operation
     * that merely looks at the path - `file_exists`, `is_file`, `getimagesize`,
     * `filesize` - which turns a stat call into an object-injection sink. A
     * path-taking function is a path-taking function whether or not it reads
     * any bytes.
     *
     * @var array<string, list<int>>
     */
    public const PATH_ARGS = [
        'file_get_contents' => [0], 'file_put_contents' => [0], 'fopen' => [0],
        'readfile' => [0], 'file' => [0], 'unlink' => [0], 'rmdir' => [0],
        'mkdir' => [0], 'rename' => [0, 1], 'copy' => [0, 1], 'move_uploaded_file' => [1],
        'glob' => [0], 'opendir' => [0], 'scandir' => [0], 'touch' => [0],
        'is_file' => [0], 'is_dir' => [0], 'is_link' => [0], 'is_readable' => [0],
        'is_writable' => [0], 'is_writeable' => [0], 'file_exists' => [0],
        'filesize' => [0], 'filemtime' => [0], 'fileatime' => [0], 'filectime' => [0],
        'stat' => [0], 'lstat' => [0], 'fileperms' => [0], 'fileowner' => [0],
        'getimagesize' => [0], 'exif_read_data' => [0], 'exif_thumbnail' => [0],
        'md5_file' => [0], 'sha1_file' => [0], 'hash_file' => [1],
        'parse_ini_file' => [0], 'highlight_file' => [0], 'show_source' => [0],
        'gzopen' => [0], 'gzfile' => [0], 'bzopen' => [0], 'readgzfile' => [0],
        'simplexml_load_file' => [0], 'realpath' => [0], 'link' => [0, 1],
        'symlink' => [0, 1], 'chmod' => [0], 'chown' => [0], 'chgrp' => [0],
    ];

    /**
     * Functions that look at a string rather than open it.
     *
     * @var array<string, true>
     */
    public const INSPECTORS = [
        'strpos' => true, 'stripos' => true, 'strrpos' => true, 'strripos' => true,
        'str_contains' => true, 'str_starts_with' => true, 'str_ends_with' => true,
        'in_array' => true, 'array_search' => true, 'array_key_exists' => true,
        'preg_match' => true, 'preg_match_all' => true, 'preg_quote' => true,
        'strcmp' => true, 'strcasecmp' => true, 'strncmp' => true, 'strncasecmp' => true,
        'substr_count' => true, 'str_replace' => true, 'str_ireplace' => true,
        'ltrim' => true, 'rtrim' => true, 'trim' => true, 'explode' => true,
    ];

    /** Schemes that make a path something other than a plain file. @var array<string, string> */
    public const SCHEMES = [
        'http' => 'network.url',
        'https' => 'network.url',
        'ftp' => 'network.url',
        'ftps' => 'network.url',
        'ssh2' => 'network.url',
        'phar' => 'deserialize.phar',
        'php' => 'filesystem.wrapper',
        'data' => 'filesystem.wrapper',
        'expect' => 'filesystem.wrapper',
        'zip' => 'filesystem.wrapper',
        'glob' => 'filesystem.wrapper',
        'ogg' => 'filesystem.wrapper',
        'compress.zlib' => 'filesystem.wrapper',
        'compress.bzip2' => 'filesystem.wrapper',
    ];

    /** The capability a literal path implies, if any. */
    public static function scheme(string $path): ?string
    {
        if (preg_match('#^([a-z0-9.+-]+)://#i', $path, $m) !== 1) {
            return null;
        }

        return self::SCHEMES[strtolower($m[1])] ?? null;
    }
}
