# Capabilities

Generated from `src/Capabilities.php` by `php scripts/gen_docs.php`. Do not edit by hand.

A policy may name a **family** (`may use the network`) or a single **member**
(`may use network.curl`). A family grant covers its members; a member grant does
not cover the family. Everything not granted is denied.

## `codegen`

Turns data into code: eval, create_function, variable functions.

| code | fires on | grant it with |
| --- | --- | --- |
| `codegen` | *the whole family* | `may use codegen`, `may use code generation` |
| `codegen.eval` | eval(...) | `may use codegen.eval`, `may use eval` |
| `codegen.create_function` | create_function(...) | `may use codegen.create_function` |
| `codegen.assert` | assert("...") with a string (evaluated before PHP 8) | `may use codegen.assert` |
| `codegen.preg` | preg_replace with the /e modifier | `may use codegen.preg` |
| `codegen.dynamic` | $fn(), $obj->$method(), new $class, call_user_func(...) | `may use codegen.dynamic`, `may use dynamic calls`, `may use variable functions` |

## `process`

Runs another program: exec, shell_exec, proc_open, backticks.

| code | fires on | grant it with |
| --- | --- | --- |
| `process` | *the whole family* | `may use process`, `may use running programs`, `may use shell commands` |
| `process.exec` | exec, shell_exec, system, passthru | `may use process.exec` |
| `process.proc` | proc_open, popen | `may use process.proc`, `may use subprocesses` |
| `process.backtick` | `command` (the backtick operator) | `may use process.backtick` |
| `process.pcntl` | pcntl_exec, pcntl_fork | `may use process.pcntl` |

## `network`

Reaches off the machine: curl, sockets, remote URLs, mail.

| code | fires on | grant it with |
| --- | --- | --- |
| `network` | *the whole family* | `may use network`, `may use network`, `may use the network` |
| `network.curl` | curl_init, curl_exec, curl_setopt | `may use network.curl`, `may use curl`, `may use http requests` |
| `network.socket` | fsockopen, stream_socket_client, socket_create | `may use network.socket`, `may use sockets` |
| `network.url` | file_get_contents/fopen/readfile on an http, https or ftp URL | `may use network.url` |
| `network.mail` | mail(...) | `may use network.mail`, `may use sending mail` |
| `network.dns` | gethostbyname, dns_get_record, checkdnsrr, get_headers | `may use network.dns`, `may use dns lookups` |

## `filesystem`

Opens, writes or removes files, or registers a stream wrapper.

| code | fires on | grant it with |
| --- | --- | --- |
| `filesystem` | *the whole family* | `may use filesystem`, `may use file access`, `may use the file system` |
| `filesystem.read` | file_get_contents, fopen, readfile, file, SplFileObject | `may use filesystem.read`, `may use reading files` |
| `filesystem.write` | file_put_contents, fwrite, copy, rename, mkdir, move_uploaded_file | `may use filesystem.write`, `may use writing files` |
| `filesystem.delete` | unlink, rmdir | `may use filesystem.delete`, `may use deleting files` |
| `filesystem.wrapper` | a php://, data://, zip:// or expect:// path, or stream_wrapper_register | `may use filesystem.wrapper`, `may use stream wrappers` |

## `include`

Chooses which file of code to run at runtime.

| code | fires on | grant it with |
| --- | --- | --- |
| `include` | *the whole family* | `may use include` |
| `include.dynamic` | include / require with anything but a literal path | `may use include.dynamic`, `may use dynamic includes`, `may use runtime includes` |
| `include.autoload` | spl_autoload_register | `may use include.autoload`, `may use autoloaders` |

## `deserialize`

Builds objects from bytes: unserialize, phar, yaml, XML entities.

| code | fires on | grant it with |
| --- | --- | --- |
| `deserialize` | *the whole family* | `may use deserialize`, `may use deserialization` |
| `deserialize.unserialize` | unserialize(...) | `may use deserialize.unserialize`, `may use unserialize` |
| `deserialize.phar` | a phar:// path, or new Phar / PharData | `may use deserialize.phar`, `may use phar` |
| `deserialize.yaml` | yaml_parse, Yaml::parse with PARSE_OBJECT | `may use deserialize.yaml`, `may use yaml loading` |
| `deserialize.xml` | XML parsed with entities enabled (LIBXML_NOENT, libxml_disable_entity_loader(false)) | `may use deserialize.xml`, `may use xml entities` |

## `scope`

Rewrites the local variables from data: extract, $$name, parse_str.

| code | fires on | grant it with |
| --- | --- | --- |
| `scope` | *the whole family* | `may use scope`, `may use scope injection` |
| `scope.extract` | extract(...), import_request_variables(...) | `may use scope.extract`, `may use extract` |
| `scope.variable` | $$name or ${$name} | `may use scope.variable`, `may use variable variables` |
| `scope.parse_str` | parse_str($s) with no result array | `may use scope.parse_str` |

## `native`

Leaves the engine: FFI, dl.

| code | fires on | grant it with |
| --- | --- | --- |
| `native` | *the whole family* | `may use native`, `may use native code` |
| `native.ffi` | FFI::cdef, FFI::load, FFI::scope | `may use native.ffi`, `may use ffi` |
| `native.dl` | dl(...) | `may use native.dl` |

## `env`

Reads or writes the environment, or changes php.ini settings.

| code | fires on | grant it with |
| --- | --- | --- |
| `env` | *the whole family* | `may use env`, `may use environment variables` |
| `env.read` | getenv, $_ENV, $_SERVER | `may use env.read`, `may use reading the environment` |
| `env.write` | putenv | `may use env.write`, `may use writing the environment` |
| `env.ini` | ini_set, ini_alter, set_include_path | `may use env.ini`, `may use changing php settings` |

## `response`

Controls the HTTP response: headers, cookies, sessions.

| code | fires on | grant it with |
| --- | --- | --- |
| `response` | *the whole family* | `may use response` |
| `response.header` | header(...), header_remove(...) | `may use response.header`, `may use response headers`, `may use setting headers` |
| `response.cookie` | setcookie, setrawcookie | `may use response.cookie`, `may use cookies` |
| `response.session` | session_start, session_id, session_regenerate_id, session_register | `may use response.session`, `may use sessions` |

## `database`

Connects to a data store, or runs a query against one.

| code | fires on | grant it with |
| --- | --- | --- |
| `database` | *the whole family* | `may use database`, `may use database access`, `may use the database` |
| `database.connect` | new PDO, mysqli_connect, mysql_connect, pg_connect | `may use database.connect`, `may use connecting to a database` |
| `database.query` | PDO::query/exec/prepare, mysqli_query, mysql_query, pg_query | `may use database.query`, `may use sql queries` |

## Refusing one

Any code above can be refused outright with `forbid <code>`. A `forbid` beats a
`may use`, so a family can be granted and one member carved out of it, and an
inherited `forbid` cannot be granted away by a policy that `extends` it.
