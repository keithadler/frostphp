# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-26

First release.

### Capability extraction

- Eleven families: `codegen`, `process`, `network`, `filesystem`, `include`,
  `deserialize`, `scope`, `native`, `env`, `response`, `database`.
- Name resolution across namespaces, `use` and `use function` imports, shadowed
  declarations, and PHP's global-namespace fallback for unqualified calls.
- Method calls counted only on receivers seen holding a connection, so
  `$builder->query()` never fires.
- `include`/`require` reported only when the path is chosen at runtime;
  `dirname(__FILE__) . '/lib.inc'` is a literal.
- Stream-wrapper schemes recognised in path positions, including `phar://` on
  stat calls, and suppressed where the string is a comparison or a lookup table.
- Include-time separated from call-time on every finding.

### Taint

- Injection into command, code, SQL, file inclusion, XSS, path, header, mail,
  LDAP and SSRF sinks; object injection through `unserialize`; variable
  overwrite through `extract`, `$$name` and `parse_str`.
- SQL findings judged by where the value lands - quoted, bare, or an identifier
  position - so an escaped value in a `LIMIT` or `ORDER BY` is still reported.
- Per-destination sanitisers: escaped for SQL is not escaped for HTML.
- `addslashes` and friends recorded as false friends, with the reason in the
  finding.
- One hop through project helpers, resolved across files by name, discovered by
  probing the helper body rather than matching its name.
- Class properties treated flow-insensitively within a class.
- Exfiltration modelled as its own direction, with bulk secrets required.
- Obfuscated payloads (`eval(base64_decode(...))`) reported as the web-shell
  shape they are.
- Guards read: allowlist lookups, comparison with a literal, `switch` cases,
  character-class tests and anchored patterns prove a value, both as a
  condition around a block and as an early return. Truthiness, length tests and
  unanchored patterns deliberately do not.
- Superglobal keys distinguished: `$_SERVER['REMOTE_ADDR']` and
  `$_FILES[...]['tmp_name']` come from the server, not the client, and
  `setcookie()` URL-encodes its value where `setrawcookie()` does not.

### Frameworks

- Blade templates converted before parsing, so a Laravel view layer is read
  rather than silently skipped; `{!! !!}` is both an XSS sink and a capability
  of its own (`response.raw`), `{{ }}` goes through Laravel's `e()` and stays
  quiet.
- Symfony parameter bags (`$request->query->get()`) followed.
- Laravel raw query builders (`whereRaw`, `orderByRaw`, ...) treated as SQL
  sinks; ordinary method names deliberately not matched on the name alone.
- Helpers followed into methods, resolved through `extends` and traits, for
  calls whose class is known from the syntax.

### Legacy PHP

- Parses at the newest dialect and falls back to PHP 5.6, so `$s{0}` and
  `match` are both readable in one tree.
- Short open tags and ASP tags rewritten before parsing, with line numbers
  preserved and column shifts subtracted back out.
- A file that holds PHP but yields no PHP is an error, never a clean run.
- PHP 5 vocabulary throughout: `mysql_*`, `create_function`, `preg_replace /e`,
  `$HTTP_*_VARS`, `import_request_variables`, `session_register`.
- `.inc`, `.phtml`, `.php3`/`4`/`5`, `.module`, `.install`, `.theme` discovered
  by default.

### Policy and tooling

- The frost dialect: `policy`, `extends`, `may use ... [in "<glob>"] [until
  <date>]`, `forbid`. Deny by default; `forbid` beats `may use`; an inherited
  `forbid` cannot be granted away.
- `init`, `audit`, `deps`, `summary`, `explain`, `capabilities` commands.
- Baselines with line-independent fingerprints, changed-lines mode via
  `--diff`, inline suppressions requiring a capability and a reason.
- text, json, sarif and github output formats.
- `frostphp deps` audits a Composer tree, separating install-time scripts from
  `autoload.files` that run on every request.
- GitHub Action and pre-commit hook.

[0.1.0]: https://github.com/keithadler/frostphp/releases/tag/v0.1.0
