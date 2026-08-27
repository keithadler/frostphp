# frostphp

[![ci](https://github.com/keithadler/frostphp/actions/workflows/ci.yml/badge.svg)](https://github.com/keithadler/frostphp/actions/workflows/ci.yml)
[![packagist](https://img.shields.io/packagist/v/keithadler/frostphp)](https://packagist.org/packages/keithadler/frostphp)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**The model wrote it. Did anyone decide it could do that?**

frostphp is a deny-by-default capability linter for PHP - the sibling of
[frostpy](https://github.com/keithadler/frostpy) and
[frostjs](https://github.com/keithadler/frostjs). You write a policy that fits
on one screen, in plain words:

```
policy "admin"
may use the database                    -- it is a CRUD app
may use unserialize in "lib/legacy/*"   -- old session format, gone by Q4
forbid dynamic includes                 -- no page is chosen by the query string
forbid shell commands                   -- nothing here shells out
```

and the check fails on anything the code reaches for that the policy does not
grant: running a subprocess, opening a socket, unserializing a cookie, `eval`ing
a string, including a file whose name came from the request.

```
$ frostphp admin
admin/edit.php:25:0: include.dynamic denied by "forbid include.dynamic" (line 5): no page is chosen by the query string
admin/edit.php:29:0: process.exec denied by "forbid process" (line 6): nothing here shells out

3 files, 2 denied
$ echo $?
1
```

## Why PHP gets its own tool

The capability idea is the same in every language. The hazards are not, and
the three that matter most in PHP have no equivalent anywhere else:

- **`include $page` is remote code execution**, not modularity. Every other
  language chooses code at runtime through a narrow, obvious API. PHP does it
  with the same keyword you use for `require 'config.php'`, so the dangerous
  form and the innocent one look identical in a diff. frostphp gives it its own
  capability family and reports only the form that takes an expression.
- **`extract($_GET)` rewrites your local variables from a request.** So does
  `parse_str($q)` with one argument, and so did `import_request_variables`.
  Nothing in Python or JavaScript can reach into a scope and redefine it from
  data.
- **`phar://` turns every path function into a deserializer.** `file_exists()`
  on a `phar://` path unserializes the archive's metadata. A stat call becomes
  an object-injection sink, which is why frostphp checks schemes on
  `getimagesize` and `filesize`, not just on `fopen`.

## Old code, new runtime

A great deal of PHP is PHP 5 source kept alive on a modern engine, and that is
exactly where a capability gate earns its keep - the code was written before
anyone was thinking about this, and half of what frostphp looks for only
appears there in the first place.

**The dialects genuinely conflict**, so neither parser target can read both:

```php
$s{0}                       // parses as PHP 5.6 or 7.4; rejected by 8.x
match ($x) { 1 => 'a' }     // parses as PHP 8.x; rejected by 5.6
```

frostphp parses each file at the newest version, and on a syntax error parses
it again as PHP 5.6. A repository mid-migration has both kinds of file in it
and each is read on its own terms. `--php 7.4` pins it if you would rather be
told.

**Short open tags are read**, and this is the part worth insisting on. PHP's
own tokenizer ignores `<? ... ?>` unless `short_open_tag` is on, and it is off
by default - so a file written that way does not fail to parse. It parses
perfectly, as one long run of inert HTML. Every function in it disappears, the
linter reports nothing, and the build goes green. A check decided by something
other than the thing under test is worse than no check, because somebody
believes it. frostphp rewrites the tags before parsing, keeps every line number
where it was, and refuses outright if a file holds PHP that no dialect could
read.

**The vocabulary is the one in your files**, not the one in the current manual:
`mysql_query`, `create_function`, `preg_replace` with `/e`, `ereg`,
`$HTTP_POST_VARS`, `session_register`, `import_request_variables`. All removed
from the language. All still in production, and all recognised.

**`.inc` and `.phtml` are read by default**, along with `.php3`/`.php4`/`.php5`
and Drupal's `.module`, `.install` and `.theme`. A scanner that globs `*.php`
walks straight past the include that was never meant to be requested directly.

## SQL, and where the value actually lands

If your codebase builds SQL by concatenation, this is the part to read.

Escaping is not a property of a value. It is a property of a value **and the
place you put it**, and every escaping function PHP ships protects exactly one
place: inside a quoted string literal. Put the same escaped value anywhere else
and the escaping does nothing, because there were no quotes to break out of:

```php
$id = mysqli_real_escape_string($db, $_GET['id']);

"SELECT * FROM u WHERE n = '$id'"     // safe - and the only safe one
"SELECT * FROM u WHERE id = $id"      // injectable:  1 OR 1=1
"SELECT * FROM u ORDER BY $id"        // injectable:  an identifier position
"SELECT * FROM u LIMIT $id"           // injectable
```

Every tool that models escaping as a flag calls all four of those clean. They
are the commonest surviving SQL injection in code that was audited once, "fixed"
by wrapping everything in an escape call, and signed off. frostphp rebuilds the
literal skeleton of the statement, finds each hole where a value is dropped in,
reads the characters immediately before it, and says which of the four you have:

```
edit.php:15: $_GET['sort'] -> mysql_query  <- SQL injection: the value lands in an
identifier or LIMIT position, which escaping never protects, so escaping it did not help
```

And `addslashes` is not a sanitiser. It was the house style of an entire
generation of PHP, it is still in the code, and it is bypassable on multi-byte
connection charsets and useless outside quotes. Taint passes straight through
it and the finding says why.

The precision rule that keeps this usable: a tainted **query string** is
injection, a tainted **bound parameter** is the safe form and is never reported.

```php
$wpdb->query($wpdb->prepare("SELECT * FROM t WHERE id = %d", $_GET['id']));  // not reported
$wpdb->query("SELECT * FROM t WHERE id = " . $_GET['id']);                   // reported
```

## Frameworks

Most PHP is written inside a framework, so a linter that only knows the
language stays quiet on most code.

**Blade templates are read.** A `.blade.php` file is not PHP: `@if`, `{{ }}`
and `{!! !!}` all parse as ordinary text, so without conversion a Laravel
application's entire view layer reports clean because none of it was read -
the same failure as short open tags in different clothes. frostphp converts
the two output forms and `@php` blocks before parsing, keeping every line
number in place:

```blade
<h1>{{ $title }}</h1>              {{-- escaped: read, and correctly silent --}}
<div>{!! $_GET['html'] !!}</div>   {{-- reported: cross-site scripting --}}
```

Unescaped output is also a capability in its own right (`response.raw`), so
`forbid raw output` is a rule a team can actually hold, and a view directory
with nothing untrusted in it still reports what it is doing rather than
nothing at all. Control directives are deliberately left as text: rewriting
`@if` means rewriting every matching `@endif`, and one unknown directive would
unbalance the block and turn a whole view folder into syntax errors.

**Symfony's parameter bags** are followed - `$request->query->get()`,
`->headers->get()`, `->cookies->get()` - not just `$request->get()`.

**Laravel's raw query builders** are SQL sinks: `whereRaw`, `orWhereRaw`,
`havingRaw`, `selectRaw`, `orderByRaw`, `groupByRaw`, plus the `DB::` facade.
`Raw` in the name is the framework telling you the escaping is now your
problem. Methods with ordinary names are *not* matched on the name alone -
`statement` and `unprepared` are real Laravel methods, and frostphp's own
`$this->statement($child)` tree walk was reported as SQL until that was
pinned by a test.

**WordPress**: `$wpdb` is a known handle, `$wpdb->prepare()` is the safe form,
and `esc_html`, `esc_attr`, `esc_url` and `esc_sql` each cover their own
destination and no other.

## Checks that prove what a value is

Careful code does not sanitise untrusted input so much as refuse it - it looks
the value up in a list of the ones it will accept and gives up otherwise. An
analysis that cannot read that guard is noisy on exactly the codebases that
took the most care:

```php
if ( ! isset( $core_classes[ $class_name ] ) ) { return false; }
return new $class_name();     // not reported: $class_name is one of the keys
```

frostphp reads allowlist lookups (`isset($map[$x])`, `in_array`,
`array_key_exists`), comparison against a literal, `switch` cases, character-
class tests, and anchored regular expressions - both as a positive check
around a block and as the early-return form above.

What it will not accept as a guard is anything that constrains nothing:

```php
if ($x)                        { system($x); }   // reported: proves nothing
if (strlen($x) < 10)           { system($x); }   // reported: proves nothing
if (preg_match('/[a-z]+/', $x)) { system($x); }  // reported: unanchored, so it
                                                 // says nothing about the rest
if (isset($_GET['x']))         { system($_GET['x']); }  // reported: proves the
                                                 // request has an x, not that
                                                 // x is safe
```

That distinction is the whole value of the feature. A guard that vouches too
easily does not make a linter quieter, it makes it wrong in the one direction
nobody can see.

## Install

```bash
composer require --dev keithadler/frostphp
```

## Use

```bash
vendor/bin/frostphp init src > frostphp.policy   # grant what the code does today
vendor/bin/frostphp src                          # check; 1 on a denial, 2 on an error
vendor/bin/frostphp audit path/to/dep            # no policy: what does this reach for?
vendor/bin/frostphp deps                         # what runs at install, and per request
vendor/bin/frostphp explain unserialize          # what is this, and how do I grant it?
vendor/bin/frostphp summary                      # the policy in plain English
```

`frostphp init` writes a policy granting exactly what the code does today, one
line per capability, with a note saying where. The first check passes. Then you
read the file and delete what should never have been allowed, and the check
starts refusing it.

## Capability is not vulnerability

Two questions, kept apart, because conflating them is how a security tool
becomes noise:

```php
exec('/usr/bin/git rev-parse HEAD');   // a capability. Put it in the policy.
exec('git log ' . $_GET['ref']);       // a bug. No policy can grant it away.
```

The first is a fact about the code and belongs in a file someone signs off. The
second fails the build on its own.

Sources are unusually crisp in PHP: `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`,
`$_FILES`, `$_SERVER`, `php://input`, `getallheaders()`, the `$HTTP_*_VARS`
aliases, and the request objects of Laravel and Symfony.

But not every key of those is the client's. `$_SERVER['HTTP_*']`,
`QUERY_STRING` and `REQUEST_URI` come off the wire; `REMOTE_ADDR` comes from
the TCP connection and `DOCUMENT_ROOT` from the configuration, and no request
can change either. Likewise `$_FILES['f']['name']` is a string the browser
sent, while `['tmp_name']` is a path PHP made up - so `unlink($f['tmp_name'])`
is not a traversal. `SERVER_NAME` stays untrusted on purpose: with
`UseCanonicalName Off`, Apache fills it from the Host header. Sinks cover command,
code, SQL, file-inclusion, XSS, path, header, mail, LDAP and SSRF, plus
`unserialize` for object injection and `extract`/`$$name` for variable
overwrite.

It follows one hop through a helper, because real code extracts the dangerous
line and the danger does not stop being danger because it moved:

```php
// includes/db.inc
function db_fetch_all($sql) { return mysql_query($sql); }

// admin/edit.php
db_fetch_all("SELECT * FROM articles WHERE id = " . $_GET['id']);
//  $_GET['id'] -> mysql_query (via db_fetch_all())
```

What a helper does is discovered by running the ordinary analysis over its body
with one parameter marked tainted - never by matching its name - so a helper can
never drift from what a direct call would report, and only the parameter that
actually reaches the sink counts. PHP makes the cross-file half of this easy in
a way Python does not: function names are global, so a helper in `includes/` and
a call in `admin/` need no import graph to resolve. It is the same name.

Classes are followed too, because the commonest real shape is a controller that
stashes the request in one method and uses it in another:

```php
class Report {
    function load()  { $this->range = $_GET['range']; }
    function build() { return "SELECT * FROM h WHERE d > {$this->range}"; }
}
```

## Escaping is per destination

A single `sanitized` flag is wrong, and wrong in a way that ships:

```php
$name = mysqli_real_escape_string($db, $_GET['name']);
$sql  = "SELECT * FROM u WHERE n = '$name'";   // safe
echo "Hello $name";                            // still cross-site scripting
```

frostphp records which destinations a value has been made safe for.
`htmlspecialchars` covers markup and not SQL; `escapeshellarg` covers the shell
and nothing else; `intval` and `(int)` cover everything, because there is no
injection in an integer.

## What runs before you call anything

PHP's supply-chain question is not "could this package do something dangerous
if I called it".

- **`autoload.files`** in a package's `composer.json` is a list of files
  Composer includes eagerly, at the top of every request, before one line of
  your code runs. A package that opens a socket at the top level of one of
  those has already opened it. Nobody called anything.
- **`scripts`** run at install time, on your machine and on the build agent, as
  whoever ran `composer`. `post-install-cmd` is a shell command in a JSON file
  downloaded from the internet.

```
$ frostphp deps
41 packages, 1440 files

RUNS AT INSTALL TIME

  (this project)   post-autoload-dump   php artisan package:discover

RUNS ON EVERY REQUEST, BEFORE YOUR CODE
(composer autoload.files entries, at their top level)

  acme/helpers     network.socket vendor/acme/helpers/bootstrap.php:2: fsockopen('metrics.invalid', 9000)
```

Reading a setting on load is counted and not flagged - the difference between
`getenv()` at include time and a socket at include time is the whole point.

## Living with it

```bash
frostphp src --format sarif > frostphp.sarif   # code scanning
frostphp src --baseline frostphp-baseline.txt  # only what is new
frostphp src --diff origin/main                # only lines this branch changed
```

- **Baselines.** `--update-baseline` records today's findings so a policy can
  be adopted on a codebase with twenty years of history. The debt is written
  down, it stops growing, and it is visible in the diff when someone pays a
  piece of it off. Fingerprints ignore line numbers, so a finding that slides
  down the file is not a new one.
- **Changed lines only.** `--diff origin/main` judges what this branch added
  and holds back what it inherited. Nobody has to fix a decade of `mysql_query`
  on the afternoon they install the linter, and nobody gets to add the next one.
- **Inline suppressions.** `// frostphp: allow process.exec -- vetted, argv is
  fixed`. The capability must be named and the reason is compulsory: an
  exception nobody explained is the thing this tool exists to prevent.
- **Expiring grants.** `may use unserialize until 2026-12-01`. It warns for a
  fortnight, then it stops granting and the denial says which line lapsed. The
  exception you gave yourself in March is not still holding the door open in
  December.
- **Shared policies.** `extends "../shared/base.policy"` merges a base, so a
  team keeps one policy and each service adds to it. An inherited `forbid`
  cannot be granted away by a child: a prohibition you can silently drop is not
  a prohibition.

## For AI coding agents

If an assistant writes PHP in your project, tell it the gate exists. Paste this
into `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, or whatever your tool reads:

```markdown
## frostphp

This project is gated by frostphp (composer package keithadler/frostphp,
installed as a dev dependency). `frostphp.policy` at the repository root says
which capabilities this code may use. Everything else is denied.

- Before finishing any change to PHP, run `vendor/bin/frostphp <paths you
  changed>` and make it pass.
- Read a denial as a question, not an obstacle. If the task genuinely needs the
  capability, add the narrowest grant that covers it (scope it with
  `in "<glob>"`, add `until <date>` if it is temporary) and say in your summary
  that you widened the policy and why. If the task does not need it, change the
  code instead.
- A taint flow is a bug, not a capability. No policy line can grant one away
  and none should be added to try.
- Never add `may use everything`, never add a suppression comment to make a
  build pass, and never delete or loosen an existing `forbid` line. Those are a
  person's decisions.
- `vendor/bin/frostphp summary` prints the policy in plain English.
```

## A finding is a fact

Accuracy is the product, and it is enforced rather than claimed. Every engine
change runs over a pinned corpus of real packages - Symfony Console and
HttpFoundation, Guzzle, Monolog, Twig, Doctrine DBAL, PHPMailer, PSR Log - and
the findings must not move:

```
$ php scripts/corpus.php
1440 files, 5.8 MB, 673 findings, 4.2s: unchanged
```

All 673 are capability facts and every one is true: Twig really does
`eval('?>'.$content)` to run a compiled template, Symfony Console really does
`shell_exec('stty -g')`, Composer's own class loader really does `include $file`,
Monolog's Git processor really does shell out to `git branch`. There is **not
one taint flow** in 1440 files of mature library code, because there should not
be. Loosen a rule by accident and the corpus prints the new findings as a diff
and fails.

A name only counts when it really refers to the thing:

```php
system($cmd);                  // the global function - reported
$logger->system($cmd);         // a method - not reported
Registry::system($cmd);        // a static call - not reported
namespace App; system($cmd);   // reported: PHP falls back to the global function
namespace App; function system() {...} system($cmd);   // not reported: the namespace owns it
```

That last pair is the one a naive matcher gets backwards in both directions.
Anything the analysis cannot resolve is not reported, and a file that does not
parse is an error (exit 2), never silence.

## What it is, and what it is not

frostphp is a build-time gate for code you own and dependencies you vet. It is
**not** a scanner that promises novel vulnerabilities in popular packages. Run
it across mature libraries and it will mostly report their advertised jobs. A
quiet result on maintained code is the tool working. Where it earns its keep is
the deny-by-default gate on first-party code, the legacy estate nobody has read
in a decade, and the moment before you adopt a dependency you have not read.

**The honest limit**, tested rather than hand-waved: frostphp reads PHP source.
It cannot see into a compiled extension, so what happens after `dl('evil.so')`
is invisible to this and to any source-level analysis. The same goes for a
payload sealed in a phar's binary stub. `tests/SupplyChainTest.php` asserts that
floor so it cannot quietly move.

## Capabilities

Eleven families. `frostphp capabilities` prints the full taxonomy, and
[docs/CAPABILITIES.md](docs/CAPABILITIES.md) documents every code.

| family | what it means |
| --- | --- |
| `codegen` | turns data into code: `eval`, `create_function`, variable functions |
| `process` | runs another program: `exec`, `shell_exec`, `proc_open`, backticks |
| `network` | reaches off the machine: curl, sockets, remote URLs, mail |
| `filesystem` | opens, writes or removes files, or registers a stream wrapper |
| `include` | chooses which file of code to run at runtime |
| `deserialize` | builds objects from bytes: `unserialize`, phar, YAML, XML entities |
| `scope` | rewrites the local variables from data: `extract`, `$$name`, `parse_str` |
| `native` | leaves the engine: FFI, `dl` |
| `env` | reads or writes the environment, or changes php.ini settings |
| `response` | controls the HTTP response: headers, cookies, sessions, raw output |
| `database` | connects to a data store, or runs a query against one |

`database` is there for a reason worth naming: "this template may not touch the
database" is the policy line a legacy cleanup actually wants, and it cannot be
written in a taxonomy that treats SQL only as a vulnerability.

## Policy grammar

One rule per line; `--` starts a comment.

```
policy "<name>"
extends "<path to another policy>"
may use <capability> [in "<glob>"] [until YYYY-MM-DD]
forbid <capability>
```

In a glob, `*` and `?` stop at a directory separator and `**` crosses them, so
a subtree is `in "src/legacy/**"`. Everything not granted is denied. A `forbid`
beats a `may use`.

## Status

Early (0.1.0), but real. The extractor resolves namespaces, `use` aliases,
`use function` imports, shadowing and method receivers; the checker supports
scoped grants, `forbid`, expiring grants, shared bases, baselines, inline
suppressions and changed-lines mode; taint covers command, code, SQL, file
inclusion, XSS, path, header, mail, LDAP and SSRF, with per-destination
escaping, SQL landing-place analysis, allowlist and early-return guards, one
hop through functions and methods across files with inheritance and traits, and
class properties; exfiltration is modelled as its own direction; Blade
templates are converted before parsing; install-time and request-time are
separated and `frostphp deps` audits a Composer tree. 177 tests plus a pinned
corpus of eight real packages.

Pointed at WordPress core - 1,855 files, no policy, 15 seconds - it reports ten
taint flows, each of which can be opened and argued about, and none of which is
a mistake in the reading. Four of the ten are the multisite file handler
sanitising a path with `str_replace('..', '')`, which frostphp says is a
blocklist rather than a fix.

## Project

- [ARCHITECTURE.md](ARCHITECTURE.md) - the pipeline, the load-bearing
  distinctions, the invariants.
- [CONTRIBUTING.md](CONTRIBUTING.md) - the zero-false-positive rule and how the
  corpus enforces it.
- [SECURITY.md](SECURITY.md) - what a green run promises, what it does not, and
  how to report a bypass privately.
- [AGENTS.md](AGENTS.md) - instructions for AI agents changing this repository.
- [docs/CAPABILITIES.md](docs/CAPABILITIES.md) - every code, what fires it, and
  the policy phrases that grant it. Generated from the source; CI checks it.

## License

MIT. See [LICENSE](LICENSE).
