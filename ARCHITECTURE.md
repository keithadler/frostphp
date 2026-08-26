# Architecture

frostphp answers two questions about a PHP file, and keeps them separate
because conflating them is how a security tool becomes noise:

1. **What can this code do?** - capability extraction.
2. **Does untrusted input reach somewhere dangerous?** - taint analysis.

The first is a fact about the code. The second is a claim about a bug. A policy
is written against the first; the second fails a build on its own.

## The pipeline

```
discover  ->  prepare  ->  parse  ->  extract  ->  taint  ->  policy  ->  report
 files       open tags     AST       Usage[]     Flow[]     verdict    text/json/sarif/github
```

- **`Discover`** walks the given paths for PHP files - `.php`, and also
  `.inc`, `.phtml`, `.php3`/`4`/`5` and Drupal's `.module`/`.install`/`.theme`,
  because that is where legacy code keeps the interesting parts.
- **`Source`** rewrites the open tags PHP's tokenizer will not see, then parses
  at the newest dialect and falls back to PHP 5.6.
- **`Extract\Extractor`** returns `Usage` records: a capability code, a
  position, the source expression, and whether it runs at include time.
- **`Taint\Analyzer`** returns `Flow` records: a source, a sink, a landing
  place, and where.
- **`Policy`** parses `frostphp.policy` and decides. Deny by default.
- **`Report`** prints. Exit 1 on a finding, 2 on an error.

## Three distinctions are load-bearing

Flattening any one of them breaks the tool.

**Capability is not vulnerability.** `exec('ls')` is a capability;
`exec($_GET['c'])` is a bug. The first belongs in a policy someone signs off,
the second cannot be granted away by any policy line.

**Include time is not call time.** A statement outside any function body runs
the moment the file is included - and in PHP a file is included by the web
server on a request, or by Composer's autoloader before a single line of
application code. A socket opened there has already been opened. `Composer\Deps`
is built entirely on this distinction.

**Escaping is per destination, not a flag.** A value escaped for SQL is not
escaped for HTML. `Taint\Value` carries the set of destinations a value has been
made safe for, and a sink checks its own.

## Where the value lands

`Taint\Sql` is the part of frostphp that says something other tools do not.

Every escaping function PHP ships protects one place: inside a quoted string
literal. So the analysis rebuilds the literal skeleton of the statement, finds
each hole where a value is dropped in, and reads the characters immediately
before it - quoted, bare, or an identifier position after `ORDER BY`/`LIMIT`.
Escaped-and-quoted is the one combination that is silent; the other three are
reported, and the message says which one you have and why escaping did not save
it.

The riskiest hole in a statement decides. One bare hole is enough.

## Deciding whether a name means the thing

The whole difference between a linter people keep and one they turn off.

- `system($c)` is the global function.
- `$logger->system($c)` and `Registry::system($c)` are not.
- `namespace App; system($c)` **is**: PHP falls back to the global namespace for
  unqualified function calls.
- `namespace App; function system(){} system($c)` is not: the namespace owns it.
- `use function App\Util\exec; exec($c)` is not: the import wins.

A naive matcher gets the third and fourth backwards in opposite directions.
`Extract\Names` resolves all five.

Method calls get the same treatment through receivers. `$db->query($sql)` counts
as a query only when `$db` was seen being assigned a connection in this file, or
is one of the globals PHP applications share by convention. `$builder->query()`
is somebody's fluent API and never fires. The cost is a missed query when the
handle arrives as an untyped parameter; that is the right trade, because a
linter that cries wolf on `->query()` gets switched off in a week and then finds
nothing at all.

## Reading code that is not all one age

The two dialects conflict - `$s{0}` parses only as PHP 5/7, `match` only as
PHP 8 - so every file is parsed at the newest version and re-parsed as 5.6 on a
syntax error. When both fail, the reported error is the attempt that reached the
furthest line, which is more likely to be about the actual mistake than about
the dialect.

Short open tags are the dangerous case, and the reason `Source::prepare` exists.
PHP's tokenizer honours `<?` only when `short_open_tag` is on, and it is off by
default, so such a file does not fail to parse - it parses as one long piece of
inert HTML, every function in it vanishes, and the linter reports nothing. The
tags are rewritten to `<?php` before parsing, the three added bytes are recorded
so reported columns can subtract them again, and no newline is ever added, so
line numbers never move.

The rewrite tracks whether it is in markup or in code, because a tag only opens
a block from markup. Inside code, `<?` is two characters in a string - a
template engine is full of them, and so is this repository. Strings, heredocs
and comments are stepped over before looking for a closing tag, because
`echo "?>";` closes nothing. Getting this wrong corrupted frostphp's own source
the first time round, which is how it was found.

Finally, a file that holds PHP but yields no PHP is an error, not a clean run.
That guard exists so this class of silent miss cannot come back.

## Taint, and its bounds

Every bound is a decision about false positives, not a gap nobody got to.

- **Branches merge, they do not overwrite.** `$c = $_GET['c']; $c = "ls";` really
  is safe and clears. But in `if (...) { $c = $_GET['c']; } else { $c = "ls"; }`
  one path reaches the sink, so `$c` stays tainted. Getting this backwards hides
  real flows.
- **An unknown call ends the chain.** `sanitise($x)` stops taint rather than
  guessing.
- **One hop, not many.** A tainted argument into a helper that sinks it. What
  the helper does is discovered by running the ordinary analysis over its body
  with one parameter marked tainted, so a helper can never drift from a direct
  call, and only the parameter that actually reaches the sink counts.
- **Across files, by name.** PHP has one global function namespace per request,
  so a helper defined in `includes/db.inc` and called from `admin/edit.php`
  needs no import graph. It is the same name.
- **Class properties are flow-insensitive.** A property assigned untrusted input
  anywhere in a class is untrusted everywhere in it, because the call order
  between methods is exactly what a static pass cannot know.

Exfiltration is modelled as its own direction - secrets reaching the network
rather than input reaching code - with a sharp precision rule: sending one named
credential is how every API client authenticates and is never reported; sending
the whole environment is.

## The invariants

1. **Zero false positives.** Enforced by `scripts/corpus.php` against pinned
   real packages. The finding count may not move by accident.
2. **Deny by default.** No policy means nothing is allowed.
3. **A denial names the rule.** Every line says which policy line refused it,
   or that nothing granted it.
4. **One runtime dependency.** `nikic/php-parser`, and nothing else.
5. **Silence is never the answer.** A file that cannot be parsed, or that holds
   PHP no dialect could read, is an error and exits 2.
6. **The floor is tested.** What frostphp cannot see - compiled extensions,
   phar payloads - is asserted in `tests/SupplyChainTest.php` so the limit
   cannot quietly move.

## Where things live

| Path | What it does |
| --- | --- |
| `src/Source.php` | open tags, dialect fallback, the vacuous-file guard |
| `src/Discover.php` | which files are PHP |
| `src/Extract/Extractor.php` | AST to `Usage` records |
| `src/Extract/Functions.php` | the function-to-capability map, path arguments, schemes |
| `src/Extract/Names.php` | namespaces, aliases, shadowing |
| `src/Extract/Handles.php` | which variables hold a database connection |
| `src/Taint/Analyzer.php` | sources, sinks, propagation, both directions |
| `src/Taint/Sql.php` | quoted, bare or identifier - where the value lands |
| `src/Taint/Vocabulary.php` | sources, per-destination sanitisers, false friends, sinks |
| `src/Taint/Helpers.php` | what a project's own functions do with their arguments |
| `src/Policy/` | the frost dialect, `extends`, globs, verdicts |
| `src/Composer/Deps.php` | install-time and request-time audit of a vendor tree |
| `src/Report/` | text, json, sarif, github |
| `scripts/corpus.php` | the false-positive guard |
| `scripts/gen_docs.php` | docs/CAPABILITIES.md, from the taxonomy |
