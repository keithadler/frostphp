# Instructions for AI coding agents working in this repository

frostphp is a deny-by-default capability linter for PHP, and this repository is
its own code. If you are an assistant making changes here, these are the rules
that matter.

## The product rule

Zero false positives is the product. Before you finish any change under
`src/Extract/`, `src/Taint/` or `src/Source.php`, run:

```bash
php scripts/corpus.php
```

The diff must be empty. If your change is meant to move it, run
`php scripts/corpus.php --update`, read every added and removed line, confirm
each addition is a true positive by opening the file in `corpus/.cache/`, and
say what changed and why in your summary. A finding you cannot show to be real
is a bug in your rule, not a judgment call.

Do this honestly. When scheme detection was tightened, the corpus printed
seventeen removals; the right move was to open `guzzlehttp/psr7` and Monolog and
confirm each one was a `str_starts_with` check rather than a use, not to record
the new numbers because the tests were green.

## Before you finish

```bash
vendor/bin/phpunit           # every test
php scripts/corpus.php       # the false-positive guard
php scripts/gen_docs.php     # regenerate docs if the taxonomy changed
php bin/frostphp src bin scripts   # frostphp on itself, must exit 0
```

All four must pass. Do not mark a task done with a failing test, and do not
weaken a test to make it pass.

## How the code is laid out

Read [ARCHITECTURE.md](ARCHITECTURE.md) first. The short version: `Discover`
finds files, `Source` parses them across two dialects, `Extract` turns them into
`Usage` records, `Taint` asks whether untrusted input reaches a sink, `Policy`
decides, `Report` prints.

Three distinctions in the design are load-bearing, and flattening any one of
them breaks the tool:

- **Capability is not vulnerability.** `exec('ls')` is a capability;
  `exec($_GET['c'])` is a bug.
- **Include time is not call time.** A socket at the top level of a file
  Composer autoloads has already been opened; the same call in a function has
  not.
- **Escaping is per destination.** A value escaped for SQL is not escaped for
  HTML, and `Taint\Value` exists to keep those apart.

## The one that bites

Silence is never an acceptable result. The worst bug this tool can have is not a
wrong finding - it is a file that produced no findings because nothing was read.
That has happened once already: short open tags parse as inert HTML, so a whole
legacy tree came back clean. If you touch `Source::prepare`, add a test that
asserts a *positive* finding in the file shape you changed, never just that it
did not error.

## Conventions that are checked or reviewed

- Tests alongside, in `tests/<Area>Test.php`. A capability or sink change needs
  positives **and** the look-alikes that must stay quiet.
- Every new CLI flag gets help text in `src/Cli/Main.php`, a usage line in the
  README, and a test.
- The capability taxonomy in `src/Capabilities.php` is the single source of
  truth. `CapabilitiesTest` fails if the extractor emits a code the policy
  language cannot name.
- The policy dialect is frost's. Before adding a form, use frost's words.
- PHP 5 is a first-class input. A rule that only recognises the current manual
  is half a rule.
