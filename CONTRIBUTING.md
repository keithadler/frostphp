# Contributing

## The zero-false-positive rule

A finding is a fact. If frostphp reports something, someone must be able to open
the file and see that it is true. That is not an aspiration; it is enforced.

```bash
php scripts/corpus.php
```

runs the engine over pinned, real packages - Symfony Console and
HttpFoundation, Guzzle, Monolog, Twig, Doctrine DBAL, PHPMailer, PSR Log - and
fails if the findings move. Adding a line is a claim that the new finding is
true, and the way to make that claim is to open the file in `corpus/.cache/` and
check it before running `--update`.

A new rule needs three things:

1. Positive tests: the shapes it should catch.
2. A **must stay quiet** block: the look-alikes it must not catch. A method with
   the same name as a function, a namespaced call, a literal where an expression
   was expected, a comparison where a use was expected.
3. An unchanged corpus, or a corpus diff you have checked line by line.

## Getting set up

```bash
composer install
vendor/bin/phpunit
php scripts/corpus.php     # fetches the pinned packages on first run
```

## Before you open a pull request

```bash
vendor/bin/phpunit
php scripts/corpus.php
php scripts/gen_docs.php --check
php bin/frostphp src bin scripts
```

## Things worth knowing

- **The taxonomy is the contract.** `src/Capabilities.php` is the single source
  of truth; `docs/CAPABILITIES.md` and `frostphp capabilities` are generated
  from it, and a test fails if the extractor emits a code a policy cannot name.
- **PHP 5 is a first-class input.** Removed functions, short open tags, `.inc`
  files and PHP 4 constructors are all in scope. A rule that only knows the
  current manual is half a rule.
- **Silence is a bug.** If a change could cause a file to be skipped rather than
  reported, add a test that asserts a positive finding in that file shape.
- **One runtime dependency.** `nikic/php-parser`. Please do not add a second.

## Reporting a false positive

Open an issue with the smallest file that reproduces it and what you expected.
A false positive is a higher-priority bug here than a missed finding, because it
is the one that gets the tool switched off.
