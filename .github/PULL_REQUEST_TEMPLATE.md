## What this changes

<!-- One or two sentences. -->

## Checks

- [ ] `vendor/bin/phpunit`
- [ ] `php scripts/corpus.php` — unchanged, or the diff is explained below
- [ ] `php scripts/gen_docs.php --check`
- [ ] `php bin/frostphp src bin scripts` — exits 0

## If the corpus moved

<!-- Every added line is a claim that the finding is true. Say which file you
     opened in corpus/.cache to confirm each one, and why any removed line was
     not a true positive. -->

## If this touches extraction, taint or parsing

- [ ] Positive tests for the shapes it should catch
- [ ] A **must stay quiet** block for the look-alikes it must not
- [ ] If a file could now be skipped rather than reported, a test asserting a
      *positive* finding in that file shape
