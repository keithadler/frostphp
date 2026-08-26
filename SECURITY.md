# Security

## What a green run promises

A clean `frostphp` exit means: in the files it read and could parse, every
capability it recognises was granted by your policy, and it found no path from
an untrusted source to a sink it models.

That is a real statement, and it is narrower than "this code is secure".

## What it does not promise

- **It reads PHP source.** A payload compiled into a native extension, or sealed
  in a phar's binary stub, is not source. frostphp will report `dl()` or
  `new Phar` as capabilities, and what happens inside is invisible to this and
  to any source-level analysis. `tests/SupplyChainTest.php` pins that floor.
- **Names built at runtime are not resolved.** `$f = 'sys' . 'tem'; $f($c);` is
  reported as a dynamic call - a capability - and not as `process.exec`.
  Guessing here would report the whole codebase.
- **It is not a vulnerability catalogue.** Weak hashes, TLS settings, hardcoded
  credentials, session fixation, CSRF, access-control mistakes: frostphp models
  none of these. Use a scanner that does, as well as this.
- **Taint stops at what it cannot see.** An unknown call ends a chain by design.
  A flow that passes through a framework's container or a callable resolved at
  runtime will not be followed.
- **A policy is only as good as its author.** `may use everything` passes.

## Reporting a bypass

A bypass is a file where frostphp reports nothing - or reports less than the
truth - for code that plainly does the thing. Those matter most, because a green
run people trust is worse than no run at all.

Please report privately through GitHub's **Report a vulnerability** button on
this repository rather than opening a public issue, with the smallest file that
reproduces it. Expect an acknowledgement within a week.

Ordinary false positives are not security issues; open a normal issue for those.

## The failure mode we care most about

The worst bug this tool can have is not a wrong finding. It is a file that
produced no findings because nothing was read. That has happened once: short
open tags parse as inert HTML under PHP's default configuration, so an entire
legacy tree came back clean. frostphp now rewrites those tags before parsing and
treats a file that holds PHP but yields no PHP as an error.

If you find another shape of that bug, it is the most valuable thing you can
send us.
