<?php

declare(strict_types=1);

namespace Frost\Policy;

/** A policy file that does not parse. Never silence: a policy nobody can read is not a policy. */
final class PolicyError extends \RuntimeException
{
}
