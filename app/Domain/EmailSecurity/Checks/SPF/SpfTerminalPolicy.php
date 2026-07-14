<?php

namespace App\Domain\EmailSecurity\Checks\SPF;

final class SpfTerminalPolicy
{
    public const HARD_FAIL = 'hard_fail';
    public const SOFT_FAIL = 'soft_fail';
    public const NEUTRAL = 'neutral';
    public const PASS_ALL = 'pass_all';
    public const IMPLICIT_NEUTRAL = 'implicit_neutral';
    public const UNKNOWN = 'unknown';
}
