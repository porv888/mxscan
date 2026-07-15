<?php

namespace App\Domain\EmailSecurity\Checks\Blacklist;

final class BlacklistStates
{
    public const PASS = 'pass';
    public const WARNING = 'warning';
    public const FAIL = 'fail';
    public const NOT_CHECKED = 'not_checked';
    public const UNKNOWN = 'unknown';
}
