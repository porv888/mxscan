<?php

namespace App\Domain\EmailSecurity\Checks\SPF;

final class SpfStates
{
    public const PASS = 'pass';
    public const FAIL = 'fail';
    public const MISSING = 'missing';
    public const WARNING = 'warning';
    public const NOT_CHECKED = 'not_checked';
    public const UNKNOWN = 'unknown';
}
