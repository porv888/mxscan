<?php

namespace App\Domain\EmailSecurity\Checks\Bimi;

final class BimiStates
{
    public const PASS = 'pass';
    public const WARNING = 'warning';
    public const FAIL = 'fail';
    public const MISSING = 'missing';
    public const UNKNOWN = 'unknown';
    public const DECLINED = 'declined';
}
