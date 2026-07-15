<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts;

final class MtaStsStates
{
    public const PASS = 'pass';
    public const WARNING = 'warning';
    public const FAIL = 'fail';
    public const MISSING = 'missing';
    public const UNKNOWN = 'unknown';
}
