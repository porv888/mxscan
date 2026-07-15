<?php

namespace App\Domain\EmailSecurity\Checks\DKIM;

final class DkimStates
{
    public const PASS = 'pass';
    public const FAIL = 'fail';
    public const MISSING = 'missing';
    public const WARNING = 'warning';
    public const UNKNOWN = 'unknown';
}
