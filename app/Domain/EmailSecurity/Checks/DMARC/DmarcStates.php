<?php

namespace App\Domain\EmailSecurity\Checks\DMARC;

final class DmarcStates
{
    public const PASS = 'pass';
    public const FAIL = 'fail';
    public const MISSING = 'missing';
    public const WARNING = 'warning';
    public const UNKNOWN = 'unknown';
}
