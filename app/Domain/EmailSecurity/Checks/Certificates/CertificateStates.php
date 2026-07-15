<?php

namespace App\Domain\EmailSecurity\Checks\Certificates;

final class CertificateStates
{
    public const PASS = 'pass';
    public const WARNING = 'warning';
    public const FAIL = 'fail';
    public const UNKNOWN = 'unknown';
    public const NOT_CHECKED = 'not_checked';
}
