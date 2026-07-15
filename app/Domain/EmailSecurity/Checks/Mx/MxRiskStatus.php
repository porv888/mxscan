<?php

namespace App\Domain\EmailSecurity\Checks\Mx;

final class MxRiskStatus
{
    public const HEALTHY = 'healthy';
    public const WARNING = 'warning';
    public const CRITICAL = 'critical';
    public const UNKNOWN = 'unknown';
}
