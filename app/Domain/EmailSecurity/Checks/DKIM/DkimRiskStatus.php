<?php

namespace App\Domain\EmailSecurity\Checks\DKIM;

final class DkimRiskStatus
{
    public const HEALTHY = 'healthy';
    public const WARNING = 'warning';
    public const CRITICAL = 'critical';
    public const UNKNOWN = 'unknown';
}
