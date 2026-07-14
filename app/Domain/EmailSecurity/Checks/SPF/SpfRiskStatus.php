<?php

namespace App\Domain\EmailSecurity\Checks\SPF;

final class SpfRiskStatus
{
    public const HEALTHY = 'healthy';
    public const WARNING = 'warning';
    public const CRITICAL = 'critical';
    public const UNKNOWN = 'unknown';
}
