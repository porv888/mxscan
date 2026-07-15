<?php

namespace App\Domain\EmailSecurity\Checks\Bimi;

final class BimiRiskStatus
{
    public const HEALTHY = 'healthy';
    public const WARNING = 'warning';
    public const CRITICAL = 'critical';
    public const UNKNOWN = 'unknown';
    public const INFORMATIONAL = 'informational';
}
