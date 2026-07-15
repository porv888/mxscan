<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts;

final class MtaStsRiskStatus
{
    public const HEALTHY = 'healthy';
    public const WARNING = 'warning';
    public const CRITICAL = 'critical';
    public const UNKNOWN = 'unknown';
}
