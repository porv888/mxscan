<?php

namespace App\Domain\EmailSecurity\Checks\DMARC;

final class DmarcRiskStatus
{
    public const HEALTHY = 'healthy';
    public const WARNING = 'warning';
    public const CRITICAL = 'critical';
    public const UNKNOWN = 'unknown';
}
