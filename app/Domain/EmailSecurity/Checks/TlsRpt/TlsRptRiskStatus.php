<?php

namespace App\Domain\EmailSecurity\Checks\TlsRpt;

final class TlsRptRiskStatus
{
    public const HEALTHY = 'healthy';
    public const WARNING = 'warning';
    public const CRITICAL = 'critical';
    public const UNKNOWN = 'unknown';
}
