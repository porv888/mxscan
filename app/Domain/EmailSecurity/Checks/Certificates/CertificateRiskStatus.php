<?php

namespace App\Domain\EmailSecurity\Checks\Certificates;

final class CertificateRiskStatus
{
    public const HEALTHY = 'healthy';
    public const WARNING = 'warning';
    public const CRITICAL = 'critical';
    public const UNKNOWN = 'unknown';
}
