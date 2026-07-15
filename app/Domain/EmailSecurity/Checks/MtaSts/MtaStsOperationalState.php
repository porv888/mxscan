<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts;

/**
 * Distinct MTA-STS operational states for reporting and recommendations.
 */
final class MtaStsOperationalState
{
    public const VALID = 'valid';
    public const DNS_RECORD_MISSING = 'dns_record_missing';
    public const HOSTNAME_UNRESOLVED = 'hostname_unresolved';
    public const TLS_FAILED = 'tls_failed';
    public const CERTIFICATE_INVALID = 'certificate_invalid';
    public const HTTP_FAILED = 'http_failed';
    public const POLICY_MISSING = 'policy_missing';
    public const POLICY_INVALID = 'policy_invalid';
}
