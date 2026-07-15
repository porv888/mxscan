<?php

namespace App\Domain\EmailSecurity\Checks\Certificates;

/**
 * Endpoint certificate verification outcome.
 */
final class CertificateVerificationState
{
    public const VALID = 'valid';
    public const HOSTNAME_MISMATCH = 'hostname_mismatch';
    public const EXPIRED = 'expired';
    public const CHAIN_INVALID = 'chain_invalid';
    public const CONNECTION_FAILED = 'connection_failed';
    public const UNABLE_TO_VERIFY = 'unable_to_verify';
}
