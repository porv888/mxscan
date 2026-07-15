<?php

namespace App\Domain\EmailSecurity\Checks\DKIM;

/**
 * Authoritative DNS publication state for DKIM keys.
 */
final class DkimPublicationState
{
    public const PUBLISHED_VALID = 'published_valid';
    public const PUBLISHED_INVALID = 'published_invalid';
    public const NOT_DETECTED = 'not_detected';
    public const LOOKUP_FAILED = 'lookup_failed';
    public const NOT_TESTED = 'not_tested';
}
