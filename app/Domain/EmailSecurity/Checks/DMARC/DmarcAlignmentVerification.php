<?php

namespace App\Domain\EmailSecurity\Checks\DMARC;

/**
 * Whether DMARC alignment was verified from email traffic or reports.
 * DNS-only scans cannot determine aligned vs not_aligned.
 */
final class DmarcAlignmentVerification
{
    public const ALIGNED = 'aligned';
    public const NOT_ALIGNED = 'not_aligned';
    public const NOT_VERIFIED = 'not_verified';
    public const NOT_APPLICABLE = 'not_applicable';
}
