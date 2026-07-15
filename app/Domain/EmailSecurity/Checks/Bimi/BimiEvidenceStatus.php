<?php

namespace App\Domain\EmailSecurity\Checks\Bimi;

final class BimiEvidenceStatus
{
    public const VALID = 'valid';
    public const ABSENT = 'absent';
    public const SELF_ASSERTED = 'self_asserted';
    public const PARTIALLY_VALIDATED = 'partially_validated';
    public const INVALID = 'invalid';
    public const UNAVAILABLE = 'unavailable';
    public const UNSUPPORTED = 'unsupported';
}
