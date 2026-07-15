<?php

namespace App\Domain\EmailSecurity\Checks\Blacklist;

final class BlacklistReputationStatus
{
    public const CLEAN = 'clean';
    public const PARTIAL = 'partial';
    public const LISTED = 'listed';
    public const UNKNOWN = 'unknown';
    public const NOT_CHECKED = 'not_checked';
}
