<?php

namespace App\Domain\EmailSecurity\Checks\Blacklist;

final class BlacklistAnalysisStatus
{
    public const COMPLETE = 'complete';
    public const PARTIAL = 'partial';
    public const UNAVAILABLE = 'unavailable';
    public const NOT_CHECKED = 'not_checked';
}
