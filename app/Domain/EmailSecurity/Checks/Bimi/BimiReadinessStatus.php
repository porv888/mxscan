<?php

namespace App\Domain\EmailSecurity\Checks\Bimi;

final class BimiReadinessStatus
{
    public const READY = 'ready';
    public const READY_SELF_ASSERTED = 'ready_self_asserted';
    public const PARTIALLY_READY = 'partially_ready';
    public const NOT_READY = 'not_ready';
    public const NOT_PARTICIPATING = 'not_participating';
    public const UNKNOWN = 'unknown';
}
