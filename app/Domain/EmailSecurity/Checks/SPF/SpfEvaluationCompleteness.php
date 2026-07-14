<?php

namespace App\Domain\EmailSecurity\Checks\SPF;

final class SpfEvaluationCompleteness
{
    public const COMPLETE = 'complete';
    public const PARTIAL = 'partial';

    public static function derive(string $protocolStatus): string
    {
        return match ($protocolStatus) {
            SpfProtocolStatus::TEMPERROR,
            SpfProtocolStatus::PARTIALLY_EVALUATED => self::PARTIAL,
            default => self::COMPLETE,
        };
    }
}
