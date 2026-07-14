<?php

namespace App\Domain\EmailSecurity\Checks\SPF\Evidence;

final class SpfDerivedStatusDTO
{
    public function __construct(
        public readonly string $protocolStatus,
        public readonly string $riskStatus,
        public readonly string $state,
        public readonly string $summary,
    ) {
    }
}
