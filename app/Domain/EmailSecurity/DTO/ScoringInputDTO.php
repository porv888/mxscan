<?php

namespace App\Domain\EmailSecurity\DTO;

use App\Domain\EmailSecurity\Checks\SPF\SpfNativeResult;

final class ScoringInputDTO
{
    /**
     * @param list<array<string, mixed>> $scoreBreakdown
     * @param array<string, mixed> $compatibilityMeta
     */
    public function __construct(
        public readonly NormalizedScanResultDTO $normalized,
        public readonly array $scoreBreakdown,
        public readonly string $scoreModelVersion = 'legacy-v1',
        public readonly array $compatibilityMeta = [],
        public readonly ?SpfNativeResult $nativeSpfResult = null,
    ) {
    }
}
