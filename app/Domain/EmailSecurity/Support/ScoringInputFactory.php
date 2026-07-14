<?php

namespace App\Domain\EmailSecurity\Support;

use App\Domain\EmailSecurity\DTO\NormalizedScanResultDTO;
use App\Domain\EmailSecurity\DTO\ScoringInputDTO;

final class ScoringInputFactory
{
    public function from(NormalizedScanResultDTO $normalized): ScoringInputDTO
    {
        $legacy = $normalized->legacyDnsMetadata;

        return new ScoringInputDTO(
            normalized: $normalized,
            scoreBreakdown: $legacy['score_breakdown'] ?? [],
            scoreModelVersion: 'legacy-v1',
            compatibilityMeta: [
                'authoritative_score' => $legacy['score'] ?? null,
                'score_source' => 'legacy_dns_payload',
            ],
        );
    }
}
