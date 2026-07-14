<?php

namespace App\Domain\EmailSecurity\Support;

use App\Domain\EmailSecurity\Checks\SPF\SpfNativeResult;
use App\Domain\EmailSecurity\DTO\NormalizedScanResultDTO;
use App\Domain\EmailSecurity\DTO\ScoringInputDTO;

final class ScoringInputFactory
{
    public function from(NormalizedScanResultDTO $normalized, ?SpfNativeResult $nativeSpf = null): ScoringInputDTO
    {
        $legacy = $normalized->legacyDnsMetadata;
        $useNativeScoring = config('email-security.spf_engine', 'legacy') === 'native' && $nativeSpf !== null;

        return new ScoringInputDTO(
            normalized: $normalized,
            scoreBreakdown: $legacy['score_breakdown'] ?? [],
            scoreModelVersion: $useNativeScoring ? 'spf-v2' : 'legacy-v1',
            compatibilityMeta: [
                'authoritative_score' => $legacy['score'] ?? null,
                'score_source' => $useNativeScoring ? 'native_spf_score_rule' : 'legacy_dns_payload',
            ],
            nativeSpfResult: $nativeSpf,
        );
    }
}
