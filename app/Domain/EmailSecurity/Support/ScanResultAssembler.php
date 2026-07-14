<?php

namespace App\Domain\EmailSecurity\Support;

use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\CheckResultDTO;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;
use App\Domain\EmailSecurity\DTO\NormalizedScanResultDTO;
use App\Domain\EmailSecurity\DTO\ScanResultDTO;

final class ScanResultAssembler
{
    /**
     * @param array<string, mixed> $sections
     */
    public function assemble(array $sections): ScanResultDTO
    {
        return new ScanResultDTO(sections: $sections);
    }

    /**
     * @param array<string, CheckResultDTO> $bundledResults
     * @param array<string, CheckResultDTO> $nativeResults
     */
    public function assembleNormalized(
        CheckContextDTO $context,
        ?DnsCollectionResultDTO $dns,
        array $bundledResults,
        array $nativeResults,
    ): NormalizedScanResultDTO {
        $checkResults = array_merge($bundledResults, $nativeResults);
        $legacyDnsMetadata = [];

        if ($dns !== null) {
            $legacyDnsMetadata = [
                'score' => $dns->score,
                'score_breakdown' => $dns->scoreBreakdown,
                'records' => $dns->records,
                'legacy_payload' => $dns->legacyDnsPayload,
            ];
        }

        return new NormalizedScanResultDTO(
            domain: $context->domainName,
            collectedAt: $context->executedAt,
            checkResults: $checkResults,
            legacyDnsMetadata: $legacyDnsMetadata,
        );
    }

    public function toScanResultDTO(NormalizedScanResultDTO $normalized): ScanResultDTO
    {
        $sections = [];

        if ($normalized->legacyDnsMetadata !== []) {
            $legacyPayload = $normalized->legacyDnsMetadata['legacy_payload'] ?? null;
            if (is_array($legacyPayload)) {
                $sections['dns'] = $legacyPayload;
            } else {
                $sections['dns'] = [
                    'score' => $normalized->legacyDnsMetadata['score'] ?? 0,
                    'records' => $normalized->legacyDnsMetadata['records'] ?? [],
                    'score_breakdown' => $normalized->legacyDnsMetadata['score_breakdown'] ?? [],
                ];
            }
        }

        if (isset($normalized->checkResults['spf'])) {
            $sections['spf'] = $normalized->checkResults['spf']->data ?? [];
        }

        if (isset($normalized->checkResults['blacklist'])) {
            $sections['blacklist'] = $normalized->checkResults['blacklist']->data ?? [];
        }

        return new ScanResultDTO(sections: $sections);
    }
}
