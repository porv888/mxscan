<?php

namespace App\Domain\EmailSecurity\DNS;

use App\Domain\EmailSecurity\Contracts\DnsCollectorInterface;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;
use App\Services\ScannerService;

/**
 * Phase 1 adapter — delegates DNS collection to ScannerService without splitting checks yet.
 */
final class LegacyScannerServiceAdapter implements DnsCollectorInterface
{
    public function __construct(
        private ScannerService $scannerService,
    ) {
    }

    public function collect(string $domain): DnsCollectionResultDTO
    {
        $payload = $this->scannerService->scanDomain($domain);

        return new DnsCollectionResultDTO(
            records: $payload['records'] ?? [],
            score: (int) ($payload['score'] ?? 0),
            scoreBreakdown: $payload['score_breakdown'] ?? [],
            legacyDnsPayload: $payload,
        );
    }
}
