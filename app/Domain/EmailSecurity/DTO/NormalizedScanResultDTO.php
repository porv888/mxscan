<?php

namespace App\Domain\EmailSecurity\DTO;

final class NormalizedScanResultDTO
{
    /**
     * @param array<string, CheckResultDTO> $checkResults
     * @param array<string, mixed> $legacyDnsMetadata
     * @param array<string, mixed> $diagnostics
     * @param list<array{key: string, message: string}> $partialFailures
     */
    public function __construct(
        public readonly string $domain,
        public readonly string $collectedAt,
        public readonly array $checkResults,
        public readonly array $legacyDnsMetadata = [],
        public readonly array $diagnostics = [],
        public readonly array $partialFailures = [],
    ) {
    }
}
