<?php

namespace App\Domain\EmailSecurity\DTO;

final class DnsCollectionResultDTO
{
    /**
     * @param array<string, mixed> $records
     * @param list<array<string, mixed>> $scoreBreakdown
     * @param array<string, mixed> $legacyDnsPayload
     */
    public function __construct(
        public readonly array $records,
        public readonly int $score,
        public readonly array $scoreBreakdown,
        public readonly array $legacyDnsPayload,
    ) {
    }
}
