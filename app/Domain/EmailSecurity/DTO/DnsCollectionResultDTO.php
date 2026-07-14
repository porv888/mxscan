<?php

namespace App\Domain\EmailSecurity\DTO;

final class DnsCollectionResultDTO
{
    /**
     * @param array<string, mixed> $records
     * @param list<array<string, mixed>> $scoreBreakdown
     * @param array<string, mixed> $legacyDnsPayload
     * @param list<array{host: string, txt: string|list<string>, ttl: ?int}> $rootTxtRecords
     */
    public function __construct(
        public readonly array $records,
        public readonly int $score,
        public readonly array $scoreBreakdown,
        public readonly array $legacyDnsPayload,
        public readonly array $rootTxtRecords = [],
    ) {
    }
}
