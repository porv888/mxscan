<?php

namespace App\Domain\EmailSecurity\DTO;

final class DnsCollectionResultDTO
{
    /**
     * @param array<string, mixed> $records
     * @param list<array<string, mixed>> $scoreBreakdown
     * @param array<string, mixed> $legacyDnsPayload
     * @param list<array{host: string, txt: string|list<string>, ttl: ?int}> $rootTxtRecords
     * @param list<array{host: string, txt: string, ttl: ?int, rr_index: int}> $dmarcTxtRecords
     * @param list<array{host: string, txt: string, ttl: ?int, rr_index: int}> $mtaStsTxtRecords
     * @param list<array{host: string, txt: string, ttl: ?int, rr_index: int}> $tlsRptTxtRecords
     * @param list<array{host: string, txt: string, ttl: ?int, rr_index: int}> $bimiTxtRecords
     */
    public function __construct(
        public readonly array $records,
        public readonly int $score,
        public readonly array $scoreBreakdown,
        public readonly array $legacyDnsPayload,
        public readonly array $rootTxtRecords = [],
        public readonly array $dmarcTxtRecords = [],
        public readonly array $mtaStsTxtRecords = [],
        public readonly array $tlsRptTxtRecords = [],
        public readonly array $bimiTxtRecords = [],
    ) {
    }
}
