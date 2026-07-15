<?php

namespace App\Domain\EmailSecurity\Checks\DMARC\Discovery;

final class DmarcDiscoveryResult
{
    /**
     * @param list<array{host: string, txt: string, ttl: ?int, rr_index: int}> $txtEvidence
     * @param list<string> $dmarcRecords
     * @param list<array<string, mixed>> $resolverDiagnostics
     */
    public function __construct(
        public readonly string $queriedDomain,
        public readonly string $recordDomain,
        public readonly string $hostname,
        public readonly string $source,
        public readonly ?string $record = null,
        public readonly bool $multipleRecords = false,
        public readonly bool $dnsFailure = false,
        public readonly ?string $dnsError = null,
        public readonly array $txtEvidence = [],
        public readonly array $dmarcRecords = [],
        public readonly array $resolverDiagnostics = [],
        public readonly ?int $ttl = null,
    ) {
    }

    public function isMissing(): bool
    {
        return !$this->dnsFailure && $this->record === null && !$this->multipleRecords;
    }

    public function hasDnsFailure(): bool
    {
        return $this->dnsFailure;
    }
}
