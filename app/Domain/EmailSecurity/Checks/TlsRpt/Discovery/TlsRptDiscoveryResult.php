<?php

namespace App\Domain\EmailSecurity\Checks\TlsRpt\Discovery;

final class TlsRptDiscoveryResult
{
    public const MAX_CNAME_DEPTH = 8;

    /**
     * @param list<array{host: string, txt: string, ttl: ?int, rr_index: int}> $txtEvidence
     * @param list<string> $selectedRecords
     * @param list<string> $aliasPath
     * @param list<array<string, mixed>> $resolverDiagnostics
     */
    public function __construct(
        public readonly string $queriedDomain,
        public readonly string $recordHostname,
        public readonly string $source,
        public readonly ?string $record = null,
        public readonly bool $multipleRecords = false,
        public readonly bool $dnsFailure = false,
        public readonly ?string $dnsError = null,
        public readonly ?string $dnsOutcome = null,
        public readonly array $txtEvidence = [],
        public readonly array $selectedRecords = [],
        public readonly array $aliasPath = [],
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
