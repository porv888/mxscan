<?php

namespace App\Domain\EmailSecurity\Checks\Bimi\DTO;

final class BimiDiscoveryResult
{
    public const MAX_CNAME_DEPTH = 5;

    /**
     * @param list<string> $aliasPath
     * @param list<array<string, mixed>> $resolverDiagnostics
     * @param list<array{domain: string, hostname: string, source: string, outcome: string, selector: string}> $fallbackPath
     */
    public function __construct(
        public readonly string $queriedDomain,
        public readonly string $recordHostname,
        public readonly string $selector,
        public readonly string $selectorSource,
        public readonly string $source,
        public readonly bool $dnsFailure = false,
        public readonly ?string $dnsError = null,
        public readonly ?string $dnsOutcome = null,
        public readonly ?string $record = null,
        public readonly ?int $ttl = null,
        public readonly array $aliasPath = [],
        public readonly array $resolverDiagnostics = [],
        public readonly array $fallbackPath = [],
        public readonly int $selectedRecordCount = 0,
    ) {
    }

    public function hasDnsFailure(): bool
    {
        return $this->dnsFailure;
    }

    public function isMissing(): bool
    {
        return !$this->dnsFailure && $this->record === null && $this->selectedRecordCount === 0;
    }

    public function hasMultipleRecords(): bool
    {
        return $this->selectedRecordCount > 1;
    }
}
