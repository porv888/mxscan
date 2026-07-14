<?php

namespace App\Domain\EmailSecurity\Checks\SPF\Discovery;

final class SpfDiscoveryResult
{
    /**
     * @param list<array{host: string, txt: string, ttl: ?int, rr_index: int}> $txtEvidence
     */
    public function __construct(
        public readonly string $domain,
        public readonly string $source,
        public readonly ?string $record = null,
        public readonly bool $multipleRecords = false,
        public readonly bool $dnsFailure = false,
        public readonly ?string $dnsError = null,
        public readonly array $txtEvidence = [],
    ) {
    }

    public function isMissing(): bool
    {
        return $this->record === null && !$this->multipleRecords && !$this->dnsFailure;
    }

    public function hasDnsFailure(): bool
    {
        return $this->dnsFailure;
    }
}
