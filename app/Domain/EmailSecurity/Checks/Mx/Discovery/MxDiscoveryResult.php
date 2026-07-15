<?php

namespace App\Domain\EmailSecurity\Checks\Mx\Discovery;

use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxDnsQueryResult;

final class MxDiscoveryResult
{
    /**
     * @param list<array<string, mixed>> $rawRecords
     * @param list<array<string, mixed>> $resolverDiagnostics
     */
    public function __construct(
        public readonly string $domain,
        public readonly string $source,
        public readonly MxDnsQueryResult $query,
        public readonly array $rawRecords = [],
        public readonly array $resolverDiagnostics = [],
    ) {
    }

    public function hasDnsFailure(): bool
    {
        return $this->query->failed() || $this->query->isTemperror();
    }

    public function isMissing(): bool
    {
        return $this->query->isGenuinelyAbsent();
    }

    public function dnsStatus(): string
    {
        return $this->query->outcome;
    }
}
