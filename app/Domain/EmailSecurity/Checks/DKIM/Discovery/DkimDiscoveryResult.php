<?php

namespace App\Domain\EmailSecurity\Checks\DKIM\Discovery;

use App\Domain\EmailSecurity\Checks\DKIM\DkimSelectorCandidate;
use App\Domain\EmailSecurity\Checks\DKIM\Evaluation\DkimDnsQueryResult;

final class DkimDiscoveryResult
{
    /**
     * @param list<string> $dkimRecords
     * @param list<array<string, mixed>> $resolverDiagnostics
     */
    public function __construct(
        public readonly DkimSelectorCandidate $candidate,
        public readonly string $dnsStatus,
        public readonly array $dkimRecords = [],
        public readonly bool $multipleRecords = false,
        public readonly ?string $rawRecord = null,
        public readonly ?int $ttl = null,
        public readonly ?string $dnsError = null,
        public readonly array $resolverDiagnostics = [],
        public readonly ?string $cnameTarget = null,
    ) {
    }

    public function hasDnsFailure(): bool
    {
        return in_array($this->dnsStatus, [
            DkimDnsQueryResult::OUTCOME_TIMEOUT,
            DkimDnsQueryResult::OUTCOME_SERVFAIL,
            DkimDnsQueryResult::OUTCOME_REFUSED,
            DkimDnsQueryResult::OUTCOME_ERROR,
        ], true);
    }

    public function isEmpty(): bool
    {
        return in_array($this->dnsStatus, [
            DkimDnsQueryResult::OUTCOME_EMPTY,
            DkimDnsQueryResult::OUTCOME_NXDOMAIN,
        ], true) || ($this->dkimRecords === [] && !$this->hasDnsFailure() && !$this->multipleRecords);
    }
}
