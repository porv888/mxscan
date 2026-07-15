<?php

namespace Tests\Support\EmailSecurity;

use App\Domain\EmailSecurity\Checks\DMARC\Contracts\DmarcDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\DMARC\Evaluation\DmarcDnsQueryResult;

final class FakeDmarcDnsResolver implements DmarcDnsResolverInterface
{
    /** @var array<string, DmarcDnsQueryResult> */
    private array $responses = [];

    public function setTxt(string $hostname, DmarcDnsQueryResult $result): void
    {
        $this->responses[strtolower(trim($hostname))] = $result;
    }

    public function setRecord(string $hostname, ?string $record, int $ttl = 3600): void
    {
        $hostname = strtolower(trim($hostname));

        if ($record === null) {
            $this->responses[$hostname] = new DmarcDnsQueryResult(
                hostname: $hostname,
                success: true,
                reconstructedTxt: [],
                outcome: DmarcDnsQueryResult::OUTCOME_EMPTY,
            );

            return;
        }

        $this->responses[$hostname] = new DmarcDnsQueryResult(
            hostname: $hostname,
            success: true,
            reconstructedTxt: [$record],
            ttl: $ttl,
            outcome: DmarcDnsQueryResult::OUTCOME_SUCCESS,
        );
    }

    public function txt(string $hostname): DmarcDnsQueryResult
    {
        $hostname = strtolower(trim($hostname));

        return $this->responses[$hostname] ?? new DmarcDnsQueryResult(
            hostname: $hostname,
            success: false,
            error: 'no stubbed response',
            outcome: DmarcDnsQueryResult::OUTCOME_ERROR,
        );
    }

    public function reset(): void
    {
        $this->responses = [];
    }
}
