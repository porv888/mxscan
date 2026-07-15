<?php

namespace Tests\Support\EmailSecurity;

use App\Domain\EmailSecurity\Checks\TlsRpt\Contracts\TlsRptDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\TlsRpt\Evaluation\TlsRptDnsQueryResult;

final class FakeTlsRptDnsResolver implements TlsRptDnsResolverInterface
{
    /** @var array<string, TlsRptDnsQueryResult> */
    private array $txtResponses = [];

    /** @var array<string, TlsRptDnsQueryResult> */
    private array $cnameResponses = [];

    public function setTxt(string $hostname, TlsRptDnsQueryResult $result): void
    {
        $this->txtResponses[strtolower($hostname)] = $result;
    }

    public function setCname(string $hostname, TlsRptDnsQueryResult $result): void
    {
        $this->cnameResponses[strtolower($hostname)] = $result;
    }

    public function txt(string $hostname): TlsRptDnsQueryResult
    {
        $hostname = strtolower(rtrim($hostname, '.'));

        return $this->txtResponses[$hostname] ?? new TlsRptDnsQueryResult(
            hostname: $hostname,
            success: true,
            outcome: TlsRptDnsQueryResult::OUTCOME_EMPTY,
        );
    }

    public function cname(string $hostname): TlsRptDnsQueryResult
    {
        $hostname = strtolower(rtrim($hostname, '.'));

        return $this->cnameResponses[$hostname] ?? new TlsRptDnsQueryResult(
            hostname: $hostname,
            success: true,
            outcome: TlsRptDnsQueryResult::OUTCOME_EMPTY,
        );
    }

    public function reset(): void
    {
        $this->txtResponses = [];
        $this->cnameResponses = [];
    }
}
