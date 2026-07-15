<?php

namespace Tests\Support\EmailSecurity;

use App\Domain\EmailSecurity\Checks\Bimi\Contracts\BimiDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\Bimi\DTO\BimiDnsQueryResult;

final class FakeBimiDnsResolver implements BimiDnsResolverInterface
{
    /** @var array<string, BimiDnsQueryResult> */
    private array $txt = [];

    /** @var array<string, BimiDnsQueryResult> */
    private array $cname = [];

    public function setTxt(string $hostname, BimiDnsQueryResult $result): void
    {
        $this->txt[strtolower($hostname)] = $result;
    }

    public function setCname(string $hostname, BimiDnsQueryResult $result): void
    {
        $this->cname[strtolower($hostname)] = $result;
    }

    public function txt(string $hostname): BimiDnsQueryResult
    {
        $hostname = strtolower(rtrim(trim($hostname), '.'));

        return $this->txt[$hostname] ?? new BimiDnsQueryResult(
            hostname: $hostname,
            success: true,
            outcome: BimiDnsQueryResult::OUTCOME_EMPTY,
            reconstructedTxt: [],
        );
    }

    public function cname(string $hostname): BimiDnsQueryResult
    {
        $hostname = strtolower(rtrim(trim($hostname), '.'));

        return $this->cname[$hostname] ?? new BimiDnsQueryResult(
            hostname: $hostname,
            success: true,
            outcome: BimiDnsQueryResult::OUTCOME_EMPTY,
            cnameTargets: [],
        );
    }

    public function reset(): void
    {
        $this->txt = [];
        $this->cname = [];
    }
}
