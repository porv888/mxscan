<?php

namespace Tests\Support\EmailSecurity;

use App\Domain\EmailSecurity\Checks\MtaSts\Contracts\MtaStsDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\MtaSts\Evaluation\MtaStsDnsQueryResult;

final class FakeMtaStsDnsResolver implements MtaStsDnsResolverInterface
{
    /** @var array<string, MtaStsDnsQueryResult> */
    private array $txtResponses = [];

    /** @var array<string, MtaStsDnsQueryResult> */
    private array $cnameResponses = [];

    public function setTxt(string $hostname, MtaStsDnsQueryResult $result): void
    {
        $this->txtResponses[strtolower($hostname)] = $result;
    }

    public function setCname(string $hostname, MtaStsDnsQueryResult $result): void
    {
        $this->cnameResponses[strtolower($hostname)] = $result;
    }

    public function txt(string $hostname): MtaStsDnsQueryResult
    {
        $hostname = strtolower(rtrim($hostname, '.'));

        return $this->txtResponses[$hostname] ?? new MtaStsDnsQueryResult(
            hostname: $hostname,
            success: true,
            outcome: MtaStsDnsQueryResult::OUTCOME_EMPTY,
        );
    }

    public function cname(string $hostname): MtaStsDnsQueryResult
    {
        $hostname = strtolower(rtrim($hostname, '.'));

        return $this->cnameResponses[$hostname] ?? new MtaStsDnsQueryResult(
            hostname: $hostname,
            success: true,
            outcome: MtaStsDnsQueryResult::OUTCOME_EMPTY,
        );
    }

    public function reset(): void
    {
        $this->txtResponses = [];
        $this->cnameResponses = [];
    }
}
