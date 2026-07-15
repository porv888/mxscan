<?php

namespace Tests\Support\EmailSecurity;

use App\Domain\EmailSecurity\Checks\DKIM\Contracts\DkimDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\DKIM\Evaluation\DkimDnsQueryResult;

final class DkimDnsMockResolver implements DkimDnsResolverInterface
{
    /** @var array<string, DkimDnsQueryResult> */
    private array $responses = [];

    /** @var list<string> */
    private array $queries = [];

    public function setTxt(string $hostname, DkimDnsQueryResult $result): void
    {
        $this->responses['RESOLVE:' . strtolower(rtrim($hostname, '.'))] = $result;
    }

    /**
     * @return list<string>
     */
    public function queries(): array
    {
        return $this->queries;
    }

    public function txt(string $hostname): DkimDnsQueryResult
    {
        $hostname = strtolower(rtrim(trim($hostname), '.'));
        $this->queries[] = $hostname;
        $key = 'RESOLVE:' . $hostname;

        return $this->responses[$key] ?? new DkimDnsQueryResult(
            hostname: $hostname,
            success: true,
            outcome: DkimDnsQueryResult::OUTCOME_EMPTY,
            reconstructedTxt: [],
        );
    }

    public function reset(): void
    {
        $this->responses = [];
        $this->queries = [];
    }
}
