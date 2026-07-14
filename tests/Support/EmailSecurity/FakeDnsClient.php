<?php

namespace Tests\Support\EmailSecurity;

use App\Services\Dns\DnsClient;
use App\Services\Dns\DnsResult;

final class FakeDnsClient extends DnsClient
{
    /** @var array<string, DnsResult> */
    private array $txtResponses = [];

    /** @var array<string, list<string>> */
    private array $aResponses = [];

    /** @var array<string, list<string>> */
    private array $aaaaResponses = [];

    /** @var array<string, list<string>> */
    private array $mxResponses = [];

    public function __construct()
    {
        parent::__construct(1500, 0);
    }

    public function setTxt(string $host, DnsResult $result): void
    {
        $this->txtResponses[strtolower($host)] = $result;
    }

    /**
     * @param list<string> $records
     */
    public function setA(string $host, array $records): void
    {
        $this->aResponses[strtolower($host)] = $records;
    }

    /**
     * @param list<string> $records
     */
    public function setMx(string $host, array $records): void
    {
        $this->mxResponses[strtolower($host)] = $records;
    }

    public function getTxtResult(string $domain): DnsResult
    {
        return $this->txtResponses[strtolower($domain)] ?? new DnsResult([], true);
    }

    public function getA(string $domain): array
    {
        return $this->aResponses[strtolower($domain)] ?? [];
    }

    public function getAAAA(string $domain): array
    {
        return $this->aaaaResponses[strtolower($domain)] ?? [];
    }

    public function getMx(string $domain): array
    {
        return $this->mxResponses[strtolower($domain)] ?? [];
    }
}
