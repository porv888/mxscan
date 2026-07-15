<?php

namespace Tests\Support\EmailSecurity;

use App\Domain\EmailSecurity\Checks\Blacklist\Contracts\BlacklistDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\Blacklist\Evaluation\BlacklistDnsQueryResult;

final class FakeBlacklistDnsResolver implements BlacklistDnsResolverInterface
{
    /** @var array<string, BlacklistDnsQueryResult> */
    private array $responses = [];

    public function setResponse(string $queryHost, BlacklistDnsQueryResult $result): void
    {
        $this->responses[strtolower($queryHost)] = $result;
    }

    public function setListed(string $queryHost, string $code = '127.0.0.2'): void
    {
        $this->setResponse($queryHost, new BlacklistDnsQueryResult(
            queryHost: $queryHost,
            success: true,
            dnsOutcome: 'ANSWER',
            addresses: [$code],
        ));
    }

    public function setCleanNxdomain(string $queryHost): void
    {
        $this->setResponse($queryHost, new BlacklistDnsQueryResult(
            queryHost: $queryHost,
            success: true,
            dnsOutcome: 'NXDOMAIN',
        ));
    }

    public function setBlocked(string $queryHost, string $code = '127.255.255.254'): void
    {
        $this->setResponse($queryHost, new BlacklistDnsQueryResult(
            queryHost: $queryHost,
            success: true,
            dnsOutcome: 'ANSWER',
            addresses: [$code],
        ));
    }

    public function setTimeout(string $queryHost): void
    {
        $this->setResponse($queryHost, new BlacklistDnsQueryResult(
            queryHost: $queryHost,
            success: false,
            dnsOutcome: 'TIMEOUT',
            error: 'timeout',
        ));
    }

    public function setDefaultClean(): void
    {
        // Default handled in queryA
    }

    /** @var bool */
    private bool $defaultListed = false;

    public function setDefaultListed(bool $listed = true): void
    {
        $this->defaultListed = $listed;
    }

    public function queryA(string $queryHost, int $timeoutMs): BlacklistDnsQueryResult
    {
        $key = strtolower($queryHost);

        if (isset($this->responses[$key])) {
            return $this->responses[$key];
        }

        if ($this->defaultListed) {
            return new BlacklistDnsQueryResult(
                queryHost: $queryHost,
                success: true,
                dnsOutcome: 'ANSWER',
                addresses: ['127.0.0.2'],
            );
        }

        return new BlacklistDnsQueryResult(
            queryHost: $queryHost,
            success: true,
            dnsOutcome: 'NXDOMAIN',
        );
    }
}
