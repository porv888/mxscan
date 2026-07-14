<?php

namespace App\Domain\EmailSecurity\Checks\SPF\Evaluation;

use App\Services\Dns\DnsClient;

final class SpfDnsDependencyResolver
{
    /** @var array<string, SpfDnsQueryResult> */
    private array $cache = [];

    public function __construct(
        private DnsClient $dnsClient,
    ) {
    }

    public function txt(string $host): SpfDnsQueryResult
    {
        return $this->cached('TXT', $host, function () use ($host) {
            $result = $this->dnsClient->getTxtResult($host);

            return new SpfDnsQueryResult(
                host: $host,
                type: 'TXT',
                success: $result->success,
                records: $result->records,
                error: $result->error,
                empty: $result->isEmpty(),
                nxdomain: $result->success && $result->isEmpty(),
                outcome: $this->resolveOutcome($result),
            );
        });
    }

    public function a(string $host): SpfDnsQueryResult
    {
        return $this->cached('A', $host, function () use ($host) {
            $records = $this->dnsClient->getA($host);

            return new SpfDnsQueryResult(
                host: $host,
                type: 'A',
                success: true,
                records: $records,
                empty: $records === [],
                nxdomain: $records === [],
                outcome: $records === [] ? SpfDnsQueryResult::OUTCOME_EMPTY : SpfDnsQueryResult::OUTCOME_SUCCESS,
            );
        });
    }

    public function aaaa(string $host): SpfDnsQueryResult
    {
        return $this->cached('AAAA', $host, function () use ($host) {
            $records = $this->dnsClient->getAAAA($host);

            return new SpfDnsQueryResult(
                host: $host,
                type: 'AAAA',
                success: true,
                records: $records,
                empty: $records === [],
                nxdomain: $records === [],
                outcome: $records === [] ? SpfDnsQueryResult::OUTCOME_EMPTY : SpfDnsQueryResult::OUTCOME_SUCCESS,
            );
        });
    }

    public function mx(string $host): SpfDnsQueryResult
    {
        return $this->cached('MX', $host, function () use ($host) {
            $records = $this->dnsClient->getMx($host);

            return new SpfDnsQueryResult(
                host: $host,
                type: 'MX',
                success: true,
                records: $records,
                empty: $records === [],
                nxdomain: $records === [],
                outcome: $records === [] ? SpfDnsQueryResult::OUTCOME_EMPTY : SpfDnsQueryResult::OUTCOME_SUCCESS,
            );
        });
    }

    public function reset(): void
    {
        $this->cache = [];
    }

    /**
     * @param callable(): SpfDnsQueryResult $callback
     */
    private function cached(string $type, string $host, callable $callback): SpfDnsQueryResult
    {
        $host = strtolower(trim($host));
        $key = "{$type}:{$host}";

        if (!isset($this->cache[$key])) {
            $this->cache[$key] = $callback();
        }

        return $this->cache[$key];
    }

    private function resolveOutcome(\App\Services\Dns\DnsResult $result): string
    {
        if (!$result->success) {
            $error = strtolower((string) $result->error);
            if (str_contains($error, 'timeout') || str_contains($error, 'timed out')) {
                return SpfDnsQueryResult::OUTCOME_TIMEOUT;
            }
            if (str_contains($error, 'servfail')) {
                return SpfDnsQueryResult::OUTCOME_SERVFAIL;
            }

            return SpfDnsQueryResult::OUTCOME_ERROR;
        }

        if ($result->isEmpty()) {
            return SpfDnsQueryResult::OUTCOME_EMPTY;
        }

        return SpfDnsQueryResult::OUTCOME_SUCCESS;
    }
}
