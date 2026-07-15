<?php

namespace App\Domain\EmailSecurity\Checks\Mx\Evaluation;

use App\Domain\EmailSecurity\Checks\Mx\Contracts\MxDnsResolverInterface;

final class MxDnsResolver implements MxDnsResolverInterface
{
    /** @var array<string, MxDnsQueryResult> */
    private array $cache = [];

    public function mx(string $domain): MxDnsQueryResult
    {
        return $this->query($domain, DNS_MX, 'MX', function (array $rows): array {
            $addresses = [];
            foreach ($rows as $row) {
                if (isset($row['target'])) {
                    $addresses[] = (string) $row['target'];
                }
            }

            return ['addresses' => $addresses, 'cnameTargets' => []];
        });
    }

    public function a(string $hostname): MxDnsQueryResult
    {
        return $this->query($hostname, DNS_A, 'A', function (array $rows): array {
            $addresses = [];
            foreach ($rows as $row) {
                if (isset($row['ip'])) {
                    $addresses[] = (string) $row['ip'];
                }
            }

            return ['addresses' => $addresses, 'cnameTargets' => []];
        });
    }

    public function aaaa(string $hostname): MxDnsQueryResult
    {
        return $this->query($hostname, DNS_AAAA, 'AAAA', function (array $rows): array {
            $addresses = [];
            foreach ($rows as $row) {
                if (isset($row['ipv6'])) {
                    $addresses[] = (string) $row['ipv6'];
                }
            }

            return ['addresses' => $addresses, 'cnameTargets' => []];
        });
    }

    public function cname(string $hostname): MxDnsQueryResult
    {
        return $this->query($hostname, DNS_CNAME, 'CNAME', function (array $rows): array {
            $targets = [];
            foreach ($rows as $row) {
                if (isset($row['target']) && is_string($row['target'])) {
                    $targets[] = strtolower(rtrim($row['target'], '.'));
                }
            }

            return ['addresses' => [], 'cnameTargets' => $targets];
        });
    }

    /**
     * @param callable(array<int, array<string, mixed>>): array{addresses: list<string>, cnameTargets: list<string>} $extract
     */
    private function query(string $hostname, int $type, string $typeLabel, callable $extract): MxDnsQueryResult
    {
        $hostname = strtolower(rtrim(trim($hostname), '.'));
        $key = "{$typeLabel}:{$hostname}";

        if (isset($this->cache[$key])) {
            return $this->cache[$key];
        }

        $rawRows = @dns_get_record($hostname, $type);

        if ($rawRows === false) {
            $this->cache[$key] = new MxDnsQueryResult(
                hostname: $hostname,
                success: false,
                error: 'dns_get_record returned false',
                outcome: MxDnsQueryResult::OUTCOME_ERROR,
            );

            return $this->cache[$key];
        }

        if (!is_array($rawRows)) {
            $this->cache[$key] = new MxDnsQueryResult(
                hostname: $hostname,
                success: false,
                error: 'Malformed DNS response',
                outcome: MxDnsQueryResult::OUTCOME_MALFORMED,
            );

            return $this->cache[$key];
        }

        if ($rawRows === []) {
            $this->cache[$key] = new MxDnsQueryResult(
                hostname: $hostname,
                success: true,
                rawRows: [],
                outcome: MxDnsQueryResult::OUTCOME_NO_DATA,
            );

            return $this->cache[$key];
        }

        $extracted = $extract($rawRows);
        $ttl = isset($rawRows[0]['ttl']) ? (int) $rawRows[0]['ttl'] : null;

        $this->cache[$key] = new MxDnsQueryResult(
            hostname: $hostname,
            success: true,
            rawRows: $rawRows,
            addresses: $extracted['addresses'],
            cnameTargets: $extracted['cnameTargets'],
            ttl: $ttl,
            outcome: MxDnsQueryResult::OUTCOME_ANSWER,
        );

        return $this->cache[$key];
    }
}
