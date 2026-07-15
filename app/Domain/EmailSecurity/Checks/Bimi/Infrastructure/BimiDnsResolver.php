<?php

namespace App\Domain\EmailSecurity\Checks\Bimi\Infrastructure;

use App\Domain\EmailSecurity\Checks\Bimi\Contracts\BimiDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\Bimi\DTO\BimiDnsQueryResult;
use App\Domain\EmailSecurity\Checks\Bimi\Support\BimiTxtReconstructor;

final class BimiDnsResolver implements BimiDnsResolverInterface
{
    /** @var array<string, BimiDnsQueryResult> */
    private array $cache = [];

    public function txt(string $hostname): BimiDnsQueryResult
    {
        $hostname = strtolower(rtrim(trim($hostname), '.'));
        $key = "TXT:{$hostname}";

        if (isset($this->cache[$key])) {
            return $this->cache[$key];
        }

        $rawRows = @dns_get_record($hostname, DNS_TXT);
        if ($rawRows === false || !is_array($rawRows)) {
            $this->cache[$key] = new BimiDnsQueryResult(
                hostname: $hostname,
                success: false,
                error: 'dns_get_record returned false',
                outcome: BimiDnsQueryResult::OUTCOME_ERROR,
            );

            return $this->cache[$key];
        }

        $reconstructed = BimiTxtReconstructor::allFromDnsRows($rawRows);
        $ttl = isset($rawRows[0]['ttl']) ? (int) $rawRows[0]['ttl'] : null;

        $this->cache[$key] = new BimiDnsQueryResult(
            hostname: $hostname,
            success: true,
            rawRows: $rawRows,
            reconstructedTxt: $reconstructed,
            ttl: $ttl,
            outcome: $reconstructed === [] ? BimiDnsQueryResult::OUTCOME_EMPTY : BimiDnsQueryResult::OUTCOME_SUCCESS,
        );

        return $this->cache[$key];
    }

    public function cname(string $hostname): BimiDnsQueryResult
    {
        $hostname = strtolower(rtrim(trim($hostname), '.'));
        $key = "CNAME:{$hostname}";

        if (isset($this->cache[$key])) {
            return $this->cache[$key];
        }

        $rawRows = @dns_get_record($hostname, DNS_CNAME);
        if ($rawRows === false || !is_array($rawRows)) {
            $this->cache[$key] = new BimiDnsQueryResult(
                hostname: $hostname,
                success: false,
                error: 'dns_get_record returned false',
                outcome: BimiDnsQueryResult::OUTCOME_ERROR,
            );

            return $this->cache[$key];
        }

        $targets = [];
        foreach ($rawRows as $row) {
            if (isset($row['target']) && is_string($row['target'])) {
                $targets[] = strtolower(rtrim($row['target'], '.'));
            }
        }

        $ttl = isset($rawRows[0]['ttl']) ? (int) $rawRows[0]['ttl'] : null;

        $this->cache[$key] = new BimiDnsQueryResult(
            hostname: $hostname,
            success: true,
            rawRows: $rawRows,
            cnameTargets: $targets,
            ttl: $ttl,
            outcome: $targets === [] ? BimiDnsQueryResult::OUTCOME_EMPTY : BimiDnsQueryResult::OUTCOME_SUCCESS,
        );

        return $this->cache[$key];
    }

    public function reset(): void
    {
        $this->cache = [];
    }
}
