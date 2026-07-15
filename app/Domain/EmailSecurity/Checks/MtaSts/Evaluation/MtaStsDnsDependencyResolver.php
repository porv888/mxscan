<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts\Evaluation;

use App\Domain\EmailSecurity\Checks\MtaSts\Contracts\MtaStsDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\MtaSts\Support\MtaStsTxtReconstructor;

final class MtaStsDnsDependencyResolver implements MtaStsDnsResolverInterface
{
    /** @var array<string, MtaStsDnsQueryResult> */
    private array $cache = [];

    public function txt(string $hostname): MtaStsDnsQueryResult
    {
        $hostname = strtolower(rtrim(trim($hostname), '.'));
        $key = "TXT:{$hostname}";

        if (isset($this->cache[$key])) {
            return $this->cache[$key];
        }

        $rawRows = @dns_get_record($hostname, DNS_TXT);
        if ($rawRows === false || !is_array($rawRows)) {
            $this->cache[$key] = new MtaStsDnsQueryResult(
                hostname: $hostname,
                success: false,
                error: 'dns_get_record returned false',
                outcome: MtaStsDnsQueryResult::OUTCOME_ERROR,
            );

            return $this->cache[$key];
        }

        $reconstructed = MtaStsTxtReconstructor::allFromDnsRows($rawRows);
        $ttl = isset($rawRows[0]['ttl']) ? (int) $rawRows[0]['ttl'] : null;

        $this->cache[$key] = new MtaStsDnsQueryResult(
            hostname: $hostname,
            success: true,
            rawRows: $rawRows,
            reconstructedTxt: $reconstructed,
            ttl: $ttl,
            outcome: $reconstructed === [] ? MtaStsDnsQueryResult::OUTCOME_EMPTY : MtaStsDnsQueryResult::OUTCOME_SUCCESS,
        );

        return $this->cache[$key];
    }

    public function cname(string $hostname): MtaStsDnsQueryResult
    {
        $hostname = strtolower(rtrim(trim($hostname), '.'));
        $key = "CNAME:{$hostname}";

        if (isset($this->cache[$key])) {
            return $this->cache[$key];
        }

        $rawRows = @dns_get_record($hostname, DNS_CNAME);
        if ($rawRows === false || !is_array($rawRows)) {
            $this->cache[$key] = new MtaStsDnsQueryResult(
                hostname: $hostname,
                success: false,
                error: 'dns_get_record returned false',
                outcome: MtaStsDnsQueryResult::OUTCOME_ERROR,
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

        $this->cache[$key] = new MtaStsDnsQueryResult(
            hostname: $hostname,
            success: true,
            rawRows: $rawRows,
            cnameTargets: $targets,
            ttl: $ttl,
            outcome: $targets === [] ? MtaStsDnsQueryResult::OUTCOME_EMPTY : MtaStsDnsQueryResult::OUTCOME_SUCCESS,
        );

        return $this->cache[$key];
    }

    public function reset(): void
    {
        $this->cache = [];
    }
}
