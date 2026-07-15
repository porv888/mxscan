<?php

namespace App\Domain\EmailSecurity\Checks\TlsRpt\Evaluation;

use App\Domain\EmailSecurity\Checks\TlsRpt\Contracts\TlsRptDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\TlsRpt\Support\TlsRptTxtReconstructor;

final class TlsRptDnsResolver implements TlsRptDnsResolverInterface
{
    /** @var array<string, TlsRptDnsQueryResult> */
    private array $cache = [];

    public function txt(string $hostname): TlsRptDnsQueryResult
    {
        $hostname = strtolower(rtrim(trim($hostname), '.'));
        $key = "TXT:{$hostname}";

        if (isset($this->cache[$key])) {
            return $this->cache[$key];
        }

        $rawRows = @dns_get_record($hostname, DNS_TXT);
        if ($rawRows === false || !is_array($rawRows)) {
            $this->cache[$key] = new TlsRptDnsQueryResult(
                hostname: $hostname,
                success: false,
                error: 'dns_get_record returned false',
                outcome: TlsRptDnsQueryResult::OUTCOME_ERROR,
            );

            return $this->cache[$key];
        }

        $reconstructed = TlsRptTxtReconstructor::allFromDnsRows($rawRows);
        $ttl = isset($rawRows[0]['ttl']) ? (int) $rawRows[0]['ttl'] : null;

        $this->cache[$key] = new TlsRptDnsQueryResult(
            hostname: $hostname,
            success: true,
            rawRows: $rawRows,
            reconstructedTxt: $reconstructed,
            ttl: $ttl,
            outcome: $reconstructed === [] ? TlsRptDnsQueryResult::OUTCOME_EMPTY : TlsRptDnsQueryResult::OUTCOME_SUCCESS,
        );

        return $this->cache[$key];
    }

    public function cname(string $hostname): TlsRptDnsQueryResult
    {
        $hostname = strtolower(rtrim(trim($hostname), '.'));
        $key = "CNAME:{$hostname}";

        if (isset($this->cache[$key])) {
            return $this->cache[$key];
        }

        $rawRows = @dns_get_record($hostname, DNS_CNAME);
        if ($rawRows === false || !is_array($rawRows)) {
            $this->cache[$key] = new TlsRptDnsQueryResult(
                hostname: $hostname,
                success: false,
                error: 'dns_get_record returned false',
                outcome: TlsRptDnsQueryResult::OUTCOME_ERROR,
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

        $this->cache[$key] = new TlsRptDnsQueryResult(
            hostname: $hostname,
            success: true,
            rawRows: $rawRows,
            cnameTargets: $targets,
            ttl: $ttl,
            outcome: $targets === [] ? TlsRptDnsQueryResult::OUTCOME_EMPTY : TlsRptDnsQueryResult::OUTCOME_SUCCESS,
        );

        return $this->cache[$key];
    }

    public function reset(): void
    {
        $this->cache = [];
    }
}
