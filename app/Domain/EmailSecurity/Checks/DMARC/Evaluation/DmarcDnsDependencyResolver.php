<?php

namespace App\Domain\EmailSecurity\Checks\DMARC\Evaluation;

use App\Domain\EmailSecurity\Checks\DMARC\Contracts\DmarcDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\DMARC\Support\DmarcTxtReconstructor;

final class DmarcDnsDependencyResolver implements DmarcDnsResolverInterface
{
    /** @var array<string, DmarcDnsQueryResult> */
    private array $cache = [];

    public function txt(string $hostname): DmarcDnsQueryResult
    {
        $hostname = strtolower(trim($hostname));
        $key = "TXT:{$hostname}";

        if (isset($this->cache[$key])) {
            return $this->cache[$key];
        }

        $rawRows = @dns_get_record($hostname, DNS_TXT);
        if ($rawRows === false || !is_array($rawRows)) {
            $this->cache[$key] = new DmarcDnsQueryResult(
                hostname: $hostname,
                success: false,
                error: 'dns_get_record returned false',
                outcome: DmarcDnsQueryResult::OUTCOME_ERROR,
            );

            return $this->cache[$key];
        }

        $reconstructed = DmarcTxtReconstructor::allFromDnsRows($rawRows);
        $ttl = isset($rawRows[0]['ttl']) ? (int) $rawRows[0]['ttl'] : null;

        $this->cache[$key] = new DmarcDnsQueryResult(
            hostname: $hostname,
            success: true,
            rawRows: $rawRows,
            reconstructedTxt: $reconstructed,
            ttl: $ttl,
            outcome: $reconstructed === [] ? DmarcDnsQueryResult::OUTCOME_EMPTY : DmarcDnsQueryResult::OUTCOME_SUCCESS,
        );

        return $this->cache[$key];
    }

    public function reset(): void
    {
        $this->cache = [];
    }
}
