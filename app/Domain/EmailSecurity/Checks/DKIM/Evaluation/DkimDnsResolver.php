<?php

namespace App\Domain\EmailSecurity\Checks\DKIM\Evaluation;

use App\Domain\EmailSecurity\Checks\DKIM\Contracts\DkimDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\DKIM\Support\DkimTxtReconstructor;

final class DkimDnsResolver implements DkimDnsResolverInterface
{
    /** @var array<string, DkimDnsQueryResult> */
    private array $cache = [];

    public function txt(string $hostname): DkimDnsQueryResult
    {
        $hostname = strtolower(rtrim(trim($hostname), '.'));
        $key = "RESOLVE:{$hostname}";

        if (isset($this->cache[$key])) {
            return $this->cache[$key];
        }

        $result = $this->resolveWithCname($hostname, [], 0);
        $this->cache[$key] = $result;

        return $result;
    }

    /**
     * @param list<string> $visited
     */
    private function resolveWithCname(string $hostname, array $visited, int $depth): DkimDnsQueryResult
    {
        if (in_array($hostname, $visited, true)) {
            return new DkimDnsQueryResult(
                hostname: $hostname,
                success: false,
                error: 'CNAME cycle detected',
                outcome: DkimDnsQueryResult::OUTCOME_ERROR,
                cnamePath: $visited,
            );
        }

        $maxDepth = (int) config('dkim.cname_max_depth', 5);
        if ($depth > $maxDepth) {
            return new DkimDnsQueryResult(
                hostname: $hostname,
                success: false,
                error: 'CNAME depth limit exceeded',
                outcome: DkimDnsQueryResult::OUTCOME_ERROR,
                cnamePath: $visited,
            );
        }

        $txtKey = "TXT:{$hostname}";
        if (isset($this->cache[$txtKey])) {
            return $this->cache[$txtKey];
        }

        $txtRows = @dns_get_record($hostname, DNS_TXT);
        if ($txtRows === false) {
            $txtRows = [];
        }

        $reconstructed = DkimTxtReconstructor::allFromDnsRows(is_array($txtRows) ? $txtRows : []);
        $dkimRecords = array_values(array_filter($reconstructed, [DkimTxtReconstructor::class, 'looksLikeDkimKey']));

        if ($dkimRecords !== []) {
            $ttl = isset($txtRows[0]['ttl']) ? (int) $txtRows[0]['ttl'] : null;
            $result = new DkimDnsQueryResult(
                hostname: $hostname,
                success: true,
                rawRows: is_array($txtRows) ? $txtRows : [],
                reconstructedTxt: $dkimRecords,
                ttl: $ttl,
                outcome: DkimDnsQueryResult::OUTCOME_ANSWER,
                cnamePath: $visited,
            );
            $this->cache[$txtKey] = $result;

            return $result;
        }

        $cnameKey = "CNAME:{$hostname}";
        if (isset($this->cache[$cnameKey])) {
            $cached = $this->cache[$cnameKey];
            if ($cached->cnameTarget !== null) {
                $visited[] = $hostname;

                return $this->resolveWithCname($cached->cnameTarget, $visited, $depth + 1);
            }
        }

        $cnameRows = @dns_get_record($hostname, DNS_CNAME);
        if (is_array($cnameRows) && $cnameRows !== []) {
            $target = strtolower(rtrim((string) ($cnameRows[0]['target'] ?? ''), '.'));
            if ($target !== '') {
                $this->cache[$cnameKey] = new DkimDnsQueryResult(
                    hostname: $hostname,
                    success: true,
                    outcome: DkimDnsQueryResult::OUTCOME_ANSWER,
                    cnameTarget: $target,
                    cnamePath: array_merge($visited, [$hostname]),
                );
                $visited[] = $hostname;

                return $this->resolveWithCname($target, $visited, $depth + 1);
            }
        }

        if ($txtRows === false) {
            return new DkimDnsQueryResult(
                hostname: $hostname,
                success: false,
                error: 'dns_get_record returned false',
                outcome: DkimDnsQueryResult::OUTCOME_ERROR,
                cnamePath: $visited,
            );
        }

        if ($reconstructed === []) {
            return new DkimDnsQueryResult(
                hostname: $hostname,
                success: true,
                rawRows: is_array($txtRows) ? $txtRows : [],
                reconstructedTxt: [],
                outcome: DkimDnsQueryResult::OUTCOME_EMPTY,
                cnamePath: $visited,
            );
        }

        return new DkimDnsQueryResult(
            hostname: $hostname,
            success: true,
            rawRows: is_array($txtRows) ? $txtRows : [],
            reconstructedTxt: $reconstructed,
            ttl: isset($txtRows[0]['ttl']) ? (int) $txtRows[0]['ttl'] : null,
            outcome: DkimDnsQueryResult::OUTCOME_ANSWER,
            cnamePath: $visited,
        );
    }

    public function reset(): void
    {
        $this->cache = [];
    }
}
