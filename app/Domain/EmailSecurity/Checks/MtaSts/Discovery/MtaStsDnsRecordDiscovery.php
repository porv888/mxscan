<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts\Discovery;

use App\Domain\EmailSecurity\Checks\MtaSts\Contracts\MtaStsDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\MtaSts\Evaluation\MtaStsDnsQueryResult;
use App\Domain\EmailSecurity\Checks\MtaSts\Support\MtaStsTxtReconstructor;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;

final class MtaStsDnsRecordDiscovery
{
    public function __construct(
        private MtaStsDnsResolverInterface $resolver,
    ) {
    }

    public function discover(string $domain, ?DnsCollectionResultDTO $dns): MtaStsDiscoveryResult
    {
        $domain = strtolower(rtrim(trim($domain), '.'));
        $hostname = '_mta-sts.' . $domain;

        if ($dns !== null && $this->hasScanEvidence($domain, $dns)) {
            return $this->discoverFromEvidence(
                $domain,
                '_mta-sts.' . $domain,
                $dns->mtaStsTxtRecords,
                'dns_collection',
                [],
            );
        }

        return $this->discoverWithCname($domain, $hostname, [], 0);
    }

    /**
     * @param list<string> $cnamePath
     */
    private function discoverWithCname(string $domain, string $hostname, array $cnamePath, int $depth): MtaStsDiscoveryResult
    {
        if ($depth >= MtaStsDiscoveryResult::MAX_CNAME_DEPTH) {
            return new MtaStsDiscoveryResult(
                queriedDomain: $domain,
                hostname: '_mta-sts.' . $domain,
                source: 'dns_query',
                dnsFailure: true,
                dnsError: 'CNAME chain exceeded maximum depth',
                dnsOutcome: 'cname_depth_exceeded',
                cnamePath: $cnamePath,
                resolverDiagnostics: [[
                    'hostname' => $hostname,
                    'outcome' => 'cname_depth_exceeded',
                ]],
            );
        }

        if (in_array($hostname, $cnamePath, true)) {
            return new MtaStsDiscoveryResult(
                queriedDomain: $domain,
                hostname: '_mta-sts.' . $domain,
                source: 'dns_query',
                dnsFailure: true,
                dnsError: 'CNAME loop detected',
                dnsOutcome: 'cname_loop',
                cnamePath: $cnamePath,
                resolverDiagnostics: [[
                    'hostname' => $hostname,
                    'outcome' => 'cname_loop',
                ]],
            );
        }

        $cnamePath[] = $hostname;

        $cnameQuery = $this->resolver->cname($hostname);
        if ($cnameQuery->failed()) {
            return $this->failureResult($domain, $hostname, $cnamePath, $cnameQuery, 'dns_query');
        }

        if ($cnameQuery->cnameTargets !== []) {
            $target = $cnameQuery->cnameTargets[0];

            return $this->discoverWithCname($domain, $target, $cnamePath, $depth + 1);
        }

        $txtQuery = $this->resolver->txt($hostname);
        if ($txtQuery->failed()) {
            return $this->failureResult($domain, $hostname, $cnamePath, $txtQuery, 'dns_query');
        }

        $evidence = [];
        foreach ($txtQuery->reconstructedTxt as $index => $txt) {
            $evidence[] = [
                'host' => $hostname,
                'txt' => $txt,
                'ttl' => $txtQuery->ttl,
                'rr_index' => $index,
            ];
        }

        return $this->discoverFromEvidence($domain, '_mta-sts.' . $domain, $evidence, 'dns_query', $cnamePath);
    }

    /**
     * @param list<array{host: string, txt: string|list<string>, ttl: ?int, rr_index?: int}> $evidence
     * @param list<string> $cnamePath
     */
    private function discoverFromEvidence(
        string $domain,
        string $displayHostname,
        array $evidence,
        string $source,
        array $cnamePath,
    ): MtaStsDiscoveryResult {
        $txtEvidence = [];
        $allTxt = [];

        foreach ($evidence as $index => $entry) {
            $joined = is_array($entry['txt'] ?? null)
                ? implode('', $entry['txt'])
                : (string) ($entry['txt'] ?? '');
            $txtEvidence[] = [
                'host' => $entry['host'] ?? $displayHostname,
                'txt' => $joined,
                'ttl' => $entry['ttl'] ?? null,
                'rr_index' => $entry['rr_index'] ?? $index,
            ];
            $allTxt[] = $joined;
        }

        $indicators = MtaStsTxtReconstructor::selectIndicatorRecords($allTxt);

        if (count($indicators) > 1) {
            return new MtaStsDiscoveryResult(
                queriedDomain: $domain,
                hostname: $displayHostname,
                source: $source,
                record: $indicators[0],
                multipleRecords: true,
                txtEvidence: $txtEvidence,
                indicatorRecords: $indicators,
                cnamePath: $cnamePath,
                ttl: $txtEvidence[0]['ttl'] ?? null,
            );
        }

        if (count($indicators) === 1) {
            return new MtaStsDiscoveryResult(
                queriedDomain: $domain,
                hostname: $displayHostname,
                source: $source,
                record: $indicators[0],
                txtEvidence: $txtEvidence,
                indicatorRecords: $indicators,
                cnamePath: $cnamePath,
                ttl: $txtEvidence[0]['ttl'] ?? null,
            );
        }

        return new MtaStsDiscoveryResult(
            queriedDomain: $domain,
            hostname: $displayHostname,
            source: $source,
            txtEvidence: $txtEvidence,
            cnamePath: $cnamePath,
            ttl: $txtEvidence[0]['ttl'] ?? null,
        );
    }

    /**
     * @param list<string> $cnamePath
     */
    private function failureResult(
        string $domain,
        string $hostname,
        array $cnamePath,
        MtaStsDnsQueryResult $query,
        string $source,
    ): MtaStsDiscoveryResult {
        return new MtaStsDiscoveryResult(
            queriedDomain: $domain,
            hostname: '_mta-sts.' . $domain,
            source: $source,
            dnsFailure: true,
            dnsError: $query->error,
            dnsOutcome: $query->outcome,
            cnamePath: $cnamePath,
            resolverDiagnostics: [[
                'hostname' => $hostname,
                'outcome' => $query->outcome,
                'error' => $query->error,
            ]],
        );
    }

    private function hasScanEvidence(string $domain, DnsCollectionResultDTO $dns): bool
    {
        return $dns->mtaStsTxtRecords !== []
            || (($dns->records['MTA-STS'] ?? null) !== null);
    }
}
