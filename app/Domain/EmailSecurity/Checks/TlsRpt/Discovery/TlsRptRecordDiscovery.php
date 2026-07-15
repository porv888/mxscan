<?php

namespace App\Domain\EmailSecurity\Checks\TlsRpt\Discovery;

use App\Domain\EmailSecurity\Checks\TlsRpt\Contracts\TlsRptDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\TlsRpt\Evaluation\TlsRptDnsQueryResult;
use App\Domain\EmailSecurity\Checks\TlsRpt\Support\TlsRptTxtReconstructor;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;

final class TlsRptRecordDiscovery
{
    public function __construct(
        private TlsRptDnsResolverInterface $resolver,
    ) {
    }

    public function discover(string $domain, ?DnsCollectionResultDTO $dns): TlsRptDiscoveryResult
    {
        $domain = strtolower(rtrim(trim($domain), '.'));
        $hostname = '_smtp._tls.' . $domain;

        if ($dns !== null && $this->hasScanEvidence($domain, $dns)) {
            return $this->discoverFromEvidence(
                $domain,
                $hostname,
                $dns->tlsRptTxtRecords,
                'dns_collection',
                [],
            );
        }

        return $this->discoverWithAlias($domain, $hostname, [], 0);
    }

    /**
     * @param list<string> $aliasPath
     */
    private function discoverWithAlias(string $domain, string $hostname, array $aliasPath, int $depth): TlsRptDiscoveryResult
    {
        if ($depth >= TlsRptDiscoveryResult::MAX_CNAME_DEPTH) {
            return new TlsRptDiscoveryResult(
                queriedDomain: $domain,
                recordHostname: '_smtp._tls.' . $domain,
                source: 'dns_query',
                dnsFailure: true,
                dnsError: 'Alias chain exceeded maximum depth',
                dnsOutcome: 'alias_depth_exceeded',
                aliasPath: $aliasPath,
                resolverDiagnostics: [[
                    'hostname' => $hostname,
                    'outcome' => 'alias_depth_exceeded',
                ]],
            );
        }

        if (in_array($hostname, $aliasPath, true)) {
            return new TlsRptDiscoveryResult(
                queriedDomain: $domain,
                recordHostname: '_smtp._tls.' . $domain,
                source: 'dns_query',
                dnsFailure: true,
                dnsError: 'Alias loop detected',
                dnsOutcome: 'alias_loop',
                aliasPath: $aliasPath,
                resolverDiagnostics: [[
                    'hostname' => $hostname,
                    'outcome' => 'alias_loop',
                ]],
            );
        }

        $aliasPath[] = $hostname;

        $cnameQuery = $this->resolver->cname($hostname);
        if ($cnameQuery->failed()) {
            return $this->failureResult($domain, $hostname, $aliasPath, $cnameQuery, 'dns_query');
        }

        if ($cnameQuery->cnameTargets !== []) {
            $target = $cnameQuery->cnameTargets[0];

            return $this->discoverWithAlias($domain, $target, $aliasPath, $depth + 1);
        }

        $txtQuery = $this->resolver->txt($hostname);
        if ($txtQuery->failed()) {
            return $this->failureResult($domain, $hostname, $aliasPath, $txtQuery, 'dns_query');
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

        return $this->discoverFromEvidence($domain, '_smtp._tls.' . $domain, $evidence, 'dns_query', $aliasPath);
    }

    /**
     * @param list<array{host: string, txt: string|list<string>, ttl: ?int, rr_index?: int}> $evidence
     * @param list<string> $aliasPath
     */
    private function discoverFromEvidence(
        string $domain,
        string $displayHostname,
        array $evidence,
        string $source,
        array $aliasPath,
    ): TlsRptDiscoveryResult {
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

        $selected = TlsRptTxtReconstructor::selectTlsRptRecords($allTxt);

        if (count($selected) > 1) {
            return new TlsRptDiscoveryResult(
                queriedDomain: $domain,
                recordHostname: $displayHostname,
                source: $source,
                record: $selected[0],
                multipleRecords: true,
                txtEvidence: $txtEvidence,
                selectedRecords: $selected,
                aliasPath: $aliasPath,
                ttl: $txtEvidence[0]['ttl'] ?? null,
            );
        }

        if (count($selected) === 1) {
            return new TlsRptDiscoveryResult(
                queriedDomain: $domain,
                recordHostname: $displayHostname,
                source: $source,
                record: $selected[0],
                txtEvidence: $txtEvidence,
                selectedRecords: $selected,
                aliasPath: $aliasPath,
                ttl: $txtEvidence[0]['ttl'] ?? null,
            );
        }

        return new TlsRptDiscoveryResult(
            queriedDomain: $domain,
            recordHostname: $displayHostname,
            source: $source,
            txtEvidence: $txtEvidence,
            aliasPath: $aliasPath,
            ttl: $txtEvidence[0]['ttl'] ?? null,
        );
    }

    /**
     * @param list<string> $aliasPath
     */
    private function failureResult(
        string $domain,
        string $hostname,
        array $aliasPath,
        TlsRptDnsQueryResult $query,
        string $source,
    ): TlsRptDiscoveryResult {
        return new TlsRptDiscoveryResult(
            queriedDomain: $domain,
            recordHostname: '_smtp._tls.' . $domain,
            source: $source,
            dnsFailure: true,
            dnsError: $query->error,
            dnsOutcome: $query->outcome,
            aliasPath: $aliasPath,
            resolverDiagnostics: [[
                'hostname' => $hostname,
                'outcome' => $query->outcome,
                'error' => $query->error,
            ]],
        );
    }

    private function hasScanEvidence(string $domain, DnsCollectionResultDTO $dns): bool
    {
        return $dns->tlsRptTxtRecords !== [];
    }
}
