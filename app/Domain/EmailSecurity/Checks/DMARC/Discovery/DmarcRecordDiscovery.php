<?php

namespace App\Domain\EmailSecurity\Checks\DMARC\Discovery;

use App\Domain\EmailSecurity\Checks\DMARC\Contracts\DmarcDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\DMARC\Support\DmarcTxtReconstructor;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;

final class DmarcRecordDiscovery
{
    public function __construct(
        private DmarcDnsResolverInterface $resolver,
    ) {
    }

    public function discoverAtHostname(string $domain, string $hostname, ?DnsCollectionResultDTO $dns): DmarcDiscoveryResult
    {
        $domain = strtolower(trim($domain));
        $hostname = strtolower(trim($hostname));

        if ($dns !== null && $this->isExactScanEvidence($domain, $hostname, $dns)) {
            return $this->discoverFromEvidence($domain, $hostname, $dns->dmarcTxtRecords, 'dns_collection');
        }

        $query = $this->resolver->txt($hostname);

        if ($query->failed()) {
            return new DmarcDiscoveryResult(
                queriedDomain: $domain,
                recordDomain: $this->stripDmarcPrefix($hostname),
                hostname: $hostname,
                source: 'dns_query',
                dnsFailure: true,
                dnsError: $query->error,
                resolverDiagnostics: [[
                    'hostname' => $hostname,
                    'outcome' => $query->outcome,
                    'error' => $query->error,
                ]],
            );
        }

        $evidence = [];
        foreach ($query->reconstructedTxt as $index => $txt) {
            $evidence[] = [
                'host' => $hostname,
                'txt' => $txt,
                'ttl' => $query->ttl,
                'rr_index' => $index,
            ];
        }

        return $this->discoverFromEvidence($domain, $hostname, $evidence, 'dns_query');
    }

    /**
     * @param list<array{host: string, txt: string|list<string>, ttl: ?int, rr_index?: int}> $evidence
     */
    private function discoverFromEvidence(string $domain, string $hostname, array $evidence, string $source): DmarcDiscoveryResult
    {
        $txtEvidence = [];
        $dmarcRecords = [];

        foreach ($evidence as $index => $entry) {
            $joined = is_array($entry['txt'] ?? null)
                ? implode('', $entry['txt'])
                : (string) ($entry['txt'] ?? '');
            $txtEvidence[] = [
                'host' => $entry['host'] ?? $hostname,
                'txt' => $joined,
                'ttl' => $entry['ttl'] ?? null,
                'rr_index' => $entry['rr_index'] ?? $index,
            ];

            if (DmarcTxtReconstructor::isDmarcVersionToken($joined)) {
                $dmarcRecords[] = $joined;
            }
        }

        if (count($dmarcRecords) > 1) {
            return new DmarcDiscoveryResult(
                queriedDomain: $domain,
                recordDomain: $this->stripDmarcPrefix($hostname),
                hostname: $hostname,
                source: $source,
                record: $dmarcRecords[0],
                multipleRecords: true,
                txtEvidence: $txtEvidence,
                dmarcRecords: $dmarcRecords,
                ttl: $txtEvidence[0]['ttl'] ?? null,
            );
        }

        if (count($dmarcRecords) === 1) {
            return new DmarcDiscoveryResult(
                queriedDomain: $domain,
                recordDomain: $this->stripDmarcPrefix($hostname),
                hostname: $hostname,
                source: $source,
                record: $dmarcRecords[0],
                txtEvidence: $txtEvidence,
                dmarcRecords: $dmarcRecords,
                ttl: $txtEvidence[0]['ttl'] ?? null,
            );
        }

        return new DmarcDiscoveryResult(
            queriedDomain: $domain,
            recordDomain: $this->stripDmarcPrefix($hostname),
            hostname: $hostname,
            source: $source,
            txtEvidence: $txtEvidence,
        );
    }

    private function isExactScanEvidence(string $domain, string $hostname, DnsCollectionResultDTO $dns): bool
    {
        return $hostname === '_dmarc.' . $domain && $dns->dmarcTxtRecords !== [];
    }

    private function stripDmarcPrefix(string $hostname): string
    {
        $prefix = '_dmarc.';

        return str_starts_with($hostname, $prefix) ? substr($hostname, strlen($prefix)) : $hostname;
    }
}
