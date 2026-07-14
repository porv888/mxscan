<?php

namespace App\Domain\EmailSecurity\Checks\SPF\Discovery;

use App\Domain\EmailSecurity\Checks\SPF\Evaluation\SpfDnsDependencyResolver;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;

final class SpfRecordDiscovery
{
    public function __construct(
        private SpfDnsDependencyResolver $resolver,
    ) {
    }

    public function discover(string $domain, ?DnsCollectionResultDTO $dns): SpfDiscoveryResult
    {
        $domain = strtolower(trim($domain));

        if ($dns !== null) {
            return $this->discoverFromEvidence($domain, $dns->rootTxtRecords, 'dns_collection');
        }

        $dnsResult = $this->resolver->txt($domain);
        if ($dnsResult->failed()) {
            return new SpfDiscoveryResult(
                domain: $domain,
                source: 'dns_query',
                dnsFailure: true,
                dnsError: $dnsResult->error,
            );
        }

        $evidence = [];
        foreach ($dnsResult->records as $index => $txt) {
            $evidence[] = [
                'host' => $domain,
                'txt' => $txt,
                'ttl' => $dnsResult->ttl,
                'rr_index' => $index,
            ];
        }

        return $this->discoverFromEvidence($domain, $evidence, 'dns_query');
    }

    /**
     * @param list<array{host: string, txt: string|list<string>, ttl: ?int, rr_index?: int}> $evidence
     */
    private function discoverFromEvidence(string $domain, array $evidence, string $source): SpfDiscoveryResult
    {
        $spfRecords = [];
        $txtEvidence = [];

        foreach ($evidence as $index => $entry) {
            $joined = self::joinTxtChunks($entry['txt']);
            $txtEvidence[] = [
                'host' => $entry['host'] ?? $domain,
                'txt' => $joined,
                'ttl' => $entry['ttl'] ?? null,
                'rr_index' => $entry['rr_index'] ?? $index,
            ];

            if (self::isSpfRecord($joined)) {
                $spfRecords[] = $joined;
            }
        }

        if (count($spfRecords) > 1) {
            return new SpfDiscoveryResult(
                domain: $domain,
                source: $source,
                record: $spfRecords[0],
                multipleRecords: true,
                txtEvidence: $txtEvidence,
            );
        }

        if (count($spfRecords) === 1) {
            return new SpfDiscoveryResult(
                domain: $domain,
                source: $source,
                record: $spfRecords[0],
                txtEvidence: $txtEvidence,
            );
        }

        return new SpfDiscoveryResult(
            domain: $domain,
            source: $source,
            txtEvidence: $txtEvidence,
        );
    }

    /**
     * @param string|list<string> $txt
     */
    public static function joinTxtChunks(string|array $txt): string
    {
        return is_array($txt) ? implode('', $txt) : $txt;
    }

    public static function isSpfRecord(string $txt): bool
    {
        return preg_match('/\bv=spf1\b/i', $txt) === 1;
    }
}
