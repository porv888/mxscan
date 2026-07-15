<?php

namespace App\Domain\EmailSecurity\Checks\Bimi;

use App\Domain\EmailSecurity\Checks\Bimi\Contracts\BimiDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\Bimi\Contracts\BimiPublicSuffixInterface;
use App\Domain\EmailSecurity\Checks\Bimi\DTO\BimiDiscoveryResult;
use App\Domain\EmailSecurity\Checks\Bimi\DTO\BimiDnsQueryResult;
use App\Domain\EmailSecurity\Checks\Bimi\DTO\BimiSelectorContext;
use App\Domain\EmailSecurity\Checks\Bimi\Support\BimiTxtReconstructor;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;

final class BimiAssertionDiscovery
{
    public function __construct(
        private BimiDnsResolverInterface $resolver,
        private BimiPublicSuffixInterface $publicSuffixResolver,
    ) {
    }

    public function discover(
        string $queriedDomain,
        BimiSelectorContext $selectorContext,
        ?DnsCollectionResultDTO $dns,
    ): BimiDiscoveryResult {
        $queriedDomain = strtolower(rtrim(trim($queriedDomain), '.'));
        $selector = $selectorContext->value;
        $recordHostname = $selector . '._bimi.' . $queriedDomain;

        $authorDiscovery = $this->discoverAtHostname(
            $queriedDomain,
            $recordHostname,
            $selector,
            $selectorContext->source,
            $dns,
        );

        if ($authorDiscovery->record !== null || $authorDiscovery->hasDnsFailure() || $authorDiscovery->hasMultipleRecords()) {
            return $authorDiscovery;
        }

        $orgMeta = $this->publicSuffixResolver->resolveOrganizationalDomain($queriedDomain, $dns);
        $orgDomain = $orgMeta['organizational_domain'] ?? null;

        if (!is_string($orgDomain) || $orgDomain === '' || $orgDomain === $queriedDomain) {
            return $authorDiscovery;
        }

        $orgHostname = $selector . '._bimi.' . $orgDomain;
        $orgDiscovery = $this->discoverAtHostname(
            $queriedDomain,
            $orgHostname,
            $selector,
            $selectorContext->source,
            null,
            'organizational_fallback',
        );

        $fallbackPath = array_merge(
            $authorDiscovery->fallbackPath,
            [[
                'domain' => $orgDomain,
                'hostname' => $orgHostname,
                'source' => 'organizational_fallback',
                'outcome' => $orgDiscovery->record !== null ? 'found' : ($orgDiscovery->hasDnsFailure() ? 'dns_failure' : 'missing'),
                'selector' => $selector,
            ]],
        );

        return new BimiDiscoveryResult(
            queriedDomain: $queriedDomain,
            recordHostname: $orgDiscovery->record !== null ? $orgHostname : $recordHostname,
            selector: $selector,
            selectorSource: $selectorContext->source,
            source: $orgDiscovery->record !== null ? 'organizational_fallback' : $authorDiscovery->source,
            dnsFailure: $orgDiscovery->dnsFailure && $authorDiscovery->isMissing(),
            dnsError: $orgDiscovery->dnsError ?? $authorDiscovery->dnsError,
            dnsOutcome: $orgDiscovery->dnsOutcome ?? $authorDiscovery->dnsOutcome,
            record: $orgDiscovery->record ?? $authorDiscovery->record,
            ttl: $orgDiscovery->ttl ?? $authorDiscovery->ttl,
            aliasPath: $orgDiscovery->aliasPath !== [] ? $orgDiscovery->aliasPath : $authorDiscovery->aliasPath,
            resolverDiagnostics: array_merge($authorDiscovery->resolverDiagnostics, $orgDiscovery->resolverDiagnostics),
            fallbackPath: $fallbackPath,
            selectedRecordCount: max($authorDiscovery->selectedRecordCount, $orgDiscovery->selectedRecordCount),
        );
    }

    private function discoverAtHostname(
        string $queriedDomain,
        string $hostname,
        string $selector,
        string $selectorSource,
        ?DnsCollectionResultDTO $dns,
        string $source = 'dns_query',
    ): BimiDiscoveryResult {
        if ($dns !== null && $this->hasScanEvidence($hostname, $dns)) {
            return $this->discoverFromEvidence(
                $queriedDomain,
                $hostname,
                $selector,
                $selectorSource,
                $this->extractBimiTxtRecords($dns),
                'dns_collection',
            );
        }

        return $this->discoverWithAlias($queriedDomain, $hostname, $selector, $selectorSource, [], 0, $source);
    }

    /**
     * @param list<string> $aliasPath
     */
    private function discoverWithAlias(
        string $queriedDomain,
        string $hostname,
        string $selector,
        string $selectorSource,
        array $aliasPath,
        int $depth,
        string $source,
    ): BimiDiscoveryResult {
        if ($depth >= BimiDiscoveryResult::MAX_CNAME_DEPTH) {
            return $this->failureResult(
                $queriedDomain,
                $hostname,
                $selector,
                $selectorSource,
                $aliasPath,
                'Alias chain exceeded maximum depth',
                'alias_depth_exceeded',
                $source,
            );
        }

        if (in_array($hostname, $aliasPath, true)) {
            return $this->failureResult(
                $queriedDomain,
                $hostname,
                $selector,
                $selectorSource,
                $aliasPath,
                'Alias loop detected',
                'alias_loop',
                $source,
            );
        }

        $aliasPath[] = $hostname;

        $cnameQuery = $this->resolver->cname($hostname);
        if ($cnameQuery->failed()) {
            return $this->failureResult(
                $queriedDomain,
                $hostname,
                $selector,
                $selectorSource,
                $aliasPath,
                $cnameQuery->error ?? 'CNAME lookup failed',
                $cnameQuery->outcome,
                $source,
                $cnameQuery,
            );
        }

        if ($cnameQuery->cnameTargets !== []) {
            return $this->discoverWithAlias(
                $queriedDomain,
                $cnameQuery->cnameTargets[0],
                $selector,
                $selectorSource,
                $aliasPath,
                $depth + 1,
                $source,
            );
        }

        $txtQuery = $this->resolver->txt($hostname);
        if ($txtQuery->failed()) {
            return $this->failureResult(
                $queriedDomain,
                $hostname,
                $selector,
                $selectorSource,
                $aliasPath,
                $txtQuery->error ?? 'TXT lookup failed',
                $txtQuery->outcome,
                $source,
                $txtQuery,
            );
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

        return $this->discoverFromEvidence(
            $queriedDomain,
            $hostname,
            $selector,
            $selectorSource,
            $evidence,
            $source,
            $aliasPath,
        );
    }

    /**
     * @param list<array{host: string, txt: string|list<string>, ttl: ?int, rr_index?: int}> $evidence
     * @param list<string> $aliasPath
     */
    private function discoverFromEvidence(
        string $queriedDomain,
        string $hostname,
        string $selector,
        string $selectorSource,
        array $evidence,
        string $source,
        array $aliasPath = [],
    ): BimiDiscoveryResult {
        $allTxt = [];

        foreach ($evidence as $index => $entry) {
            $joined = is_array($entry['txt'] ?? null)
                ? implode('', $entry['txt'])
                : (string) ($entry['txt'] ?? '');
            $allTxt[] = $joined;
        }

        $selected = BimiTxtReconstructor::selectBimiRecords($allTxt);
        $invalidVersion = $this->findInvalidVersionRecord($allTxt);

        if ($selected === [] && $invalidVersion !== null) {
            return new BimiDiscoveryResult(
                queriedDomain: $queriedDomain,
                recordHostname: $hostname,
                selector: $selector,
                selectorSource: $selectorSource,
                source: $source,
                record: $invalidVersion,
                ttl: $evidence[0]['ttl'] ?? null,
                aliasPath: $aliasPath,
                resolverDiagnostics: [],
                fallbackPath: [[
                    'domain' => $queriedDomain,
                    'hostname' => $hostname,
                    'source' => $source,
                    'outcome' => 'invalid_version',
                    'selector' => $selector,
                ]],
                selectedRecordCount: 1,
            );
        }

        return new BimiDiscoveryResult(
            queriedDomain: $queriedDomain,
            recordHostname: $hostname,
            selector: $selector,
            selectorSource: $selectorSource,
            source: $source,
            record: $selected[0] ?? null,
            ttl: $evidence[0]['ttl'] ?? null,
            aliasPath: $aliasPath,
            resolverDiagnostics: [],
            fallbackPath: [[
                'domain' => $queriedDomain,
                'hostname' => $hostname,
                'source' => $source,
                'outcome' => count($selected) > 0 ? 'found' : 'missing',
                'selector' => $selector,
            ]],
            selectedRecordCount: count($selected),
        );
    }

    /**
     * @param list<string> $aliasPath
     */
    private function failureResult(
        string $queriedDomain,
        string $hostname,
        string $selector,
        string $selectorSource,
        array $aliasPath,
        string $error,
        string $outcome,
        string $source,
        ?BimiDnsQueryResult $query = null,
    ): BimiDiscoveryResult {
        return new BimiDiscoveryResult(
            queriedDomain: $queriedDomain,
            recordHostname: $hostname,
            selector: $selector,
            selectorSource: $selectorSource,
            source: $source,
            dnsFailure: true,
            dnsError: $error,
            dnsOutcome: $outcome,
            aliasPath: $aliasPath,
            resolverDiagnostics: [[
                'hostname' => $hostname,
                'outcome' => $outcome,
                'error' => $error,
                'query_success' => $query?->success,
            ]],
            fallbackPath: [[
                'domain' => $queriedDomain,
                'hostname' => $hostname,
                'source' => $source,
                'outcome' => $outcome,
                'selector' => $selector,
            ]],
        );
    }

    private function hasScanEvidence(string $hostname, DnsCollectionResultDTO $dns): bool
    {
        $hostname = strtolower(rtrim(trim($hostname), '.'));
        $records = $this->extractBimiTxtRecords($dns);

        foreach ($records as $entry) {
            $host = strtolower(rtrim(trim((string) ($entry['host'] ?? '')), '.'));
            if ($host === $hostname) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<array{host: string, txt: string|list<string>, ttl: ?int, rr_index?: int}>
     */
    private function extractBimiTxtRecords(DnsCollectionResultDTO $dns): array
    {
        $reflection = new \ReflectionClass($dns);
        if (!$reflection->hasProperty('bimiTxtRecords')) {
            return [];
        }

        $property = $reflection->getProperty('bimiTxtRecords');
        $records = $property->getValue($dns);

        return is_array($records) ? $records : [];
    }

    /**
     * @param list<string> $allTxt
     */
    private function findInvalidVersionRecord(array $allTxt): ?string
    {
        foreach ($allTxt as $txt) {
            $txt = ltrim($txt);
            if (!preg_match('/^v=/i', $txt)) {
                continue;
            }

            if (BimiTxtReconstructor::isBimiVersionToken($txt)) {
                continue;
            }

            if (preg_match('/^v=BIMI/i', $txt)) {
                return $txt;
            }
        }

        return null;
    }
}
