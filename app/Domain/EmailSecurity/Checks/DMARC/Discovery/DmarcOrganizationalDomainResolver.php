<?php

namespace App\Domain\EmailSecurity\Checks\DMARC\Discovery;

use App\Domain\EmailSecurity\Checks\DMARC\Parsing\DmarcParser;

final class DmarcOrganizationalDomainResolver
{
    public const MAX_QUERIES = 8;

    public function __construct(
        private DmarcRecordDiscovery $recordDiscovery,
        private DmarcParser $parser,
    ) {
    }

    /**
     * @return array{
     *   queried_domain: string,
     *   policy_domain: ?string,
     *   policy_source: string,
     *   organizational_domain: ?string,
     *   public_suffix_domain: ?string,
     *   lookup_path: list<string>,
     *   queries_used: int,
     *   discovery_method: string,
     *   exact_discovery: DmarcDiscoveryResult,
     *   policy_discovery: ?DmarcDiscoveryResult,
     *   partially_evaluated: bool
     * }
     */
    public function resolve(string $queriedDomain, ?\App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO $dns): array
    {
        $queriedDomain = strtolower(trim($queriedDomain));
        $labels = explode('.', $queriedDomain);
        if (count($labels) > 7) {
            $labels = array_slice($labels, -7);
        }

        $lookupPath = [];
        $queriesUsed = 0;
        $partiallyEvaluated = false;
        $policyDiscovery = null;
        $policyDomain = null;
        $organizationalDomain = null;
        $publicSuffixDomain = null;
        $policySource = 'none';

        $exactHostname = '_dmarc.' . $queriedDomain;
        $exactDiscovery = $this->recordDiscovery->discoverAtHostname($queriedDomain, $exactHostname, $dns);
        $lookupPath[] = $exactHostname;
        $queriesUsed++;

        if ($exactDiscovery->hasDnsFailure()) {
            return $this->result(
                $queriedDomain,
                null,
                'none',
                null,
                null,
                $lookupPath,
                $queriesUsed,
                $exactDiscovery,
                null,
                true,
            );
        }

        if ($exactDiscovery->record !== null && !$exactDiscovery->multipleRecords) {
            return $this->result(
                $queriedDomain,
                $exactDiscovery->recordDomain,
                'exact',
                $exactDiscovery->recordDomain,
                null,
                $lookupPath,
                $queriesUsed,
                $exactDiscovery,
                $exactDiscovery,
                false,
            );
        }

        $walkLabels = $labels;
        $shortestRecordDomain = null;
        $shortestDiscovery = null;

        while (count($walkLabels) >= 2 && $queriesUsed < self::MAX_QUERIES) {
            $candidate = implode('.', $walkLabels);
            if ($candidate === $queriedDomain) {
                array_shift($walkLabels);
                continue;
            }

            $hostname = '_dmarc.' . $candidate;
            $discovery = $this->recordDiscovery->discoverAtHostname($queriedDomain, $hostname, null);
            $lookupPath[] = $hostname;
            $queriesUsed++;

            if ($discovery->hasDnsFailure()) {
                $partiallyEvaluated = true;
                break;
            }

            if ($discovery->multipleRecords) {
                return $this->result(
                    $queriedDomain,
                    $discovery->recordDomain,
                    'organizational',
                    $discovery->recordDomain,
                    null,
                    $lookupPath,
                    $queriesUsed,
                    $exactDiscovery,
                    $discovery,
                    false,
                );
            }

            if ($discovery->record === null) {
                array_shift($walkLabels);
                continue;
            }

            $parsed = $this->parser->parse($discovery->record);
            $psd = $parsed->tags['psd']['normalized'] ?? 'u';

            if ($psd === 'n') {
                return $this->result(
                    $queriedDomain,
                    $discovery->recordDomain,
                    'organizational',
                    $discovery->recordDomain,
                    null,
                    $lookupPath,
                    $queriesUsed,
                    $exactDiscovery,
                    $discovery,
                    false,
                );
            }

            if ($psd === 'y') {
                $orgDomain = $this->childDomain($queriedDomain, $discovery->recordDomain);

                return $this->result(
                    $queriedDomain,
                    $discovery->recordDomain,
                    'public_suffix',
                    $orgDomain ?? $queriedDomain,
                    $discovery->recordDomain,
                    $lookupPath,
                    $queriesUsed,
                    $exactDiscovery,
                    $discovery,
                    false,
                );
            }

            $shortestRecordDomain = $discovery->recordDomain;
            $shortestDiscovery = $discovery;
            array_shift($walkLabels);
        }

        if ($shortestDiscovery !== null) {
            $policySource = $shortestRecordDomain === $queriedDomain ? 'exact' : 'organizational';

            return $this->result(
                $queriedDomain,
                $shortestRecordDomain,
                $policySource,
                $shortestRecordDomain,
                null,
                $lookupPath,
                $queriesUsed,
                $exactDiscovery,
                $shortestDiscovery,
                $partiallyEvaluated,
            );
        }

        return $this->result(
            $queriedDomain,
            null,
            'none',
            null,
            null,
            $lookupPath,
            $queriesUsed,
            $exactDiscovery,
            $policyDiscovery,
            $partiallyEvaluated,
        );
    }

    /**
     * @param list<string> $lookupPath
     * @return array<string, mixed>
     */
    private function result(
        string $queriedDomain,
        ?string $policyDomain,
        string $policySource,
        ?string $organizationalDomain,
        ?string $publicSuffixDomain,
        array $lookupPath,
        int $queriesUsed,
        DmarcDiscoveryResult $exactDiscovery,
        ?DmarcDiscoveryResult $policyDiscovery,
        bool $partiallyEvaluated,
    ): array {
        return [
            'queried_domain' => $queriedDomain,
            'policy_domain' => $policyDomain,
            'policy_source' => $policySource,
            'organizational_domain' => $organizationalDomain,
            'public_suffix_domain' => $publicSuffixDomain,
            'lookup_path' => $lookupPath,
            'queries_used' => $queriesUsed,
            'discovery_method' => 'treewalk',
            'exact_discovery' => $exactDiscovery,
            'policy_discovery' => $policyDiscovery,
            'partially_evaluated' => $partiallyEvaluated,
        ];
    }

    private function childDomain(string $queriedDomain, string $psdDomain): ?string
    {
        if ($queriedDomain === $psdDomain) {
            return $queriedDomain;
        }

        if (!str_ends_with($queriedDomain, '.' . $psdDomain)) {
            return null;
        }

        $suffix = '.' . $psdDomain;
        $prefix = substr($queriedDomain, 0, -strlen($suffix));
        $parts = explode('.', $prefix);

        return $parts[0] . $suffix;
    }
}
