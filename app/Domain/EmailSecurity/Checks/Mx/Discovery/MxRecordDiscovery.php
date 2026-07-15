<?php

namespace App\Domain\EmailSecurity\Checks\Mx\Discovery;

use App\Domain\EmailSecurity\Checks\Mx\Contracts\MxDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\Mx\Evaluation\MxRecordNormalizer;

final class MxRecordDiscovery
{
    public function __construct(
        private MxDnsResolverInterface $resolver,
        private MxRecordNormalizer $normalizer,
    ) {
    }

    public function discover(string $domain): MxDiscoveryResult
    {
        $domain = $this->normalizer->normalizeDomain($domain);
        $query = $this->resolver->mx($domain);

        $diagnostics = [[
            'hostname' => $domain,
            'qtype' => 'MX',
            'outcome' => $query->outcome,
            'error' => $query->error,
        ]];

        if ($query->failed() || $query->isTemperror()) {
            return new MxDiscoveryResult(
                domain: $domain,
                source: 'dns_query',
                query: $query,
                resolverDiagnostics: $diagnostics,
            );
        }

        if ($query->isGenuinelyAbsent()) {
            return new MxDiscoveryResult(
                domain: $domain,
                source: 'dns_query',
                query: $query,
                resolverDiagnostics: $diagnostics,
            );
        }

        $rawRecords = [];
        foreach ($query->rawRows as $index => $row) {
            $rawRecords[] = [
                'pri' => $row['pri'] ?? 0,
                'target' => $row['target'] ?? '',
                'ttl' => $row['ttl'] ?? $query->ttl,
                'rr_index' => $index,
            ];
        }

        return new MxDiscoveryResult(
            domain: $domain,
            source: 'dns_query',
            query: $query,
            rawRecords: $rawRecords,
            resolverDiagnostics: $diagnostics,
        );
    }
}
