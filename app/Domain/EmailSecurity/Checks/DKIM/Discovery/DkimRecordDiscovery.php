<?php

namespace App\Domain\EmailSecurity\Checks\DKIM\Discovery;

use App\Domain\EmailSecurity\Checks\DKIM\Contracts\DkimDnsResolverInterface;
use App\Domain\EmailSecurity\Checks\DKIM\DkimSelectorCandidate;
use App\Domain\EmailSecurity\Checks\DKIM\Evaluation\DkimDnsQueryResult;

final class DkimRecordDiscovery
{
    public function __construct(
        private DkimDnsResolverInterface $resolver,
    ) {
    }

    public function discover(DkimSelectorCandidate $candidate): DkimDiscoveryResult
    {
        $query = $this->resolver->txt($candidate->hostname);

        $diagnostics = [[
            'hostname' => $candidate->hostname,
            'outcome' => $query->outcome,
            'error' => $query->error,
            'cname_path' => $query->cnamePath,
            'ttl' => $query->ttl,
        ]];

        if ($query->failed()) {
            return new DkimDiscoveryResult(
                candidate: $candidate,
                dnsStatus: $query->outcome,
                dnsError: $query->error,
                resolverDiagnostics: $diagnostics,
            );
        }

        $dkimRecords = $query->reconstructedTxt;

        if (count($dkimRecords) > 1) {
            return new DkimDiscoveryResult(
                candidate: $candidate,
                dnsStatus: DkimDnsQueryResult::OUTCOME_ANSWER,
                dkimRecords: $dkimRecords,
                multipleRecords: true,
                rawRecord: $dkimRecords[0],
                ttl: $query->ttl,
                resolverDiagnostics: $diagnostics,
                cnameTarget: $this->resolveCnameTarget($query),
            );
        }

        if (count($dkimRecords) === 1) {
            return new DkimDiscoveryResult(
                candidate: $candidate,
                dnsStatus: DkimDnsQueryResult::OUTCOME_ANSWER,
                dkimRecords: $dkimRecords,
                rawRecord: $dkimRecords[0],
                ttl: $query->ttl,
                resolverDiagnostics: $diagnostics,
                cnameTarget: $this->resolveCnameTarget($query),
            );
        }

        return new DkimDiscoveryResult(
            candidate: $candidate,
            dnsStatus: $query->outcome === DkimDnsQueryResult::OUTCOME_ANSWER
                ? DkimDnsQueryResult::OUTCOME_EMPTY
                : $query->outcome,
            resolverDiagnostics: $diagnostics,
        );
    }

    private function resolveCnameTarget(DkimDnsQueryResult $query): ?string
    {
        if ($query->cnameTarget !== null && $query->cnameTarget !== '') {
            return $query->cnameTarget;
        }

        $path = $query->cnamePath;
        if ($path === []) {
            return null;
        }

        return $path[array_key_last($path)];
    }
}
