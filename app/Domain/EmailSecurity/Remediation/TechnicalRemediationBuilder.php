<?php

namespace App\Domain\EmailSecurity\Remediation;

use App\Domain\EmailSecurity\Checks\Certificates\Support\CertificateAnalysisReader;
use App\Domain\EmailSecurity\Checks\DKIM\Support\DkimAnalysisReader;
use App\Domain\EmailSecurity\Checks\MtaSts\Support\MtaStsAnalysisReader;
use App\Domain\EmailSecurity\Checks\Mx\Support\MxAnalysisReader;
use App\Domain\EmailSecurity\Checks\TlsRpt\Support\TlsRptAnalysisReader;
use App\Models\Domain;
use App\Models\Scan;
use App\Services\Dmarc\DmarcRuaClassifier;

final class TechnicalRemediationBuilder
{
    public function __construct(
        private SpfRemediationBuilder $spf,
        private DmarcRuaClassifier $dmarcRuaClassifier,
    ) {
    }

    /**
     * @param array<string, mixed> $resultData
     * @return array<string, mixed>
     */
    public function build(Domain $domain, Scan $scan, array $resultData): array
    {
        $records = is_array($resultData['dns']['records'] ?? null) ? $resultData['dns']['records'] : [];
        $spfCount = (($records['SPF']['status'] ?? '') === 'found') ? 1 : 0;

        return [
            'spf' => $this->spf->build($domain, '~all', null, $spfCount)->toArray(),
            'senders' => $domain->senders()->where('is_active', true)->orderBy('id')->get()->map(
                fn ($sender) => $sender->only([
                    'id', 'sender_type', 'provider', 'mechanism', 'value', 'source',
                    'confidence', 'confirmation_status', 'last_seen_at', 'is_active',
                ])
            )->all(),
            'sender_providers' => config('remediation.senders', []),
            'dns_providers' => config('remediation.dns_providers', []),
            'dns_provider' => $domain->dns_provider,
            'dmarc' => $this->dmarc($domain, $records, $resultData),
            'mta_sts' => $this->mtaSts($domain, $scan, $resultData),
            'tls_rpt' => $this->tlsRpt($domain, $resultData),
            'dkim' => $this->dkim($resultData),
            'certificates' => CertificateAnalysisReader::analysis(
                is_array($resultData['certificates'] ?? null) ? $resultData['certificates'] : null
            ) ?? [],
        ];
    }

    /**
     * @param array<string, mixed> $records
     * @return array<string, mixed>
     */
    private function dmarc(Domain $domain, array $records, array $resultData): array
    {
        $current = (($records['DMARC']['status'] ?? '') === 'found')
            ? (string) ($records['DMARC']['data'] ?? '')
            : '';
        $canonicalEmail = strtolower($domain->dmarc_rua_email);
        $expected = 'mailto:' . $canonicalEmail;
        $rewrite = $current === ''
            ? [
                'updated' => "v=DMARC1; p=none; rua={$expected}",
                'action' => 'add_rua',
                'rua_link_state' => DmarcRuaClassifier::LINK_NOT_CONNECTED,
            ]
            : $this->dmarcRuaClassifier->rewriteRua($current, $canonicalEmail);
        $classification = $current === ''
            ? [
                'recipients' => [],
                'mxscan_recipients' => [],
                'external_recipients' => [],
                'has_any_mxscan_rua' => false,
                'has_canonical_mxscan_rua' => false,
                'rua_link_state' => DmarcRuaClassifier::LINK_NOT_CONNECTED,
            ]
            : $this->dmarcRuaClassifier->classify($current, $canonicalEmail);

        $mxscanRecipients = $classification['mxscan_recipients'];
        $foreignConnection = collect($mxscanRecipients)->contains(function (array $recipient) use ($domain): bool {
            return Domain::query()
                ->whereKeyNot($domain->id)
                ->get()
                ->contains(fn (Domain $other) => strtolower($other->dmarc_rua_email) === strtolower($recipient['email']));
        });
        $genericPresent = collect($mxscanRecipients)->contains(
            fn (array $recipient) => $recipient['email'] === 'dmarc@mxscan.me'
        );
        $staleTokenPresent = collect($mxscanRecipients)->contains(
            fn (array $recipient) => $recipient['email'] !== 'dmarc@mxscan.me'
                && $recipient['email'] !== $canonicalEmail
        );
        $linkState = match (true) {
            $classification['has_canonical_mxscan_rua'] => 'MXScan address present and linked',
            $foreignConnection => 'Address belongs to another report connection',
            $staleTokenPresent => 'Old MXScan address detected',
            $genericPresent => 'MXScan address present but not recognized',
            default => 'MXScan address absent',
        };

        $removed = collect($mxscanRecipients)
            ->reject(fn (array $recipient) => $recipient['email'] === $canonicalEmail)
            ->pluck('uri')
            ->values()
            ->all();
        $added = $classification['has_canonical_mxscan_rua'] ? [] : [$expected];

        $analysis = \App\Domain\EmailSecurity\Checks\DMARC\Support\DmarcAnalysisReader::analysis(
            is_array($resultData['dmarc'] ?? null) ? $resultData['dmarc'] : null
        ) ?? [];
        $nativeDestinations = data_get($analysis, 'aggregate_reporting.destinations', []);
        $external = [];
        foreach ($classification['external_recipients'] as $recipient) {
            $destinationDomain = strtolower(substr($recipient['email'], strrpos($recipient['email'], '@') + 1));
            $native = collect($nativeDestinations)->first(
                fn ($item) => is_array($item) && strtolower((string) ($item['normalized_destination'] ?? '')) === $recipient['email']
            );
            $external[] = [
                'uri' => $recipient['uri'],
                'email' => $recipient['email'],
                'destination_domain' => $destinationDomain,
                'owner' => $destinationDomain,
                'authorization_host' => $domain->domain . '._report._dmarc.' . $destinationDomain,
                'authorization_status' => $native['authorization_status'] ?? 'unknown',
                'customer_controls_zone' => false,
                'corrected_without_destination' => $this->removeRuaDestination($rewrite['updated'], $recipient['uri']),
            ];
        }

        return [
            'current_value' => $current,
            'current_rua' => collect($classification['recipients'])->pluck('uri')->all(),
            'mxscan_address' => $expected,
            'mxscan_present' => $classification['has_any_mxscan_rua'],
            'mxscan_link_state' => $linkState,
            'corrected_value' => $rewrite['updated'],
            'diff' => ['remove' => $removed, 'add' => $added],
            'external_destinations' => $external,
            'type' => 'TXT',
            'host' => '_dmarc',
            'ttl' => 'Auto',
        ];
    }

    private function removeRuaDestination(string $record, string $destination): string
    {
        $quoted = preg_quote($destination, '/');
        $updated = preg_replace(
            [
                '/(' . $quoted . ')\s*,\s*/i',
                '/,\s*(' . $quoted . ')/i',
            ],
            '',
            $record,
            1,
        );

        return $updated ?? $record;
    }

    /**
     * @param array<string, mixed> $resultData
     * @return array<string, mixed>
     */
    private function mtaSts(Domain $domain, Scan $scan, array $resultData): array
    {
        $analysis = MtaStsAnalysisReader::analysis(
            is_array($resultData['mta_sts'] ?? null) ? $resultData['mta_sts'] : null
        ) ?? [];
        $mx = MxAnalysisReader::analysis(
            is_array($resultData['mx'] ?? null) ? $resultData['mx'] : null
        ) ?? [];
        $hosts = collect($mx['targets'] ?? [])->map(
            fn ($target) => is_array($target)
                ? ($target['normalized_hostname'] ?? $target['hostname'] ?? null)
                : null
        )->filter()->unique()->values()->all();
        $version = ($scan->created_at ?? now())->utc()->format('YmdHis');
        $policyLines = ['version: STSv1', 'mode: testing'];
        foreach ($hosts as $host) {
            $policyLines[] = 'mx: ' . $host;
        }
        $policyLines[] = 'max_age: 86400';

        return [
            'analysis' => $analysis,
            'type' => 'TXT',
            'host' => '_mta-sts',
            'value' => "v=STSv1; id={$version};",
            'ttl' => 'Auto',
            'policy_hostname' => 'mta-sts.' . $domain->domain,
            'policy_url' => 'https://mta-sts.' . $domain->domain . '/.well-known/mta-sts.txt',
            'policy' => implode("\n", $policyLines),
            'mx_hosts' => $hosts,
        ];
    }

    /**
     * @param array<string, mixed> $resultData
     * @return array<string, mixed>
     */
    private function tlsRpt(Domain $domain, array $resultData): array
    {
        $analysis = TlsRptAnalysisReader::analysis(
            is_array($resultData['tls_rpt'] ?? null) ? $resultData['tls_rpt'] : null
        ) ?? [];
        $expected = $analysis['reporting']['expected_destination']['expected_address'] ?? null;
        $destination = is_string($expected) && $expected !== ''
            ? $expected
            : 'tlsrpt@' . $domain->domain;
        $destination = str_starts_with($destination, 'mailto:') ? $destination : 'mailto:' . $destination;

        return [
            'analysis' => $analysis,
            'type' => 'TXT',
            'host' => '_smtp._tls',
            'value' => 'v=TLSRPTv1; rua=' . $destination,
            'ttl' => 'Auto',
        ];
    }

    /**
     * @param array<string, mixed> $resultData
     * @return array<string, mixed>
     */
    private function dkim(array $resultData): array
    {
        $analysis = DkimAnalysisReader::analysis(
            is_array($resultData['dkim'] ?? null) ? $resultData['dkim'] : null
        ) ?? [];
        $selectors = collect($analysis['selectors'] ?? [])->pluck('selector')->filter()->all();
        $detected = [];
        foreach (config('remediation.senders', []) as $key => $provider) {
            if (array_intersect($selectors, $provider['dkim_selectors'] ?? []) !== []) {
                $detected[] = $key;
            }
        }

        return ['analysis' => $analysis, 'detected_providers' => $detected];
    }
}
