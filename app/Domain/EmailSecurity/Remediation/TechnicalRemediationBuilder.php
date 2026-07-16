<?php

namespace App\Domain\EmailSecurity\Remediation;

use App\Domain\EmailSecurity\Checks\Certificates\Support\CertificateAnalysisReader;
use App\Domain\EmailSecurity\Checks\DKIM\Support\DkimAnalysisReader;
use App\Domain\EmailSecurity\Checks\MtaSts\Support\MtaStsAnalysisReader;
use App\Domain\EmailSecurity\Checks\Mx\Support\MxAnalysisReader;
use App\Domain\EmailSecurity\Checks\TlsRpt\Support\TlsRptAnalysisReader;
use App\Models\Domain;
use App\Models\Scan;

final class TechnicalRemediationBuilder
{
    public function __construct(
        private SpfRemediationBuilder $spf,
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
            'dmarc' => $this->dmarc($domain, $records),
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
    private function dmarc(Domain $domain, array $records): array
    {
        $current = (($records['DMARC']['status'] ?? '') === 'found')
            ? (string) ($records['DMARC']['data'] ?? '')
            : '';
        preg_match('/(?:^|;)\s*rua=([^;]+)/i', $current, $match);
        $destinations = array_values(array_filter(array_map(
            fn (string $value) => trim($value),
            explode(',', $match[1] ?? ''),
        )));
        $expected = 'mailto:' . $domain->dmarc_rua_email;
        $present = collect($destinations)->contains(fn ($value) => strtolower($value) === strtolower($expected));
        $allDestinations = array_values(array_unique(array_merge($destinations, [$expected])));

        if ($current === '') {
            $corrected = 'v=DMARC1; p=none; rua=' . implode(',', $allDestinations);
        } elseif ($match !== []) {
            $corrected = preg_replace(
                '/((?:^|;)\s*rua=)[^;]+/i',
                '$1' . implode(',', $allDestinations),
                $current,
                1,
            ) ?? $current;
        } else {
            $corrected = rtrim(trim($current), ';') . '; rua=' . implode(',', $allDestinations);
        }

        $external = [];
        foreach ($allDestinations as $destination) {
            $email = preg_replace('/^mailto:/i', '', $destination) ?? '';
            $destinationDomain = strtolower((string) strrchr($email, '@'));
            $destinationDomain = ltrim($destinationDomain, '@');
            if ($destinationDomain !== '' && $destinationDomain !== strtolower($domain->domain) && $destinationDomain !== 'mxscan.me') {
                $external[] = $domain->domain . '._report._dmarc.' . $destinationDomain;
            }
        }

        return [
            'current_value' => $current,
            'current_rua' => $destinations,
            'mxscan_address' => $expected,
            'mxscan_present' => $present,
            'corrected_value' => $corrected,
            'external_authorization_hosts' => $external,
            'type' => 'TXT',
            'host' => '_dmarc',
            'ttl' => 'Auto',
        ];
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
