<?php

namespace App\Services;

use App\Models\Domain;
use App\Models\ScanSnapshot;
use App\Models\ScanDelta;
use App\Models\Incident;
use App\Jobs\NotifyIncident;
use Illuminate\Support\Facades\Log;

class MonitoringService
{
    /**
     * Persist a scan snapshot from normalized scan results
     */
    public function persistSnapshot(Domain $domain, string $scanType, array $scanResults): ScanSnapshot
    {
        // Normalize the scan results to match our snapshot schema
        $normalized = $this->normalizeScanResults($scanResults, $scanType);

        $snapshot = ScanSnapshot::create([
            'domain_id' => $domain->id,
            'scan_type' => $scanType,
            'mx_ok' => $normalized['mx_ok'],
            'spf_ok' => $normalized['spf_ok'],
            'spf_lookups' => $normalized['spf_lookups'],
            'dmarc_ok' => $normalized['dmarc_ok'],
            'tlsrpt_ok' => $normalized['tlsrpt_ok'],
            'mtasts_ok' => $normalized['mtasts_ok'],
            'rbl_hits' => $normalized['rbl_hits'],
            'score' => $normalized['score'],
        ]);

        Log::info('Scan snapshot created', [
            'domain' => $domain->domain,
            'scan_type' => $scanType,
            'snapshot_id' => $snapshot->id,
            'score' => $snapshot->score,
        ]);

        return $snapshot;
    }

    /**
     * Compute delta between current and previous snapshot, and raise incidents
     */
    public function computeDeltaAndIncidents(Domain $domain, ScanSnapshot $snapshot): ?ScanDelta
    {
        $previousSnapshot = $snapshot->getPreviousSnapshot();

        if (!$previousSnapshot) {
            Log::info('No previous snapshot found for comparison', [
                'domain' => $domain->domain,
                'snapshot_id' => $snapshot->id,
            ]);
            return null;
        }

        $changes = $this->computeChanges($previousSnapshot, $snapshot);

        if (empty($changes)) {
            Log::info('No changes detected between snapshots', [
                'domain' => $domain->domain,
                'previous_id' => $previousSnapshot->id,
                'current_id' => $snapshot->id,
            ]);
            return null;
        }

        $delta = ScanDelta::create([
            'domain_id' => $domain->id,
            'snapshot_id' => $snapshot->id,
            'changes' => $changes,
        ]);

        Log::info('Scan delta created', [
            'domain' => $domain->domain,
            'delta_id' => $delta->id,
            'changes_count' => count($changes),
        ]);

        // Raise incidents based on the changes
        $this->raiseIncidents($domain, $snapshot, $changes);

        return $delta;
    }

    /**
     * Normalize scan results from different sources into our snapshot format
     */
    protected function normalizeScanResults(array $scanResults, string $scanType): array
    {
        $normalized = [
            'mx_ok' => false,
            'spf_ok' => false,
            'spf_lookups' => 0,
            'dmarc_ok' => false,
            'tlsrpt_ok' => false,
            'mtasts_ok' => false,
            'rbl_hits' => [],
            'score' => 0,
        ];

        // Handle different scan result formats based on scan type
        switch ($scanType) {
            case 'full':
                $normalized = $this->normalizeFullScanResults($scanResults);
                break;
            case 'dns':
                $normalized = $this->normalizeDnsScanResults($scanResults);
                break;
            case 'spf':
                $normalized = $this->normalizeSpfScanResults($scanResults);
                break;
            case 'blacklist':
                $normalized = $this->normalizeBlacklistScanResults($scanResults);
                break;
        }

        return $normalized;
    }

    /**
     * Normalize full scan results
     */
    protected function normalizeFullScanResults(array $results): array
    {
        return [
            'mx_ok' => $this->mxOkFromResults($results),
            'spf_ok' => data_get($results, 'dns.records.SPF.status') === 'found',
            'spf_lookups' => data_get($results, 'spf.lookups', 0),
            'dmarc_ok' => data_get($results, 'dns.records.DMARC.status') === 'found',
            'tlsrpt_ok' => $this->tlsRptOkFromResults($results),
            'mtasts_ok' => $this->mtaStsOkFromResults($results),
            'rbl_hits' => $this->extractRblHits($results),
            'score' => data_get($results, 'dns.score', 0),
        ];
    }

    /**
     * Normalize DNS-only scan results
     */
    protected function normalizeDnsScanResults(array $results): array
    {
        return [
            'mx_ok' => $this->mxOkFromResults($results),
            'spf_ok' => data_get($results, 'dns.records.SPF.status') === 'found',
            'spf_lookups' => 0,
            'dmarc_ok' => data_get($results, 'dns.records.DMARC.status') === 'found',
            'tlsrpt_ok' => $this->tlsRptOkFromResults($results),
            'mtasts_ok' => $this->mtaStsOkFromResults($results),
            'rbl_hits' => [],
            'score' => data_get($results, 'dns.score', 0),
        ];
    }

    /**
     * Normalize SPF-only scan results
     */
    protected function normalizeSpfScanResults(array $results): array
    {
        return [
            'mx_ok' => false,
            'spf_ok' => !empty(data_get($results, 'spf.record')),
            'spf_lookups' => data_get($results, 'spf.lookups', 0),
            'dmarc_ok' => false,
            'tlsrpt_ok' => false,
            'mtasts_ok' => false,
            'rbl_hits' => [],
            'score' => 0,
        ];
    }

    /**
     * Normalize blacklist scan results
     */
    protected function normalizeBlacklistScanResults(array $results): array
    {
        $rblHits = [];
        if (isset($results['blacklist']['listed']) && is_array($results['blacklist']['listed'])) {
            $rblHits = array_keys($results['blacklist']['listed']);
        }
        
        return [
            'mx_ok' => false,
            'spf_ok' => false,
            'spf_lookups' => 0,
            'dmarc_ok' => false,
            'tlsrpt_ok' => false,
            'mtasts_ok' => false,
            'rbl_hits' => $rblHits,
            'score' => 0,
        ];
    }

    /**
     * Extract boolean value from nested array using multiple possible keys
     */
    protected function extractBooleanValue(array $data, array $keys): bool
    {
        foreach ($keys as $key) {
            $value = data_get($data, $key);
            if ($value !== null) {
                return (bool) $value;
            }
        }
        return false;
    }

    /**
     * Extract integer value from nested array using multiple possible keys
     */
    protected function extractIntegerValue(array $data, array $keys): int
    {
        foreach ($keys as $key) {
            $value = data_get($data, $key);
            if ($value !== null) {
                return (int) $value;
            }
        }
        return 0;
    }

    /**
     * Extract RBL hits from scan results
     */
    protected function extractRblHits(array $results): array
    {
        $blacklist = data_get($results, 'blacklist.analysis.listings')
            ?? data_get($results, 'blacklist.listings')
            ?? [];

        if (!is_array($blacklist) || $blacklist === []) {
            $listedCount = (int) data_get($results, 'blacklist.listed_count', 0);
            if ($listedCount <= 0) {
                return [];
            }
        }

        $hits = [];
        if (is_array($blacklist)) {
            foreach ($blacklist as $listing) {
                if (!is_array($listing)) {
                    continue;
                }
                $provider = (string) ($listing['provider_name'] ?? $listing['provider_key'] ?? '');
                if ($provider !== '' && !in_array($provider, $hits, true)) {
                    $hits[] = $provider;
                }
            }
        }

        return $hits;
    }

    /**
     * Compute changes between two snapshots
     */
    protected function computeChanges(ScanSnapshot $previous, ScanSnapshot $current): array
    {
        $changes = [];
        $fields = ['mx_ok', 'spf_ok', 'spf_lookups', 'dmarc_ok', 'tlsrpt_ok', 'mtasts_ok', 'score'];

        foreach ($fields as $field) {
            if ($previous->$field !== $current->$field) {
                $changes[] = [
                    'field' => $field,
                    'from' => $previous->$field,
                    'to' => $current->$field,
                ];
            }
        }

        // Handle RBL hits separately
        $prevRbl = collect($previous->rbl_hits ?? []);
        $currRbl = collect($current->rbl_hits ?? []);
        
        $listed = $currRbl->diff($prevRbl)->values()->all();
        $delisted = $prevRbl->diff($currRbl)->values()->all();

        if (!empty($listed) || !empty($delisted)) {
            $change = [
                'field' => 'rbl_hits',
                'from' => $previous->rbl_hits,
                'to' => $current->rbl_hits,
            ];
            
            if (!empty($listed)) {
                $change['listed'] = $listed;
            }
            
            if (!empty($delisted)) {
                $change['delisted'] = $delisted;
            }
            
            $changes[] = $change;
        }

        return $changes;
    }

    /**
     * Raise incidents based on detected changes
     */
    protected function raiseIncidents(Domain $domain, ScanSnapshot $snapshot, array $changes): void
    {
        foreach ($changes as $change) {
            $field = $change['field'];

            switch ($field) {
                case 'mx_ok':
                    if ($change['to'] === false) {
                        $this->createIncident($domain, 'record_missing', 'incident',
                            'MX record became invalid or missing.', ['field' => 'mx_ok']);
                    } elseif ($change['to'] === true) {
                        $this->createIncident($domain, 'record_missing', 'warning',
                            'MX record has been fixed.', ['field' => 'mx_ok']);
                    }
                    break;

                case 'spf_ok':
                    if ($change['to'] === false) {
                        $this->createIncident($domain, 'record_missing', 'warning',
                            'SPF record became invalid or missing.', ['field' => 'spf_ok']);
                    } elseif ($change['to'] === true) {
                        $this->createIncident($domain, 'record_missing', 'warning',
                            'SPF record has been fixed.', ['field' => 'spf_ok']);
                    }
                    break;

                case 'dmarc_ok':
                    if ($change['to'] === false) {
                        $this->createIncident($domain, 'record_missing', 'warning',
                            'DMARC record became invalid or missing.', ['field' => 'dmarc_ok']);
                    } elseif ($change['to'] === true) {
                        $this->createIncident($domain, 'record_missing', 'warning',
                            'DMARC record has been fixed.', ['field' => 'dmarc_ok']);
                    }
                    break;

                case 'spf_lookups':
                    if (($change['to'] ?? 0) > 10) {
                        $this->createIncident($domain, 'spf_fail', 'incident',
                            'SPF DNS lookups exceed RFC limit of 10.', ['lookups' => $change['to']]);
                    } elseif (($change['to'] ?? 0) >= 9) {
                        $this->createIncident($domain, 'spf_fail', 'warning',
                            'SPF DNS lookups approaching RFC limit.', ['lookups' => $change['to']]);
                    }
                    break;

                case 'score':
                    $scoreDrop = ($change['from'] ?? 0) - ($change['to'] ?? 0);
                    if ($scoreDrop >= 20) {
                        $this->createIncident($domain, 'record_missing', 'warning',
                            "Domain score dropped significantly from {$change['from']} to {$change['to']}.",
                            ['score_from' => $change['from'], 'score_to' => $change['to']]);
                    }
                    break;

                case 'rbl_hits':
                    if (!empty($change['listed'])) {
                        $this->createIncident($domain, 'blacklist_listed', 'incident',
                            'Domain/IP listed on blacklists: ' . implode(', ', $change['listed']),
                            ['listed' => $change['listed']]);
                    }
                    
                    if (!empty($change['delisted'])) {
                        $this->createIncident($domain, 'blacklist_listed', 'warning',
                            'Domain/IP delisted from blacklists: ' . implode(', ', $change['delisted']),
                            ['delisted' => $change['delisted']]);
                    }
                    break;
            }
        }
    }

    /**
     * Create and dispatch incident notification
     */
    protected function createIncident(Domain $domain, string $kind, string $severity, string $message, array $context = []): void
    {
        $field = $context['field'] ?? null;

        $existingQuery = Incident::query()
            ->where('domain_id', $domain->id)
            ->where('type', $kind)
            ->whereNull('resolved_at');

        if ($field !== null) {
            $existingQuery->where('meta->field', $field);
        } else {
            $existingQuery->where('message', $message);
        }

        $existing = $existingQuery->latest('occurred_at')->first();
        if ($existing) {
            $existing->update([
                'occurred_at' => now(),
                'severity' => $severity,
                'meta' => $context,
            ]);

            Log::info('Incident deduplicated (updated existing open incident)', [
                'domain' => $domain->domain,
                'incident_id' => $existing->id,
                'type' => $kind,
            ]);

            return;
        }

        $incident = Incident::create([
            'domain_id' => $domain->id,
            'type' => $kind,
            'severity' => $severity,
            'message' => $message,
            'meta' => $context,
            'occurred_at' => now(),
        ]);

        Log::info('Incident created', [
            'domain' => $domain->domain,
            'incident_id' => $incident->id,
            'type' => $kind,
            'severity' => $severity,
        ]);

        // Dispatch notification job
        NotifyIncident::dispatch($incident);
    }

    /**
     * @param array<string, mixed> $results
     */
    protected function mxOkFromResults(array $results): bool
    {
        $mxInfo = data_get($results, 'mx');
        $analysis = \App\Domain\EmailSecurity\Checks\Mx\Support\MxAnalysisReader::analysis(
            is_array($mxInfo) ? $mxInfo : null,
        ) ?? \App\Domain\EmailSecurity\Checks\Mx\Support\MxAnalysisReader::fromLegacyDnsRecord(
            data_get($results, 'dns.records.MX'),
            is_array($mxInfo) ? $mxInfo : null,
        );

        if (in_array($analysis['state'] ?? '', [
            \App\Domain\EmailSecurity\Checks\Mx\MxStates::FAIL,
            \App\Domain\EmailSecurity\Checks\Mx\MxStates::MISSING,
        ], true)) {
            return false;
        }

        if (($analysis['risk_status'] ?? '') === \App\Domain\EmailSecurity\Checks\Mx\MxRiskStatus::UNKNOWN) {
            return false;
        }

        return in_array($analysis['risk_status'] ?? '', [
            \App\Domain\EmailSecurity\Checks\Mx\MxRiskStatus::HEALTHY,
            \App\Domain\EmailSecurity\Checks\Mx\MxRiskStatus::WARNING,
        ], true);
    }

    /**
     * @param array<string, mixed> $results
     */
    protected function mtaStsOkFromResults(array $results): bool
    {
        $mtaStsInfo = data_get($results, 'mta_sts');
        $analysis = \App\Domain\EmailSecurity\Checks\MtaSts\Support\MtaStsAnalysisReader::analysis(
            is_array($mtaStsInfo) ? $mtaStsInfo : null,
        ) ?? \App\Domain\EmailSecurity\Checks\MtaSts\Support\MtaStsAnalysisReader::fromLegacyDnsRecord(
            data_get($results, 'dns.records.MTA-STS'),
            is_array($mtaStsInfo) ? $mtaStsInfo : null,
        );

        return ($analysis['state'] ?? '') === \App\Domain\EmailSecurity\Checks\MtaSts\MtaStsStates::PASS;
    }

    /**
     * @param array<string, mixed> $results
     */
    protected function tlsRptOkFromResults(array $results): bool
    {
        $tlsRptInfo = data_get($results, 'tls_rpt');
        $analysis = \App\Domain\EmailSecurity\Checks\TlsRpt\Support\TlsRptAnalysisReader::analysis(
            is_array($tlsRptInfo) ? $tlsRptInfo : null,
        ) ?? \App\Domain\EmailSecurity\Checks\TlsRpt\Support\TlsRptAnalysisReader::fromLegacyDnsRecord(
            data_get($results, 'dns.records.TLS-RPT'),
            is_array($tlsRptInfo) ? $tlsRptInfo : null,
        );

        return ($analysis['state'] ?? '') === \App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptStates::PASS;
    }
}
