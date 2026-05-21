<?php

namespace App\Http\Controllers\Concerns;

use App\Models\Scan;
use App\Services\Dmarc\DmarcStatusService;
use App\Services\ScanTrendService;
use App\Services\ScoreBreakdownService;

trait PreparesScanReport
{
    /**
     * @return array<string, mixed>
     */
    protected function prepareScanReportViewData(Scan $scan): array
    {
        $scan->load(['domain', 'blacklistResults']);
        $domain = $scan->domain->fresh();

        $enabled = [
            'dns' => $scan->hasDnsResults(),
            'spf' => $scan->hasSpfResults(),
            'blacklist' => $scan->hasBlacklistResults(),
            'delivery' => false,
        ];

        $isBlacklistOnly = $scan->isBlacklistOnly();
        $hasDns = $scan->hasDnsResults();
        $hasSpf = $scan->hasSpfResults();
        $hasBlacklist = $scan->hasBlacklistResults();

        $snapshot = $domain->latestScanSnapshot;
        $lastSnapshot = $domain->scanSnapshots()
            ->where('id', '!=', $snapshot?->id)
            ->latest('created_at')
            ->first();

        $scoreDelta = null;
        if ($snapshot && $lastSnapshot) {
            $scoreDelta = ($snapshot->score ?? 0) - ($lastSnapshot->score ?? 0);
        }

        $resultData = $scan->result_json ?? [];
        if (is_string($resultData)) {
            $resultData = json_decode($resultData, true) ?? [];
        }
        $records = $resultData['dns']['records'] ?? $resultData ?? [];

        $spfInfo = $resultData['spf'] ?? null;
        $spfLookupCount = $spfInfo['lookups'] ?? $domain->spf_lookup_count ?? null;
        $spfMax = 10;
        $spfSuggestion = $spfInfo['flattened'] ?? null;

        $dmarcData = $records['DMARC'] ?? null;
        $dmarcPolicy = null;
        $dmarcAligned = null;
        if ($dmarcData && ($dmarcData['status'] ?? '') === 'found') {
            $dmarcRecord = $dmarcData['data'];
            if (preg_match('/p=([^;]+)/', $dmarcRecord, $matches)) {
                $dmarcPolicy = $matches[1];
            }
            $dmarcAligned = (str_contains($dmarcRecord, 'aspf=') || str_contains($dmarcRecord, 'adkim='));
        }

        $tlsrptOk = isset($records['TLS-RPT']) && $records['TLS-RPT']['status'] === 'found';
        $mtastsOk = isset($records['MTA-STS']) && $records['MTA-STS']['status'] === 'found';
        $bimiHasData = isset($records['BIMI']);
        $bimiOk = isset($records['BIMI']) && ($records['BIMI']['status'] ?? '') === 'found';

        $blacklistData = $resultData['blacklist'] ?? [];
        $blacklistHits = $blacklistData['listed_count'] ?? 0;
        $blacklistTotal = $blacklistData['total_checks'] ?? 0;
        $blacklistRows = $scan->blacklistResults;

        $domainDays = $domain->getDaysUntilDomainExpiry();
        $sslDays = $domain->getDaysUntilSslExpiry();

        $incidents = $domain->incidents()
            ->where('created_at', '>=', now()->subDays(7))
            ->whereNull('resolved_at')
            ->orderByDesc('severity')
            ->orderByDesc('created_at')
            ->get();

        $deliveries = collect();

        $activeSchedule = $domain->activeSchedule;
        $cadence = 'off';
        if ($activeSchedule) {
            $frequency = $activeSchedule->frequency;
            $cadence = $frequency === 'daily' ? 'daily' : ($frequency === 'weekly' ? 'weekly' : 'off');
        }

        $dmarcStatus = app(DmarcStatusService::class)->getStatus($domain);

        $breakdownService = app(ScoreBreakdownService::class);
        $scoreBreakdown = $resultData['dns']['score_breakdown']
            ?? $breakdownService->buildFromDnsRecords(is_array($records) ? $records : []);
        $scoreDeductions = $breakdownService->deductions($scoreBreakdown);

        $includeIncidentTrend = auth()->user()->canUseMonitoring();
        $scoreTrend = app(ScanTrendService::class)->getDomainTrend(
            $domain->id,
            30,
            $includeIncidentTrend
        );

        return compact(
            'scan',
            'domain',
            'enabled',
            'isBlacklistOnly',
            'hasDns',
            'hasSpf',
            'hasBlacklist',
            'snapshot',
            'lastSnapshot',
            'scoreDelta',
            'resultData',
            'records',
            'spfLookupCount',
            'spfMax',
            'spfSuggestion',
            'dmarcPolicy',
            'dmarcAligned',
            'tlsrptOk',
            'mtastsOk',
            'bimiHasData',
            'bimiOk',
            'blacklistHits',
            'blacklistTotal',
            'blacklistRows',
            'domainDays',
            'sslDays',
            'incidents',
            'deliveries',
            'cadence',
            'dmarcStatus',
            'scoreBreakdown',
            'scoreDeductions',
            'scoreTrend',
        );
    }
}
