<?php

namespace App\Domain\EmailSecurity\Reporting;

use App\Domain\EmailSecurity\Contracts\ScanReportFactoryInterface;
use App\Domain\EmailSecurity\DTO\ScanReportViewModelDTO;
use App\Domain\EmailSecurity\Recommendations\ScanRecommendationService;
use App\Models\Domain;
use App\Models\Scan;
use App\Services\Dmarc\DmarcStatusService;
use App\Services\ScanTrendService;
use App\Services\ScoreBreakdownService;

final class ScanReportFactory implements ScanReportFactoryInterface
{
    public function __construct(
        private ScoreBreakdownService $scoreBreakdownService,
        private ScanReportStatusMapper $statusMapper,
        private ScanRecommendationService $recommendationService,
        private DmarcStatusService $dmarcStatusService,
        private ScanTrendService $scanTrendService,
    ) {
    }

    public function build(Scan $scan, Domain $domain): ScanReportViewModelDTO
    {
        $scan->loadMissing(['blacklistResults']);
        $domain = $domain->fresh();

        if (in_array($scan->status, ['queued', 'running', 'failed'], true)) {
            return new ScanReportViewModelDTO($this->pendingPayload($scan, $domain));
        }

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
        if (!is_array($records)) {
            $records = [];
        }

        $spfInfo = $resultData['spf'] ?? null;
        $spfMissing = (($records['SPF']['status'] ?? null) !== 'found');
        $spfLookupCount = null;
        if (!$spfMissing && is_array($spfInfo) && array_key_exists('lookups', $spfInfo)) {
            $spfLookupCount = $spfInfo['lookups'];
        }
        $spfMax = 10;
        $spfSuggestion = is_array($spfInfo) ? ($spfInfo['flattened'] ?? null) : null;

        $dmarcData = $records['DMARC'] ?? null;
        $dmarcPolicy = null;
        $dmarcAligned = null;
        if ($dmarcData && ($dmarcData['status'] ?? '') === 'found') {
            $dmarcRecord = $dmarcData['data'];
            if (is_string($dmarcRecord) && preg_match('/p=([^;]+)/', $dmarcRecord, $matches)) {
                $dmarcPolicy = $matches[1];
            }
            if (is_string($dmarcRecord)) {
                $dmarcAligned = (str_contains($dmarcRecord, 'aspf=') || str_contains($dmarcRecord, 'adkim='));
            }
        }

        $tlsrptOk = isset($records['TLS-RPT']) && $records['TLS-RPT']['status'] === 'found';
        $mtastsOk = isset($records['MTA-STS']) && $records['MTA-STS']['status'] === 'found';
        $bimiHasData = isset($records['BIMI']);
        $bimiOk = isset($records['BIMI']) && ($records['BIMI']['status'] ?? '') === 'found';

        $blacklistData = $resultData['blacklist'] ?? null;
        $blacklistHits = is_array($blacklistData) ? (int) ($blacklistData['listed_count'] ?? 0) : 0;
        $blacklistTotal = is_array($blacklistData) ? (int) ($blacklistData['total_checks'] ?? 0) : 0;
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

        $dmarcStatus = $this->dmarcStatusService->getStatus($domain);

        $scoreBreakdown = $resultData['dns']['score_breakdown']
            ?? $this->scoreBreakdownService->buildFromDnsRecords($records);
        $scoreDeductions = $this->scoreBreakdownService->deductions($scoreBreakdown);

        $statusCards = $this->statusMapper->buildStatusCards(
            $resultData,
            $records,
            $scan->score
        );

        $recommendations = $this->recommendationService->build($domain, $resultData, $records);
        $allClear = $this->recommendationService->evaluateAllClear($resultData, $records);

        $includeIncidentTrend = auth()->user()->canUseMonitoring();
        $scoreTrend = $this->scanTrendService->getDomainTrend(
            $domain->id,
            30,
            $includeIncidentTrend
        );

        $score = $scan->score;

        $finishedCount = Scan::query()
            ->where('domain_id', $domain->id)
            ->where('status', 'finished')
            ->count();
        $isFirstFinishedScan = $scan->status === 'finished' && $finishedCount <= 1;

        return new ScanReportViewModelDTO(compact(
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
            'score',
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
            'statusCards',
            'recommendations',
            'allClear',
            'isFirstFinishedScan',
        ));
    }

    /**
     * @return array<string, mixed>
     */
    private function pendingPayload(Scan $scan, $domain): array
    {
        return [
            'scan' => $scan,
            'domain' => $domain,
            'enabled' => ['dns' => false, 'spf' => false, 'blacklist' => false, 'delivery' => false],
            'isBlacklistOnly' => false,
            'hasDns' => false,
            'hasSpf' => false,
            'hasBlacklist' => false,
            'snapshot' => null,
            'lastSnapshot' => null,
            'scoreDelta' => null,
            'score' => null,
            'resultData' => [],
            'records' => [],
            'spfLookupCount' => null,
            'spfMax' => 10,
            'spfSuggestion' => null,
            'dmarcPolicy' => null,
            'dmarcAligned' => null,
            'tlsrptOk' => false,
            'mtastsOk' => false,
            'bimiHasData' => false,
            'bimiOk' => false,
            'blacklistHits' => 0,
            'blacklistTotal' => 0,
            'blacklistRows' => collect(),
            'domainDays' => null,
            'sslDays' => null,
            'incidents' => collect(),
            'deliveries' => collect(),
            'cadence' => 'off',
            'dmarcStatus' => null,
            'scoreBreakdown' => [],
            'scoreDeductions' => [],
            'scoreTrend' => ['labels' => [], 'scores' => []],
            'statusCards' => [],
            'recommendations' => [],
            'allClear' => ['state' => 'needs_fixes', 'message' => null],
            'isFirstFinishedScan' => false,
        ];
    }
}
