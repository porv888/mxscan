<?php

namespace App\Domain\EmailSecurity\Reporting;

use App\Domain\EmailSecurity\Checks\Bimi\BimiAnalysisReader;
use App\Domain\EmailSecurity\Checks\Bimi\BimiStates;
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

        $dmarcInfo = $resultData['dmarc'] ?? null;
        $dmarcAnalysis = \App\Domain\EmailSecurity\Checks\DMARC\Support\DmarcAnalysisReader::analysis($dmarcInfo)
            ?? \App\Domain\EmailSecurity\Checks\DMARC\Support\DmarcAnalysisReader::fromLegacyDnsRecord(
                $records['DMARC'] ?? null,
                $dmarcInfo,
            );
        $dmarcPolicy = is_array($dmarcAnalysis['policy'] ?? null)
            ? ($dmarcAnalysis['policy']['effective_policy'] ?? $dmarcAnalysis['policy']['published_p'] ?? null)
            : null;
        $alignment = is_array($dmarcAnalysis['alignment'] ?? null) ? $dmarcAnalysis['alignment'] : [];
        $dmarcAligned = ($alignment['dkim'] ?? 'relaxed') === 'strict'
            || ($alignment['spf'] ?? 'relaxed') === 'strict';

        $tlsRptInfo = $resultData['tls_rpt'] ?? null;
        $tlsRptAnalysis = \App\Domain\EmailSecurity\Checks\TlsRpt\Support\TlsRptAnalysisReader::analysis($tlsRptInfo)
            ?? \App\Domain\EmailSecurity\Checks\TlsRpt\Support\TlsRptAnalysisReader::fromLegacyDnsRecord(
                $records['TLS-RPT'] ?? null,
                $tlsRptInfo,
            );
        $tlsrptOk = ($tlsRptAnalysis['state'] ?? '') === \App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptStates::PASS;
        $mtaStsInfo = $resultData['mta_sts'] ?? null;
        $mtaStsAnalysis = \App\Domain\EmailSecurity\Checks\MtaSts\Support\MtaStsAnalysisReader::analysis($mtaStsInfo)
            ?? \App\Domain\EmailSecurity\Checks\MtaSts\Support\MtaStsAnalysisReader::fromLegacyDnsRecord(
                $records['MTA-STS'] ?? null,
                $mtaStsInfo,
            );
        $mtastsOk = ($mtaStsAnalysis['state'] ?? '') === \App\Domain\EmailSecurity\Checks\MtaSts\MtaStsStates::PASS;
        $bimiInfo = $resultData['bimi'] ?? null;
        $bimiAnalysis = BimiAnalysisReader::analysis($bimiInfo)
            ?? BimiAnalysisReader::fromLegacyDnsRecord($records['BIMI'] ?? null, $bimiInfo);
        $bimiHasData = $bimiInfo !== null || isset($records['BIMI']);
        $bimiOk = in_array($bimiAnalysis['state'] ?? '', [BimiStates::PASS, BimiStates::DECLINED], true);

        $blacklistData = $resultData['blacklist'] ?? null;
        $blacklistAnalysis = \App\Domain\EmailSecurity\Checks\Blacklist\Support\BlacklistAnalysisReader::resolvedAnalysis(
            is_array($blacklistData) ? $blacklistData : null,
        );
        $blacklistCounts = is_array($blacklistAnalysis['counts'] ?? null) ? $blacklistAnalysis['counts'] : [];
        $blacklistHits = (int) ($blacklistCounts['listed_results'] ?? (is_array($blacklistData) ? ($blacklistData['listed_count'] ?? 0) : 0));
        $blacklistTotal = (int) ($blacklistCounts['usable_results'] ?? (is_array($blacklistData) ? ($blacklistData['total_checks'] ?? 0) : 0));
        $blacklistRows = $scan->blacklistResults;

        $domainDays = $domain->getDaysUntilDomainExpiry();
        $certificatesInfo = $resultData['certificates'] ?? null;
        $sslPresenter = new \App\View\Presenters\CertificateSectionPresenter(
            certificatesInfo: is_array($certificatesInfo) ? $certificatesInfo : null,
            mtaStsInfo: is_array($mtaStsInfo) ? $mtaStsInfo : null,
            domain: $domain,
        );
        $sslDays = $sslPresenter->sslDays();

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
