<?php

namespace App\Domain\EmailSecurity\Reporting;

use App\Domain\EmailSecurity\Checks\Bimi\BimiAnalysisReader;
use App\Domain\EmailSecurity\Checks\Bimi\BimiStates;
use App\Domain\EmailSecurity\Contracts\ScanReportFactoryInterface;
use App\Domain\EmailSecurity\DTO\ScanReportViewModelDTO;
use App\Domain\EmailSecurity\Recommendations\ScanRecommendationService;
use App\Domain\EmailSecurity\Remediation\TechnicalRemediationBuilder;
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
        private TechnicalRemediationBuilder $technicalRemediationBuilder,
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
        $dmarcAlignmentVerification = is_string($dmarcAnalysis['alignment_verification'] ?? null)
            ? $dmarcAnalysis['alignment_verification']
            : \App\Domain\EmailSecurity\Checks\DMARC\DmarcAlignmentVerification::NOT_VERIFIED;
        $dmarcAligned = match ($dmarcAlignmentVerification) {
            \App\Domain\EmailSecurity\Checks\DMARC\DmarcAlignmentVerification::ALIGNED => true,
            \App\Domain\EmailSecurity\Checks\DMARC\DmarcAlignmentVerification::NOT_ALIGNED => false,
            default => null,
        };

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
        $scoreBreakdown = $this->withDmarcSubcomponents($scoreBreakdown, $dmarcAnalysis);
        $scoreDeductions = $this->scoreBreakdownService->deductions($scoreBreakdown);
        $technicalRemediation = $this->technicalRemediationBuilder->build($domain, $scan, $resultData);

        $statusCards = $this->statusMapper->buildStatusCards(
            $resultData,
            $records,
            $scan->score
        );

        $recommendations = $this->recommendationService->build($domain, $resultData, $records);
        $allClear = $this->recommendationService->evaluateAllClear($resultData, $records);

        app(ScanReportInvariantGuard::class)->assertConsistent(
            $scan->score,
            $resultData,
            $records,
            $statusCards,
            $recommendations,
            $scoreBreakdown,
            (string) $scan->id,
        );

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
            'dmarcAlignmentVerification',
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
            'technicalRemediation',
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
            'dmarcAlignmentVerification' => 'not_verified',
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
            'technicalRemediation' => [],
            'scoreTrend' => ['labels' => [], 'scores' => []],
            'statusCards' => [],
            'recommendations' => [],
            'allClear' => ['state' => 'needs_fixes', 'message' => null],
            'isFirstFinishedScan' => false,
        ];
    }

    /**
     * @param list<array<string, mixed>> $breakdown
     * @param array<string, mixed> $analysis
     * @return list<array<string, mixed>>
     */
    private function withDmarcSubcomponents(array $breakdown, array $analysis): array
    {
        foreach ($breakdown as &$row) {
            if (($row['key'] ?? '') !== 'dmarc' || !empty($row['subcomponents'])) {
                continue;
            }

            $policy = is_array($analysis['policy'] ?? null) ? $analysis['policy'] : [];
            $enforcement = $policy['enforcement'] ?? 'unknown';
            $effectivePolicy = $policy['effective_policy'] ?? null;
            $pct = (int) ($policy['pct'] ?? 100);
            $testing = (bool) ($policy['testing_mode'] ?? false);
            $policyEarned = match (true) {
                $testing, $effectivePolicy === 'none', $pct === 0, $enforcement === 'monitoring' => 12,
                $enforcement === 'partial_enforcement' && $effectivePolicy === 'quarantine' => 20,
                in_array($enforcement, ['partial_enforcement', 'quarantine', 'reject'], true) => 24,
                default => 0,
            };

            $reporting = is_array($analysis['aggregate_reporting'] ?? null)
                ? $analysis['aggregate_reporting']
                : [];
            $destinations = is_array($reporting['destinations'] ?? null)
                ? $reporting['destinations']
                : [];
            $authorized = $destinations !== [] && collect($destinations)->every(
                fn ($destination) => is_array($destination)
                    && in_array($destination['authorization_status'] ?? 'unknown', ['authorized', 'not_required'], true)
            );
            $expectation = is_array($reporting['mxscan_expectation'] ?? null)
                ? $reporting['mxscan_expectation']
                : [];
            $linked = ($expectation['expected_address'] ?? null) === null || ($expectation['present'] ?? false) === true;
            $reportsEarned = ($reporting['configured'] ?? false) && $authorized && $linked ? 6 : 0;

            $row['subcomponents'] = [
                [
                    'key' => 'dmarc_policy',
                    'label' => 'DMARC Policy',
                    'earned' => $policyEarned,
                    'possible' => 24,
                    'status' => $policyEarned === 24 ? 'ok' : 'partial',
                ],
                [
                    'key' => 'dmarc_reports',
                    'label' => 'DMARC Reports',
                    'earned' => $reportsEarned,
                    'possible' => 6,
                    'status' => $reportsEarned === 6 ? 'ok' : 'partial',
                ],
            ];
        }
        unset($row);

        return $breakdown;
    }
}
