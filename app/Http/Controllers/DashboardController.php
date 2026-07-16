<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\Domain;
use App\Models\Scan;
use App\Models\Incident;
use App\Services\Dmarc\DmarcAnalyticsService;
use App\Services\Dmarc\DmarcStatusService;
use App\Services\ScanTrendService;
use App\View\Presenters\CertificateSectionPresenter;
use App\Domain\EmailSecurity\Contracts\ScanReportFactoryInterface;

class DashboardController extends Controller
{
    /**
     * Create a new controller instance.
     */
    public function __construct()
    {
        $this->middleware('auth');
    }

    /**
     * Show the application dashboard.
     */
    public function index()
    {
        \Log::info('Dashboard accessed', [
            'user_id' => Auth::id(),
            'authenticated' => Auth::check(),
            'session_id' => session()->getId()
        ]);
        
        $user = Auth::user();

        // Get total domains count
        $totalDomains = $user->domains()->count();

        // Get recent scans
        $recentScans = Scan::with('domain')
            ->whereHas('domain', function ($query) use ($user) {
                $query->where('user_id', $user->id);
            })
            ->latest()
            ->take(5)
            ->get();

        // Get domains with relationships for blacklist widget
        $domains = $user->domains()->with(['activeSchedule', 'latestSpfCheck', 'scans' => function($query) {
            $query->whereHas('blacklistResults')->latest()->take(1);
        }])->get();

        // One authoritative completed-scan source drives every dashboard score.
        $completedScans = Scan::with('domain')
            ->where('user_id', $user->id)
            ->where('status', 'finished')
            ->whereNotNull('score')
            ->orderByDesc('finished_at')
            ->orderByDesc('created_at')
            ->get();
        $latestFinishedScan = $completedScans->first();
        $latestScansByDomain = $completedScans->unique('domain_id')->keyBy('domain_id');
        $lastScanDate = $latestFinishedScan?->finished_at ?? $latestFinishedScan?->created_at;
        $averageScore = $latestScansByDomain->isNotEmpty()
            ? round($latestScansByDomain->avg('score'), 1)
            : null;

        // Get unresolved incidents for user's domains
        $domainIds = $user->domains()->pluck('id');
        $unresolvedIncidents = Incident::whereIn('domain_id', $domainIds)
            ->unresolved()
            ->with(['domain.scans' => fn ($q) => $q->where('status', 'finished')->latest('finished_at')->limit(1)])
            ->orderByRaw("CASE severity WHEN 'incident' THEN 1 WHEN 'warning' THEN 2 ELSE 3 END")
            ->latest('occurred_at')
            ->take(5)
            ->get();

        $unresolvedIncidents->each(function (Incident $incident) use ($user) {
            $latestScan = $incident->domain?->scans->first();
            if ($user->canUseMonitoring()) {
                $incident->action_url = route('monitoring.incidents.show', $incident);
            } elseif ($latestScan) {
                $incident->action_url = route('reports.show', $latestScan);
            } else {
                $incident->action_url = route('domains.hub', $incident->domain);
            }
        });
        
        $incidentCount = Incident::whereIn('domain_id', $domainIds)
            ->unresolved()
            ->count();

        $priorityActions = collect();

        // Risk-based KPIs (replace passive metrics)
        $domainsAtRisk = $domains->filter(function($d) use ($latestScansByDomain) {
            $score = $latestScansByDomain->get($d->id)?->score;

            return ($score !== null && $score < 70) || $d->blacklist_status === 'listed';
        })->count();
        
        $expiringSoon = $domains->filter(function ($d) {
            $domainDays = $d->getDaysUntilDomainExpiry();
            $sslDays = $this->sslDaysForDomain($d);

            return ($domainDays !== null && $domainDays < 30) || ($sslDays !== null && $sslDays < 30);
        })->count();
        
        $monitoringGap = $domains->filter(function ($d) {
            $stale = $d->last_scanned_at === null || $d->last_scanned_at->lt(now()->subDays(7));
            if (!$stale) {
                return false;
            }
            $hasActiveSchedule = $d->activeSchedule && $d->activeSchedule->status === 'active';
            if ($hasActiveSchedule) {
                return true;
            }
            if ($d->created_at && $d->created_at->gt(now()->subHours(24))) {
                return false;
            }

            return true;
        })->count();

        $dmarcDashboard = app(DmarcAnalyticsService::class)->getDashboardSummary($user->id, 7);
        $dmarcEmptyState = ($dmarcDashboard['has_data'] ?? false)
            ? null
            : $this->resolveDmarcDashboardEmptyState($domains);
        $finishedScanCount = Scan::query()
            ->where('user_id', $user->id)
            ->where('status', 'finished')
            ->count();

        $awaitingFirstScan = $totalDomains > 0 && $finishedScanCount === 0;
        $firstScanPending = null;
        $firstScanDomain = null;
        $latestFindings = collect();
        $dashboardRecommendations = collect();
        $primaryFindingAction = null;
        $dashboardHero = null;
        $dashboardScoreHistory = ['labels' => [], 'scores' => [], 'statuses' => [], 'scan_ids' => [], 'count' => 0];

        if ($awaitingFirstScan) {
            $firstScanDomain = $domains->first();
            $firstScanPending = Scan::query()
                ->where('user_id', $user->id)
                ->whereIn('status', ['queued', 'running', 'failed'])
                ->latest()
                ->first();
        } elseif ($finishedScanCount > 0) {
            if ($latestFinishedScan && $latestFinishedScan->domain) {
                $report = app(ScanReportFactoryInterface::class)
                    ->build($latestFinishedScan, $latestFinishedScan->domain)
                    ->toArray();
                $latestFindings = collect($report['recommendations'] ?? [])
                    ->reject(fn ($r) => ($r['severity'] ?? '') === 'optional')
                    ->values();
                $resultJson = is_array($latestFinishedScan->result_json)
                    ? $latestFinishedScan->result_json
                    : (json_decode((string) $latestFinishedScan->result_json, true) ?? []);
                $unauthorizedExternalCount = (int) data_get(
                    $resultJson,
                    'dmarc.analysis.external_authorization.unauthorized_count',
                    0,
                );
                if ($unauthorizedExternalCount > 0
                    && !$latestFindings->contains(fn (array $finding) => ($finding['key'] ?? null) === 'dmarc_rua_unauthorized')) {
                    $latestFindings->push([
                        'key' => 'dmarc_rua_unauthorized',
                        'semantic_key' => 'authorize_external_dmarc_reporting',
                        'severity' => 'medium',
                        'priority' => 4,
                        'explanation' => 'An external DMARC report destination has not authorized this domain.',
                        'technical_target' => 'tech-dmarc_reports',
                        'locked' => false,
                    ]);
                }
                $severityOrder = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3];
                $dashboardRecommendations = $latestFindings
                    ->map(fn (array $finding, int $index) => $this->mapDashboardRecommendation(
                        $finding,
                        $latestFinishedScan->domain,
                        $latestFinishedScan,
                        $report['scoreBreakdown'] ?? [],
                        $index + 1,
                    ))
                    ->sort(function (array $a, array $b) use ($severityOrder): int {
                        return [
                            $severityOrder[$a['severity']] ?? 2,
                            -$a['score_impact_points'],
                            $a['security_rank'],
                            $a['locked'] ? 1 : 0,
                            $a['source_rank'],
                        ] <=> [
                            $severityOrder[$b['severity']] ?? 2,
                            -$b['score_impact_points'],
                            $b['security_rank'],
                            $b['locked'] ? 1 : 0,
                            $b['source_rank'],
                        ];
                    })
                    ->take(3)
                    ->values();
                $dashboardRecommendations->transform(function (array $recommendation, int $index): array {
                    $recommendation['rank'] = $index + 1;

                    return $recommendation;
                });
                $top = $dashboardRecommendations->first();
                $primaryFindingAction = $this->mapFindingToPrimaryAction(
                    $latestFindings->first(),
                    $latestFinishedScan->domain,
                    $latestFinishedScan
                );
                $dashboardHero = [
                    'scan_id' => (string) $latestFinishedScan->id,
                    'domain_id' => $latestFinishedScan->domain_id,
                    'domain' => $latestFinishedScan->domain->domain,
                    'score' => (int) $latestFinishedScan->score,
                    'status' => $this->scoreStatus((int) $latestFinishedScan->score),
                    'scanned_at' => $latestFinishedScan->finished_at ?? $latestFinishedScan->created_at,
                    'priority' => $top,
                    'report_url' => route('reports.show', $latestFinishedScan),
                ];
                $dashboardScoreHistory = app(ScanTrendService::class)
                    ->getDomainScanHistory($latestFinishedScan->domain_id, 30);
            }
        }

        $priorityActions = $dashboardRecommendations;
        $dashboardMetrics = $this->dashboardMetrics(
            $domainsAtRisk,
            $expiringSoon,
            $monitoringGap,
            $incidentCount,
            $domains,
            $dmarcDashboard,
            $dmarcEmptyState,
        );

        return view('dashboard.index', compact(
            'totalDomains',
            'lastScanDate',
            'averageScore',
            'recentScans',
            'domains',
            'unresolvedIncidents',
            'incidentCount',
            'priorityActions',
            'domainsAtRisk',
            'expiringSoon',
            'monitoringGap',
            'dmarcDashboard',
            'dmarcEmptyState',
            'dashboardScoreHistory',
            'dashboardHero',
            'dashboardRecommendations',
            'dashboardMetrics',
            'awaitingFirstScan',
            'firstScanPending',
            'firstScanDomain',
            'latestFindings',
            'primaryFindingAction',
            'latestFinishedScan',
            'finishedScanCount'
        ));
    }

    /**
     * @param array<string, mixed> $finding
     * @param list<array<string, mixed>> $scoreBreakdown
     * @return array<string, mixed>
     */
    protected function mapDashboardRecommendation(
        array $finding,
        Domain $domain,
        Scan $scan,
        array $scoreBreakdown,
        int $rank,
    ): array {
        $key = (string) ($finding['key'] ?? '');
        $reportUrl = route('reports.show', $scan);
        $target = $finding['technical_target'] ?? null;
        $technicalUrl = $reportUrl . ($target ? '#' . $target : '');

        [$title, $issueTitle, $explanation, $actionLabel, $actionUrl] = match ($key) {
            'spf_missing' => [
                'Add an SPF record',
                'SPF is missing',
                'No SPF record was found for ' . $domain->domain . '.',
                'Fix SPF',
                $reportUrl . '#tech-spf',
            ],
            'spf_invalid', 'spf_lookups' => [
                'Fix the SPF record',
                'SPF needs attention',
                (string) ($finding['explanation'] ?? 'The published SPF record needs correction.'),
                'Fix SPF',
                $reportUrl . '#tech-spf',
            ],
            'dmarc_mxscan_rua' => [
                'Relink MXScan reporting',
                'MXScan reporting is not linked',
                'An MXScan reporting address exists in DNS but is not linked to this domain.',
                'Relink reporting',
                route('dmarc.show', $domain),
            ],
            'dmarc_rua_unauthorized' => [
                'Resolve external DMARC authorization',
                'External DMARC authorization is required',
                'A third-party report destination has not authorized receiving reports for this domain.',
                'Review authorization',
                $reportUrl . '#tech-dmarc_reports',
            ],
            'mtasts' => [
                'Publish MTA-STS',
                'MTA-STS is missing',
                'Secure mail transport enforcement is not active for this domain.',
                'Publish MTA-STS',
                $reportUrl . '#tech-mtasts',
            ],
            default => [
                (string) ($finding['title'] ?? 'Review finding'),
                (string) ($finding['title'] ?? 'Security finding'),
                (string) ($finding['explanation'] ?? 'Review the full technical evidence.'),
                (string) ($finding['action'] ?? 'View full report'),
                $technicalUrl,
            ],
        };

        $scoreImpactPoints = $this->scoreImpactPointsForFinding($key, $scoreBreakdown);

        return [
            'rank' => $rank,
            'key' => $key,
            'semantic_key' => $finding['semantic_key'] ?? null,
            'severity' => strtolower((string) ($finding['severity'] ?? 'medium')),
            'title' => $title,
            'issue_title' => $issueTitle,
            'explanation' => $explanation,
            'score_impact' => $scoreImpactPoints > 0 ? 'Up to ' . $scoreImpactPoints . ' points available' : null,
            'score_impact_points' => $scoreImpactPoints,
            'security_rank' => (int) ($finding['priority'] ?? 99),
            'locked' => (bool) ($finding['locked'] ?? false),
            'source_rank' => $rank,
            'action_label' => $actionLabel,
            'action_url' => $actionUrl,
            'evidence_url' => $technicalUrl,
            'scan_id' => (string) $scan->id,
            'domain_id' => $domain->id,
            'domain' => $domain->domain,
            'score' => (int) $scan->score,
        ];
    }

    /**
     * @param list<array<string, mixed>> $scoreBreakdown
     */
    protected function scoreImpactPointsForFinding(string $key, array $scoreBreakdown): int
    {
        $scoreKey = match (true) {
            str_starts_with($key, 'spf') => 'spf',
            in_array($key, ['dmarc_rua_missing', 'dmarc_rua_unauthorized', 'dmarc_mxscan_rua'], true) => 'dmarc_reports',
            str_starts_with($key, 'dmarc') => 'dmarc_policy',
            $key === 'mtasts' => 'mtasts',
            $key === 'dkim_dns' => 'dkim',
            default => null,
        };
        if ($scoreKey === null) {
            return 0;
        }

        foreach ($scoreBreakdown as $row) {
            $candidate = ($row['key'] ?? null) === $scoreKey ? $row : null;
            if ($candidate === null) {
                $candidate = collect($row['subcomponents'] ?? [])->firstWhere('key', $scoreKey);
            }
            if ($candidate !== null) {
                $available = max(0, (int) ($candidate['possible'] ?? 0) - (int) ($candidate['earned'] ?? 0));

                return $available;
            }
        }

        return 0;
    }

    protected function scoreStatus(int $score): string
    {
        return match (true) {
            $score >= 80 => 'Strong',
            $score >= 60 => 'Needs attention',
            default => 'High risk',
        };
    }

    /**
     * @return list<array<string, mixed>>
     */
    protected function dashboardMetrics(
        int $domainsAtRisk,
        int $expiringSoon,
        int $monitoringGap,
        int $incidentCount,
        $domains,
        array $dmarcDashboard,
        ?array $dmarcEmptyState,
    ): array {
        $automationCount = $domains->filter(fn ($domain) => $domain->activeSchedule)->count();
        $dmarcNeedsAction = !($dmarcDashboard['has_data'] ?? false)
            && in_array($dmarcEmptyState['kind'] ?? null, ['detected_unlinked', 'not_connected'], true);

        return [
            [
                'icon' => 'shield-alert',
                'title' => 'Domains at risk',
                'value' => (string) $domainsAtRisk,
                'description' => $domainsAtRisk === 1
                    ? 'One domain has a score below 70 or is blacklisted.'
                    : ($domainsAtRisk > 1
                        ? $domainsAtRisk . ' domains have a score below 70 or are blacklisted.'
                        : 'No domains currently have a score below 70 or a blacklist finding.'),
                'state' => $domainsAtRisk > 0 ? 'danger' : 'success',
                'action_label' => $domainsAtRisk > 0 ? 'View domain' : null,
                'action_url' => route('dashboard.domains'),
            ],
            [
                'icon' => 'calendar-clock',
                'title' => 'Expiring soon',
                'value' => (string) $expiringSoon,
                'description' => $expiringSoon > 0
                    ? $expiringSoon . ' domains or certificates expire within 30 days.'
                    : 'No domains or certificates expire within 30 days.',
                'state' => $expiringSoon > 0 ? 'warning' : 'success',
                'action_label' => $expiringSoon > 0 ? 'Review expiry' : null,
                'action_url' => route('dashboard.domains'),
            ],
            [
                'icon' => 'clock-check',
                'title' => 'Monitoring coverage',
                'value' => $monitoringGap . ($monitoringGap === 1 ? ' gap' : ' gaps'),
                'description' => $monitoringGap > 0
                    ? 'One or more configured domains are overdue for an automated scan.'
                    : 'All configured domains are monitored on schedule.',
                'state' => $monitoringGap > 0 ? 'warning' : 'success',
                'action_label' => $monitoringGap > 0 ? 'Configure monitoring' : null,
                'action_url' => route('domains'),
            ],
            [
                'icon' => 'mail-check',
                'title' => 'DMARC reporting',
                'value' => ($dmarcDashboard['has_data'] ?? false) ? 'Receiving' : ($dmarcNeedsAction ? 'Needs action' : 'Waiting'),
                'description' => ($dmarcDashboard['has_data'] ?? false)
                    ? number_format($dmarcDashboard['total_volume']) . ' messages analyzed over 7 days.'
                    : ($dmarcEmptyState['copy'] ?? 'Waiting for the first aggregate report.'),
                'state' => $dmarcNeedsAction ? 'warning' : (($dmarcDashboard['has_data'] ?? false) ? 'success' : 'neutral'),
                'action_label' => $dmarcEmptyState['cta'] ?? 'View DMARC',
                'action_url' => ($dmarcDashboard['has_data'] ?? false)
                    ? route('dmarc.index')
                    : ($dmarcEmptyState['url'] ?? route('dmarc.index')),
            ],
            [
                'icon' => 'siren',
                'title' => 'Active security incidents',
                'value' => (string) $incidentCount,
                'description' => 'Operational alerts and detected security events. Configuration findings are listed separately.',
                'state' => $incidentCount > 0 ? 'danger' : 'success',
                'action_label' => $incidentCount > 0 ? 'View incidents' : null,
                'action_url' => route('monitoring.incidents'),
            ],
            [
                'icon' => 'workflow',
                'title' => 'Automations',
                'value' => (string) $automationCount,
                'description' => $automationCount > 0
                    ? $automationCount . ' domains have scheduled scans.'
                    : 'No scheduled scan automations are configured.',
                'state' => $automationCount > 0 ? 'success' : 'neutral',
                'action_label' => $automationCount > 0 ? 'View automations' : 'Create automation',
                'action_url' => route('automations.index'),
            ],
        ];
    }

    /**
     * Resolve dashboard DMARC empty-state copy from rua_link_state across domains.
     *
     * Priority when no aggregate report data: detected_unlinked → not_connected → waiting.
     *
     * @param \Illuminate\Support\Collection<int, Domain> $domains
     * @return array{kind: string, copy: string, cta: string|null, url: string}|null
     */
    protected function resolveDmarcDashboardEmptyState($domains): ?array
    {
        if ($domains->isEmpty()) {
            return null;
        }

        $statusService = app(DmarcStatusService::class);
        $unlinkedDomain = null;
        $notConnectedDomain = null;
        $waitingDomain = null;

        foreach ($domains as $domain) {
            $status = $statusService->getStatus($domain);
            $ruaState = $status['rua_link_state'] ?? null;

            if ($ruaState === DmarcStatusService::RUA_LINK_DETECTED_UNLINKED && $unlinkedDomain === null) {
                $unlinkedDomain = $domain;
            } elseif ($ruaState === DmarcStatusService::RUA_LINK_NOT_CONNECTED
                && ($status['has_dmarc_record'] ?? false)
                && $notConnectedDomain === null) {
                $notConnectedDomain = $domain;
            } elseif (
                ($ruaState === DmarcStatusService::RUA_LINK_CONNECTED
                    || ($status['status'] ?? null) === DmarcStatusService::STATUS_ENABLED_MXSCAN_WAITING)
                && $waitingDomain === null
            ) {
                $waitingDomain = $domain;
            }
        }

        if ($unlinkedDomain) {
            return [
                'kind' => 'detected_unlinked',
                'copy' => 'MXScan reporting is present, but it is not linked to this domain.',
                'cta' => 'Relink MXScan reporting',
                'url' => route('dmarc.show', $unlinkedDomain),
            ];
        }

        if ($notConnectedDomain) {
            return [
                'kind' => 'not_connected',
                'copy' => 'DMARC is active. Connect MXScan reporting to identify senders and authentication failures.',
                'cta' => 'Connect MXScan reporting',
                'url' => route('dmarc.show', $notConnectedDomain),
            ];
        }

        if ($waitingDomain) {
            return [
                'kind' => 'waiting',
                'copy' => 'Waiting for the first aggregate report. Reports commonly arrive within 24–48 hours.',
                'cta' => null,
                'url' => route('dmarc.show', $waitingDomain),
            ];
        }

        return [
            'kind' => 'waiting',
            'copy' => 'Waiting for the first aggregate report. Reports commonly arrive within 24–48 hours.',
            'cta' => null,
            'url' => route('dmarc.index'),
        ];
    }

    /**
     * @param array<string, mixed>|null $finding
     * @return array{label: string, url: string}|null
     */
    protected function mapFindingToPrimaryAction(?array $finding, Domain $domain, Scan $scan): ?array
    {
        if (!$finding) {
            $dmarcStatus = app(DmarcStatusService::class)->getStatus($domain);
            $ruaState = $dmarcStatus['rua_link_state'] ?? null;
            if ($ruaState === DmarcStatusService::RUA_LINK_DETECTED_UNLINKED) {
                return [
                    'label' => 'Relink reporting',
                    'url' => route('dmarc.show', $domain),
                ];
            }

            return [
                'label' => 'View full report',
                'url' => route('reports.show', $scan),
            ];
        }

        $label = match ($finding['key'] ?? '') {
            'blacklist' => 'Review blacklist listing',
            'spf_missing', 'spf_invalid', 'spf_lookups' => 'Fix SPF',
            'dmarc_mxscan_rua' => 'Relink reporting',
            'dmarc_rua_unauthorized' => 'Review authorization',
            'dmarc_missing', 'dmarc_policy', 'dmarc_alignment' => 'Fix DMARC policy',
            'dkim_dns' => 'Add DKIM DNS configuration',
            default => $finding['action'] ?? 'View full report',
        };

        $target = $finding['technical_target'] ?? null;
        $url = match ($finding['key'] ?? '') {
            'dmarc_mxscan_rua' => route('dmarc.show', $domain),
            default => route('reports.show', $scan) . ($target ? '#' . $target : ''),
        };

        return [
            'label' => $label,
            'url' => $url,
        ];
    }

    private function sslDaysForDomain(Domain $domain): ?int
    {
        $latestScan = $domain->scans()->where('status', 'finished')->latest('finished_at')->first();
        $certificatesInfo = null;
        $mtaStsInfo = null;

        if ($latestScan !== null) {
            $resultJson = $latestScan->result_json ?? [];
            if (is_array($resultJson)) {
                $certificatesInfo = is_array($resultJson['certificates'] ?? null)
                    ? $resultJson['certificates']
                    : null;
                $mtaStsInfo = is_array($resultJson['mta_sts'] ?? null)
                    ? $resultJson['mta_sts']
                    : null;
            }
        }

        return (new CertificateSectionPresenter($certificatesInfo, $mtaStsInfo, $domain))->sslDays();
    }
}
