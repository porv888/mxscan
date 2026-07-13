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

        // Get last scan date from domains
        $lastScanDomain = $user->domains()
            ->whereNotNull('last_scanned_at')
            ->orderByDesc('last_scanned_at')
            ->first();
        
        $lastScanDate = $lastScanDomain ? $lastScanDomain->last_scanned_at : null;

        // Get average security score
        $averageScore = $user->domains()
            ->whereNotNull('score_last')
            ->avg('score_last');

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

        // Build priority actions list
        $priorityActions = collect();
        
        foreach ($domains as $domain) {
            // Check for blacklisted domains
            if ($domain->blacklist_status === 'listed') {
                $latestScan = $domain->scans()->latest()->first();
                if ($latestScan) {
                    $priorityActions->push([
                        'type' => 'blacklist',
                        'severity' => 'critical',
                        'icon' => 'shield-alert',
                        'title' => 'Remove from blacklists',
                        'description' => $domain->domain . ' is listed on ' . $domain->blacklist_count . ' blacklist(s)',
                        'domain' => $domain,
                        'action_url' => route('scans.show', $latestScan),
                        'action_label' => 'View & Fix'
                    ]);
                }
            }
            
            // Check for low scores
            if ($domain->score_last !== null && $domain->score_last < 60) {
                $latestScan = $domain->scans()->latest()->first();
                $priorityActions->push([
                    'type' => 'score',
                    'severity' => 'warning',
                    'icon' => 'trending-down',
                    'title' => 'Improve security score',
                    'description' => $domain->domain . ' has a score of ' . $domain->score_last . '%',
                    'domain' => $domain,
                    'action_url' => $latestScan ? route('scans.show', $latestScan) : route('dashboard.domains'),
                    'action_label' => 'View Report'
                ]);
            }
            
            // Check for expiring domains/SSL
            $domainDays = $domain->getDaysUntilDomainExpiry();
            $sslDays = $domain->getDaysUntilSslExpiry();
            
            if ($domainDays !== null && $domainDays < 30) {
                $priorityActions->push([
                    'type' => 'expiry',
                    'severity' => $domainDays < 7 ? 'critical' : 'warning',
                    'icon' => 'calendar-x',
                    'title' => 'Domain expiring soon',
                    'description' => $domain->domain . ' expires in ' . $domainDays . ' days',
                    'domain' => $domain,
                    'action_url' => route('dashboard.domains.edit', $domain),
                    'action_label' => 'Renew'
                ]);
            }
            
            if ($sslDays !== null && $sslDays < 30) {
                $priorityActions->push([
                    'type' => 'ssl',
                    'severity' => $sslDays < 7 ? 'critical' : 'warning',
                    'icon' => 'lock',
                    'title' => 'SSL certificate expiring',
                    'description' => $domain->domain . ' SSL expires in ' . $sslDays . ' days',
                    'domain' => $domain,
                    'action_url' => route('dashboard.domains.edit', $domain),
                    'action_label' => 'Renew'
                ]);
            }
            
            // Check for SPF issues
            $spfCheck = $domain->latestSpfCheck;
            if ($spfCheck && $spfCheck->lookup_count >= 10) {
                $priorityActions->push([
                    'type' => 'spf',
                    'severity' => 'warning',
                    'icon' => 'mail-warning',
                    'title' => 'SPF lookup limit exceeded',
                    'description' => $domain->domain . ' uses ' . $spfCheck->lookup_count . '/10 DNS lookups',
                    'domain' => $domain,
                    'action_url' => route('spf.show', $domain),
                    'action_label' => 'Fix SPF'
                ]);
            }
        }
        
        // Sort by severity and take top 3
        $priorityActions = $priorityActions->sortBy(function($action) {
            return $action['severity'] === 'critical' ? 0 : 1;
        })->take(3)->values();

        // Risk-based KPIs (replace passive metrics)
        $domainsAtRisk = $domains->filter(function($d) {
            return ($d->score_last !== null && $d->score_last < 70) || $d->blacklist_status === 'listed';
        })->count();
        
        $expiringSoon = $domains->filter(function($d) {
            $domainDays = $d->getDaysUntilDomainExpiry();
            $sslDays = $d->getDaysUntilSslExpiry();
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
        $scoreTrend = app(ScanTrendService::class)->getUserTrend($user->id, 30);

        $finishedScanCount = Scan::query()
            ->where('user_id', $user->id)
            ->where('status', 'finished')
            ->count();

        $awaitingFirstScan = $totalDomains > 0 && $finishedScanCount === 0;
        $firstScanPending = null;
        $firstScanDomain = null;
        $latestFindings = collect();
        $primaryFindingAction = null;
        $latestFinishedScan = null;

        if ($awaitingFirstScan) {
            $firstScanDomain = $domains->first();
            $firstScanPending = Scan::query()
                ->where('user_id', $user->id)
                ->whereIn('status', ['queued', 'running', 'failed'])
                ->latest()
                ->first();
        } elseif ($finishedScanCount > 0) {
            $latestFinishedScan = Scan::with('domain')
                ->where('user_id', $user->id)
                ->where('status', 'finished')
                ->latest('finished_at')
                ->first();

            if ($latestFinishedScan && $latestFinishedScan->domain) {
                $resultJson = $latestFinishedScan->result_json ?? [];
                if (is_string($resultJson)) {
                    $resultJson = json_decode($resultJson, true) ?? [];
                }
                $recs = app(\App\Services\ScanReport\ScanRecommendationService::class)
                    ->build($latestFinishedScan->domain, $resultJson);
                $latestFindings = collect($recs)
                    ->reject(fn ($r) => ($r['severity'] ?? '') === 'optional')
                    ->take(3)
                    ->values();

                $top = $latestFindings->first();
                $primaryFindingAction = $this->mapFindingToPrimaryAction(
                    $top,
                    $latestFinishedScan->domain,
                    $latestFinishedScan
                );
            }
        }

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
            'scoreTrend',
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
        $dmarcStatus = app(DmarcStatusService::class)->getStatus($domain);
        $ruaState = $dmarcStatus['rua_link_state'] ?? null;

        if ($ruaState === DmarcStatusService::RUA_LINK_NOT_CONNECTED
            && ($dmarcStatus['has_dmarc_record'] ?? false)) {
            return [
                'label' => 'Connect DMARC reporting',
                'url' => route('dmarc.show', $domain),
            ];
        }
        if ($ruaState === DmarcStatusService::RUA_LINK_DETECTED_UNLINKED) {
            return [
                'label' => 'Relink MXScan reporting',
                'url' => route('dmarc.show', $domain),
            ];
        }

        if (!$finding) {
            return [
                'label' => 'View full report',
                'url' => route('reports.show', $scan),
            ];
        }

        $label = match ($finding['key'] ?? '') {
            'blacklist' => 'Review blacklist listing',
            'spf_missing' => 'Add SPF record',
            'spf_invalid', 'spf_lookups' => 'Fix SPF record',
            'dmarc_missing', 'dmarc_policy', 'dmarc_alignment' => 'Fix DMARC policy',
            'dkim_dns' => 'Add DKIM DNS configuration',
            default => $finding['action'] ?? 'View full report',
        };

        return [
            'label' => $label,
            'url' => route('reports.show', $scan) . '#fix-pack',
        ];
    }
}
