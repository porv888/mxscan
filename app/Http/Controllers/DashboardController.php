<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\Domain;
use App\Models\Scan;
use App\Models\Incident;

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
            ->with('domain')
            ->orderByRaw("CASE severity WHEN 'incident' THEN 1 WHEN 'warning' THEN 2 ELSE 3 END")
            ->latest('occurred_at')
            ->take(5)
            ->get();
        
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
        
        $unscannedDomains = $domains->filter(function($d) {
            return $d->last_scanned_at === null || $d->last_scanned_at->lt(now()->subDays(7));
        })->count();

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
            'unscannedDomains'
        ));
    }
}
