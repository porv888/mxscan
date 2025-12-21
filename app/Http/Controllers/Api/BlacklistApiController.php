<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Domain;
use App\Models\BlacklistResult;
use App\Services\BlacklistChecker;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Carbon\Carbon;

class BlacklistApiController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:sanctum');
    }

    /**
     * Get blacklist status for a domain.
     */
    public function status(Request $request, Domain $domain): JsonResponse
    {
        $this->authorize('view', $domain);

        $latestScan = $domain->scans()
            ->whereHas('blacklistResults')
            ->latest()
            ->first();

        if (!$latestScan) {
            return response()->json([
                'status' => 'not_checked',
                'message' => 'No blacklist checks performed yet',
                'data' => null
            ]);
        }

        $blacklistResults = $latestScan->blacklistResults;
        $summary = (new BlacklistChecker())->getScanSummary($latestScan);

        return response()->json([
            'status' => $summary['is_clean'] ? 'clean' : 'listed',
            'message' => $summary['is_clean'] ? 'Domain is clean' : 'Domain has blacklist entries',
            'data' => [
                'domain' => $domain->domain,
                'scan_id' => $latestScan->id,
                'scan_date' => $latestScan->created_at->toISOString(),
                'summary' => $summary,
                'results' => $blacklistResults->groupBy('ip_address')->map(function($ipResults, $ip) {
                    return [
                        'ip_address' => $ip,
                        'status' => $ipResults->where('status', 'listed')->count() > 0 ? 'listed' : 'clean',
                        'providers' => $ipResults->map(function($result) {
                            return [
                                'provider' => $result->provider,
                                'status' => $result->status,
                                'message' => $result->message,
                                'removal_url' => $result->removal_url
                            ];
                        })
                    ];
                })
            ]
        ]);
    }

    /**
     * Get blacklist history for a domain.
     */
    public function history(Request $request, Domain $domain): JsonResponse
    {
        $this->authorize('view', $domain);

        $days = $request->get('days', 30);
        $startDate = Carbon::now()->subDays($days);

        $scans = $domain->scans()
            ->whereHas('blacklistResults')
            ->where('created_at', '>=', $startDate)
            ->with('blacklistResults')
            ->orderBy('created_at', 'desc')
            ->get();

        $history = $scans->map(function($scan) {
            $blacklistResults = $scan->blacklistResults;
            $listedCount = $blacklistResults->where('status', 'listed')->count();
            
            return [
                'scan_id' => $scan->id,
                'scan_date' => $scan->created_at->toISOString(),
                'status' => $listedCount > 0 ? 'listed' : 'clean',
                'total_checks' => $blacklistResults->count(),
                'listed_count' => $listedCount,
                'unique_ips' => $blacklistResults->pluck('ip_address')->unique()->count()
            ];
        });

        return response()->json([
            'status' => 'success',
            'data' => [
                'domain' => $domain->domain,
                'period' => [
                    'start' => $startDate->toISOString(),
                    'end' => now()->toISOString(),
                    'days' => $days
                ],
                'history' => $history
            ]
        ]);
    }

    /**
     * Trigger a new blacklist check.
     */
    public function check(Request $request, Domain $domain): JsonResponse
    {
        $this->authorize('update', $domain);

        try {
            $scan = \App\Models\Scan::create([
                'domain_id' => $domain->id,
                'user_id' => $request->user()->id,
                'status' => 'running',
                'progress_pct' => 0,
            ]);

            $blacklistChecker = new BlacklistChecker();
            $results = $blacklistChecker->checkDomain($scan, $domain->domain);
            $summary = $blacklistChecker->getScanSummary($scan);

            $score = $summary['is_clean'] ? 100 : max(100 - ($summary['listed_count'] * 20), 0);

            $scan->update([
                'status' => 'finished',
                'progress_pct' => 100,
                'score' => $score,
                'facts_json' => json_encode(['blacklist_summary' => $summary]),
                'finished_at' => now(),
            ]);

            return response()->json([
                'status' => 'success',
                'message' => 'Blacklist check completed',
                'data' => [
                    'scan_id' => $scan->id,
                    'domain' => $domain->domain,
                    'summary' => $summary,
                    'scan_url' => route('scans.show', $scan)
                ]
            ]);

        } catch (\Exception $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'Blacklist check failed: ' . $e->getMessage()
            ], 500);
        }
    }

    /**
     * Get blacklist statistics for user's domains.
     */
    public function statistics(Request $request): JsonResponse
    {
        $user = $request->user();
        $days = $request->get('days', 30);
        $startDate = Carbon::now()->subDays($days);

        $domains = $user->domains()->with(['scans' => function($query) use ($startDate) {
            $query->whereHas('blacklistResults')
                  ->where('created_at', '>=', $startDate);
        }])->get();

        $totalChecks = 0;
        $listedCount = 0;
        $domainsMonitored = 0;
        $currentlyListed = 0;

        foreach ($domains as $domain) {
            $hasChecks = false;
            $domainListed = false;

            foreach ($domain->scans as $scan) {
                $results = $scan->blacklistResults;
                if ($results->count() > 0) {
                    $hasChecks = true;
                    $totalChecks += $results->count();
                    $scanListed = $results->where('status', 'listed')->count();
                    $listedCount += $scanListed;
                    
                    if ($scanListed > 0) {
                        $domainListed = true;
                    }
                }
            }

            if ($hasChecks) {
                $domainsMonitored++;
                if ($domainListed) {
                    $currentlyListed++;
                }
            }
        }

        return response()->json([
            'status' => 'success',
            'data' => [
                'period' => [
                    'start' => $startDate->toISOString(),
                    'end' => now()->toISOString(),
                    'days' => $days
                ],
                'statistics' => [
                    'total_checks' => $totalChecks,
                    'listed_results' => $listedCount,
                    'clean_results' => $totalChecks - $listedCount,
                    'domains_monitored' => $domainsMonitored,
                    'domains_currently_listed' => $currentlyListed,
                    'domains_clean' => $domainsMonitored - $currentlyListed
                ]
            ]
        ]);
    }
}