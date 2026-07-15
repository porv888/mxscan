<?php

namespace App\Http\Controllers\Api;

use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistScanOrchestrator;
use App\Domain\EmailSecurity\Checks\Blacklist\Support\BlacklistAnalysisReader;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Http\Controllers\Controller;
use App\Models\BlacklistResult;
use App\Models\Domain;
use App\Services\Entitlement\EntitlementFeature;
use App\Services\Entitlement\EntitlementService;
use Carbon\Carbon;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class BlacklistApiController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:sanctum');
    }

    public function status(Request $request, Domain $domain): JsonResponse
    {
        $this->authorize('view', $domain);

        $latestScan = $domain->scans()
            ->where(function ($query) {
                $query->where('type', 'blacklist')->orWhere('type', 'full');
            })
            ->whereNotNull('result_json')
            ->latest()
            ->first();

        if ($latestScan === null) {
            return response()->json([
                'status' => 'not_checked',
                'message' => 'No blacklist checks performed yet',
                'data' => null,
            ]);
        }

        $blacklist = is_array($latestScan->result_json) ? ($latestScan->result_json['blacklist'] ?? null) : null;
        $facts = BlacklistAnalysisReader::facts(is_array($blacklist) ? $blacklist : null);
        $blacklistResults = $latestScan->blacklistResults;

        return response()->json([
            'status' => $facts['blacklist_status'] ?? 'not-checked',
            'reputation_status' => $facts['blacklist_reputation_status'] ?? null,
            'message' => BlacklistAnalysisReader::summary(is_array($blacklist) ? $blacklist : null)
                ?? 'Blacklist status available',
            'data' => [
                'domain' => $domain->domain,
                'scan_id' => $latestScan->id,
                'scan_date' => $latestScan->created_at->toISOString(),
                'facts' => $facts,
                'summary' => is_array($blacklist) ? $blacklist : null,
                'results' => $blacklistResults->groupBy('ip_address')->map(function ($ipResults, $ip) {
                    return [
                        'ip_address' => $ip,
                        'status' => $ipResults->where('status', 'listed')->count() > 0 ? 'listed' : 'clean',
                        'providers' => $ipResults->map(function ($result) {
                            return [
                                'provider' => $result->provider,
                                'status' => $result->status,
                                'message' => $result->message,
                                'removal_url' => $result->removal_url,
                            ];
                        }),
                    ];
                }),
            ],
        ]);
    }

    public function history(Request $request, Domain $domain): JsonResponse
    {
        $this->authorize('view', $domain);

        $days = $request->get('days', 30);
        $startDate = Carbon::now()->subDays($days);

        $scans = $domain->scans()
            ->where(function ($query) {
                $query->where('type', 'blacklist')->orWhere('type', 'full');
            })
            ->whereNotNull('result_json')
            ->where('created_at', '>=', $startDate)
            ->orderBy('created_at', 'desc')
            ->get();

        $history = $scans->map(function ($scan) {
            $blacklist = is_array($scan->result_json) ? ($scan->result_json['blacklist'] ?? null) : null;
            $facts = BlacklistAnalysisReader::facts(is_array($blacklist) ? $blacklist : null);

            return [
                'scan_id' => $scan->id,
                'scan_date' => $scan->created_at->toISOString(),
                'status' => $facts['blacklist_status'] ?? 'not-checked',
                'reputation_status' => $facts['blacklist_reputation_status'] ?? null,
                'usable_results' => $facts['blacklist_usable_results'] ?? 0,
                'listed_count' => $facts['blacklist_count'] ?? 0,
            ];
        });

        return response()->json([
            'status' => 'success',
            'data' => [
                'domain' => $domain->domain,
                'period' => [
                    'start' => $startDate->toISOString(),
                    'end' => now()->toISOString(),
                    'days' => $days,
                ],
                'history' => $history,
            ],
        ]);
    }

    public function check(Request $request, Domain $domain, EntitlementService $entitlements, BlacklistScanOrchestrator $orchestrator): JsonResponse
    {
        $this->authorize('update', $domain);

        if (!$entitlements->canOnDomain($request->user(), $domain, EntitlementFeature::PARTIAL_SCAN)) {
            return response()->json([
                'status' => 'error',
                'message' => $entitlements->denyMessage(EntitlementFeature::PARTIAL_SCAN),
                'upgrade_url' => $entitlements->upgradeUrl(),
            ], 402);
        }

        try {
            $scan = \App\Models\Scan::create([
                'domain_id' => $domain->id,
                'user_id' => $request->user()->id,
                'type' => 'blacklist',
                'status' => 'running',
                'progress_pct' => 0,
            ]);

            $context = CheckContextDTO::fromExecution(
                $domain,
                $scan,
                new ScanOptionsDTO(dns: false, spf: false, blacklist: true),
            );

            $execution = $orchestrator->run($scan, $context);
            $payload = $execution['payload'];
            $facts = BlacklistAnalysisReader::facts($payload);

            $scan->update([
                'status' => 'finished',
                'progress_pct' => 100,
                'result_json' => ['blacklist' => $payload],
                'facts_json' => $facts,
                'finished_at' => now(),
            ]);

            return response()->json([
                'status' => 'success',
                'message' => 'Blacklist check completed',
                'data' => [
                    'scan_id' => $scan->id,
                    'domain' => $domain->domain,
                    'reputation_status' => $facts['blacklist_reputation_status'] ?? null,
                    'facts' => $facts,
                    'summary' => $payload,
                    'scan_url' => route('scans.show', $scan),
                ],
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'Blacklist check failed: ' . $e->getMessage(),
            ], 500);
        }
    }

    public function statistics(Request $request): JsonResponse
    {
        $user = $request->user();
        $domainIds = $user->domains()->pluck('id');

        $totalChecks = BlacklistResult::whereHas('scan', function ($query) use ($domainIds) {
            $query->whereIn('domain_id', $domainIds);
        })->count();

        $listedChecks = BlacklistResult::whereHas('scan', function ($query) use ($domainIds) {
            $query->whereIn('domain_id', $domainIds);
        })->where('status', 'listed')->count();

        return response()->json([
            'status' => 'success',
            'data' => [
                'total_checks' => $totalChecks,
                'listed_checks' => $listedChecks,
                'clean_checks' => max(0, $totalChecks - $listedChecks),
            ],
        ]);
    }
}
