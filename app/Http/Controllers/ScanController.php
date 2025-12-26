<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\Domain;
use App\Models\Scan;
use App\Jobs\RunFullScan;
use App\Services\ScanRunner;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;
use App\Services\ScannerService;
use Symfony\Component\HttpFoundation\Response;

class ScanController extends Controller
{
    /**
     * Display a listing of scans.
     */
    public function index(Request $request)
    {
        $query = Scan::with('domain')
            ->where('user_id', Auth::id());

        // Apply filters
        $filter = $request->get('filter');
        if ($filter === 'failed') {
            $query->where('status', 'failed');
        } elseif ($filter === 'dropped') {
            // Scans where score dropped compared to previous
            $query->whereRaw('score < (SELECT s2.score FROM ' . (new Scan)->getTable() . ' s2 WHERE s2.domain_id = ' . (new Scan)->getTable() . '.domain_id AND s2.id < ' . (new Scan)->getTable() . '.id ORDER BY s2.id DESC LIMIT 1)');
        } elseif ($filter === 'week') {
            $query->where('created_at', '>=', now()->subDays(7));
        }

        $scans = $query->orderBy('created_at', 'desc')->paginate(20);

        // Calculate score deltas for each scan
        foreach ($scans as $scan) {
            $previousScan = Scan::where('domain_id', $scan->domain_id)
                ->where('id', '<', $scan->id)
                ->whereNotNull('score')
                ->orderBy('id', 'desc')
                ->first();
            
            $scan->score_delta = $previousScan && $scan->score !== null 
                ? $scan->score - $previousScan->score 
                : null;
        }

        // Get filter counts for badges
        $totalCount = Scan::where('user_id', Auth::id())->count();
        $failedCount = Scan::where('user_id', Auth::id())->where('status', 'failed')->count();
        $weekCount = Scan::where('user_id', Auth::id())->where('created_at', '>=', now()->subDays(7))->count();

        return view('scans.index', compact('scans', 'filter', 'totalCount', 'failedCount', 'weekCount'));
    }

    // Cooldown in seconds between scans per domain
    private const COOLDOWN = 10;

    /**
     * Run full scan (DNS + SPF + Blacklist)
     */
    public function run(Request $request, Domain $domain)
    {
        $this->authorize('scan', $domain);
        $this->throttle($domain);

        RunFullScan::dispatch($domain->id, ['dns' => true, 'spf' => true, 'blacklist' => true]);

        return $this->queued($request, 'Full scan started for ' . $domain->domain);
    }

    /**
     * Run DNS-only scan
     */
    public function runDns(Request $request, Domain $domain)
    {
        $this->authorize('scan', $domain);
        $this->throttle($domain);

        RunFullScan::dispatch($domain->id, ['dns' => true, 'spf' => false, 'blacklist' => false]);

        return $this->queued($request, 'DNS scan started for ' . $domain->domain);
    }

    /**
     * Run Blacklist-only scan (plan gated)
     */
    public function runBlacklist(Request $request, Domain $domain)
    {
        $this->authorize('scan', $domain);

        // Plan gate: check if user can run blacklist scans
        if (!auth()->user()->can('blacklist', $domain)) {
            if ($request->expectsJson()) {
                return response()->json([
                    'error' => 'Upgrade required to run blacklist checks.',
                    'upgrade_url' => route('pricing')
                ], Response::HTTP_PAYMENT_REQUIRED);
            }
            
            return back()->with('error', 'Blacklist checks require a paid plan. <a href="' . route('pricing') . '" class="underline">Upgrade now</a>');
        }

        $this->throttle($domain);
        RunFullScan::dispatch($domain->id, ['dns' => false, 'spf' => false, 'blacklist' => true]);

        return $this->queued($request, 'Blacklist scan started for ' . $domain->domain);
    }

    /**
     * Run SPF-only scan
     */
    public function runSpf(Request $request, Domain $domain)
    {
        $this->authorize('scan', $domain);
        $this->throttle($domain);

        RunFullScan::dispatch($domain->id, ['dns' => false, 'spf' => true, 'blacklist' => false]);

        return $this->queued($request, 'SPF scan started for ' . $domain->domain);
    }

    /**
     * Legacy method for backward compatibility
     */
    public function start(Domain $domain)
    {
        return $this->run(request(), $domain);
    }

    /**
     * NEW: Synchronous run that redirects to scan results when finished.
     * Accepts mode: full|dns|spf|blacklist (default: full)
     */
    public function runSync(Request $request, Domain $domain)
    {
        Log::info('ScanController::runSync called', [
            'domain_id' => $domain->id,
            'domain' => $domain->domain,
            'user_id' => auth()->id(),
            'mode' => $request->get('mode'),
            'is_ajax' => $request->expectsJson(),
            'headers' => $request->headers->all()
        ]);

        try {
            $this->authorize('scan', $domain);
        } catch (\Illuminate\Auth\Access\AuthorizationException $e) {
            Log::warning('Unauthorized scan attempt', [
                'user_id' => auth()->id(),
                'domain_id' => $domain->id,
                'domain' => $domain->domain,
                'ip' => $request->ip()
            ]);
            
            if ($request->expectsJson()) {
                return response()->json(['error' => 'You are not authorized to scan this domain.'], 403);
            }
            
            return back()->with('error', 'You are not authorized to scan this domain.');
        }

        // Get scan mode from request
        $mode = $request->string('mode', 'full')->toString();

        // If gating features, check here (e.g., blacklist)
        if ($mode === 'blacklist' && !auth()->user()->can('blacklist', $domain)) {
            if ($request->expectsJson()) {
                return response()->json([
                    'error' => 'Blacklist checks require a paid plan.',
                    'upgrade_url' => route('pricing')
                ], 402); // Payment Required
            }
            
            return back()->with('error', 'Blacklist checks require a paid plan. <a href="' . route('pricing') . '" class="underline">Upgrade now</a>');
        }
        
        try {
            $this->throttle($domain);
        } catch (\Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException $e) {
            if ($request->expectsJson()) {
                return response()->json([
                    'error' => 'Please wait ' . self::COOLDOWN . ' seconds before running another scan on ' . $domain->domain . '.'
                ], 429);
            }
            
            return back()->with('error', 'Please wait ' . self::COOLDOWN . ' seconds before running another scan on ' . $domain->domain . '.');
        }

        // Map mode -> options
        $options = match ($mode) {
            'dns'       => ['dns' => true,  'spf' => false, 'blacklist' => false],
            'spf'       => ['dns' => false, 'spf' => true,  'blacklist' => false],
            'blacklist' => ['dns' => false, 'spf' => false, 'blacklist' => true],
            default     => ['dns' => true,  'spf' => true,  'blacklist' => true], // full
        };
        
        // Also check for full mode blacklist gating
        if ($mode === 'full' && !auth()->user()->can('blacklist', $domain)) {
            // For full scans, disable blacklist if user doesn't have permission
            $options['blacklist'] = false;
        }

        try {
            // Run synchronously using ScanRunner service
            $scanRunner = app(ScanRunner::class);
            $scan = $scanRunner->runSync($domain, $options);

            // Handle JSON requests
            if ($request->expectsJson()) {
                return response()->json([
                    'success' => true,
                    'message' => 'Scan completed successfully!',
                    'scan_id' => $scan->id,
                    'redirect_url' => route('scans.show', $scan)
                ]);
            }

            // Redirect to the reports page (new unified location)
            return redirect()->route('reports.show', $scan)
                ->with('success', 'Scan completed successfully.');
                
        } catch (\Exception $e) {
            Log::error('Synchronous scan failed', [
                'domain' => $domain->domain,
                'mode' => $mode,
                'error' => $e->getMessage()
            ]);
            
            if ($request->expectsJson()) {
                return response()->json([
                    'error' => 'Scan failed: ' . $e->getMessage()
                ], 500);
            }
            
            return back()->with('error', 'Scan failed: ' . $e->getMessage());
        }
    }

    private function queued(Request $request, string $message = 'Scan started')
    {
        if ($request->expectsJson()) {
            return response()->json(['queued' => true, 'message' => $message]);
        }

        return back()->with('status', $message);
    }

    private function throttle(Domain $domain): void
    {
        $key = "scan:cooldown:domain:{$domain->id}";
        if (Cache::has($key)) {
            throw new \Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException(
                self::COOLDOWN,
                "Please wait " . self::COOLDOWN . " seconds before running another scan on {$domain->domain}."
            );
        }
        Cache::put($key, true, self::COOLDOWN);
    }

    /**
     * Clear throttling for a domain (for testing/admin purposes)
     */
    public function clearThrottle(Domain $domain): void
    {
        $key = "scan:cooldown:domain:{$domain->id}";
        Cache::forget($key);
    }


    /**
     * Display the scan results.
     */
    public function show(Scan $scan)
    {
        // Only allow owner
        if ($scan->user_id !== Auth::id()) {
            abort(403, 'Unauthorized access to scan.');
        }

        // Load relationships and refresh domain to get latest expiry dates
        $scan->load(['domain', 'blacklistResults']);
        $domain = $scan->domain->fresh();

        // Determine enabled services based on scan type
        $enabled = [
            'dns' => $scan->hasDnsResults(),
            'spf' => $scan->hasSpfResults(),
            'blacklist' => $scan->hasBlacklistResults(),
            'delivery' => false, // Delivery monitoring is separate
        ];

        // Get scan type flags
        $isBlacklistOnly = $scan->isBlacklistOnly();
        $hasDns = $scan->hasDnsResults();
        $hasSpf = $scan->hasSpfResults();
        $hasBlacklist = $scan->hasBlacklistResults();

        // Get latest and previous snapshots for delta calculation
        $snapshot = $domain->latestScanSnapshot;
        $lastSnapshot = $domain->scanSnapshots()
            ->where('id', '!=', $snapshot?->id)
            ->latest('created_at')
            ->first();

        // Calculate score delta
        $scoreDelta = null;
        if ($snapshot && $lastSnapshot) {
            $scoreDelta = ($snapshot->score ?? 0) - ($lastSnapshot->score ?? 0);
        }

        // Parse result data
        $resultData = $scan->result_json ?? [];
        $records = $resultData['dns']['records'] ?? $resultData ?? [];

        // Extract metrics for KPIs
        $spfInfo = $resultData['spf'] ?? null;
        $spfLookupCount = $spfInfo['lookups'] ?? $domain->spf_lookup_count ?? null;
        $spfMax = 10;
        $spfSuggestion = $spfInfo['flattened'] ?? null;

        // DMARC metrics
        $dmarcData = $records['DMARC'] ?? null;
        $dmarcPolicy = null;
        $dmarcAligned = null;
        if ($dmarcData && $dmarcData['status'] === 'found') {
            $dmarcRecord = $dmarcData['data'];
            if (preg_match('/p=([^;]+)/', $dmarcRecord, $matches)) {
                $dmarcPolicy = $matches[1];
            }
            $dmarcAligned = (str_contains($dmarcRecord, 'aspf=') || str_contains($dmarcRecord, 'adkim='));
        }

        // TLS/MTA-STS status
        $tlsrptOk = isset($records['TLS-RPT']) && $records['TLS-RPT']['status'] === 'found';
        $mtastsOk = isset($records['MTA-STS']) && $records['MTA-STS']['status'] === 'found';

        // Blacklist metrics
        $blacklistData = $resultData['blacklist'] ?? [];
        $blacklistHits = $blacklistData['listed_count'] ?? 0;
        $blacklistTotal = $blacklistData['total_checks'] ?? 0;
        $blacklistRows = $scan->blacklistResults;

        // Domain/SSL expiry
        $domainDays = $domain->getDaysUntilDomainExpiry();
        $sslDays = $domain->getDaysUntilSslExpiry();

        // Get recent incidents (last 7 days, unresolved)
        $incidents = $domain->incidents()
            ->where('created_at', '>=', now()->subDays(7))
            ->whereNull('resolved_at')
            ->orderByDesc('severity')
            ->orderByDesc('created_at')
            ->get();

        // Get recent delivery monitors (if enabled)
        $deliveries = collect();
        if ($enabled['delivery']) {
            $deliveries = $domain->deliveryMonitors()
                ->latest('created_at')
                ->limit(5)
                ->get();
        }

        // Get current schedule cadence
        $activeSchedule = $domain->activeSchedule;
        $cadence = 'off';
        if ($activeSchedule) {
            $frequency = $activeSchedule->frequency;
            $cadence = $frequency === 'daily' ? 'daily' : ($frequency === 'weekly' ? 'weekly' : 'off');
        }

        // Get unified DMARC setup status for the DMARC Visibility block
        $dmarcStatus = app(\App\Services\Dmarc\DmarcStatusService::class)->getStatus($domain);

        return view('scans.show', compact(
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
            'blacklistHits',
            'blacklistTotal',
            'blacklistRows',
            'domainDays',
            'sslDays',
            'incidents',
            'deliveries',
            'cadence',
            'dmarcStatus'
        ));
    }

    /**
     * Get scan status for polling (JSON API).
     */
    public function status(Scan $scan)
    {
        // Only allow owner
        if ($scan->user_id !== Auth::id()) {
            abort(403, 'Unauthorized access to scan.');
        }

        $messages = [
            0   => 'Queued...',
            10  => 'Checking MX records...',
            30  => 'Checking SPF record...',
            50  => 'Checking DMARC policy...',
            70  => 'Checking TLS-RPT...',
            90  => 'Checking MTA-STS...',
            100 => 'Scan complete!',
        ];

        $message = $messages[$scan->progress_pct] ?? 'Scanning...';

        return response()->json([
            'status' => $scan->status,
            'progress' => $scan->progress_pct,
            'score' => $scan->score,
            'message' => $message,
        ]);
    }

    /**
     * Get scan results (JSON API).
     */
    public function result(Scan $scan)
    {
        // Ensure user owns the scan
        if ($scan->user_id !== Auth::id()) {
            abort(403);
        }

        return response()->json([
            'facts' => json_decode($scan->facts_json, true),
            'recommendations' => json_decode($scan->recommendations_json, true) ?? [],
            'score' => $scan->score,
        ]);
    }
}
