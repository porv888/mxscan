<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Concerns\PreparesScanReport;
use Illuminate\Http\Request;
use App\Models\Domain;
use App\Models\Scan;
use App\Jobs\RunFullScan;
use App\Services\ScanRunner;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;
use Symfony\Component\HttpFoundation\Response;

class ScanController extends Controller
{
    use PreparesScanReport;
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
        $this->authorize('partialScan', $domain);
        $this->throttle($domain);

        RunFullScan::dispatch($domain->id, ['dns' => true, 'spf' => false, 'blacklist' => false]);

        return $this->queued($request, 'DNS scan started for ' . $domain->domain);
    }

    /**
     * Run DKIM-only scan
     */
    public function runDkim(Request $request, Domain $domain)
    {
        $this->authorize('partialScan', $domain);
        $this->throttle($domain);

        RunFullScan::dispatch($domain->id, [
            'dns' => false,
            'spf' => false,
            'blacklist' => false,
            'dkim' => true,
            'dkim_selector' => $request->input('dkim_selector'),
            'dkim_signature' => $request->input('dkim_signature'),
        ]);

        return $this->queued($request, 'DKIM scan started for ' . $domain->domain);
    }

    /**
     * Run Blacklist-only scan (plan gated)
     */
    public function runBlacklist(Request $request, Domain $domain)
    {
        $this->authorize('partialScan', $domain);
        $this->throttle($domain);
        RunFullScan::dispatch($domain->id, ['dns' => false, 'spf' => false, 'blacklist' => true]);

        return $this->queued($request, 'Blacklist scan started for ' . $domain->domain);
    }

    /**
     * Run SPF-only scan
     */
    public function runSpf(Request $request, Domain $domain)
    {
        $this->authorize('partialScan', $domain);
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
     * Confirm and start a synchronous scan (GET landing page with fresh CSRF token).
     */
    public function showScanNow(Request $request, Domain $domain)
    {
        $mode = $request->string('mode', 'full')->toString();
        if (!in_array($mode, ['full', 'dns', 'spf', 'blacklist'], true)) {
            $mode = 'full';
        }

        if (in_array($mode, ['dns', 'spf', 'blacklist'], true)) {
            $this->authorize('partialScan', $domain);
        } else {
            $this->authorize('scan', $domain);
        }

        return view('scans.scan-now', [
            'domain' => $domain,
            'mode' => $mode,
        ]);
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

        $mode = $request->string('mode', 'full')->toString();

        try {
            if (in_array($mode, ['dns', 'spf', 'blacklist'], true)) {
                $this->authorize('partialScan', $domain);
            } else {
                $this->authorize('scan', $domain);
            }
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

        $options = match ($mode) {
            'dns'       => ['dns' => true,  'spf' => false, 'blacklist' => false],
            'spf'       => ['dns' => false, 'spf' => true,  'blacklist' => false],
            'blacklist' => ['dns' => false, 'spf' => false, 'blacklist' => true],
            default     => ['dns' => true,  'spf' => true,  'blacklist' => true],
        };

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

        try {
            $scanRunner = app(ScanRunner::class);
            $scan = $scanRunner->runSync($domain, $options);

            if ($request->expectsJson()) {
                return response()->json([
                    'success' => true,
                    'message' => 'Scan completed successfully!',
                    'scan_id' => $scan->id,
                    'redirect_url' => route('scans.show', $scan)
                ]);
            }

            return redirect()->route('reports.show', $scan)
                ->with('toast', ['type' => 'success', 'text' => 'Scan completed successfully.']);
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
        if ($scan->user_id !== Auth::id()) {
            abort(403, 'Unauthorized access to scan.');
        }

        return view('scans.show', $this->prepareScanReportViewData($scan));
    }

    /**
     * Get scan status for polling (JSON API).
     */
    public function status(Scan $scan)
    {
        if ($scan->user_id !== Auth::id()) {
            abort(403, 'Unauthorized access to scan.');
        }

        $progress = (int) ($scan->progress_pct ?? 0);
        $status = $scan->status;

        $stage = match (true) {
            $status === 'queued' => 'queued',
            $status === 'failed' => 'failed',
            $status === 'finished' => 'completed',
            $status === 'running' && $progress >= 90 => 'preparing_report',
            $status === 'running' => 'scanning',
            default => 'scanning',
        };

        $messages = [
            'queued' => 'Queued — waiting to start',
            'scanning' => 'Scanning DNS, SPF, and blacklist checks',
            'preparing_report' => 'Preparing your report',
            'completed' => 'Scan complete',
            'failed' => 'Scan failed',
        ];

        $userError = null;
        if ($status === 'failed') {
            $result = $scan->result_json;
            if (is_string($result)) {
                $result = json_decode($result, true) ?? [];
            }
            $userError = is_array($result) ? ($result['user_error'] ?? 'The scan could not be completed. Please try again.') : 'The scan could not be completed. Please try again.';
        }

        return response()->json([
            'status' => $status,
            'stage' => $stage,
            'progress' => $progress,
            'score' => $scan->score,
            'message' => $userError ?? ($messages[$stage] ?? 'Scanning...'),
            'domain' => $scan->domain?->domain,
            'report_url' => route('reports.show', $scan),
            'retry_url' => $scan->domain ? route('domains.scan.now', $scan->domain) : null,
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
