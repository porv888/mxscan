<?php

namespace App\Http\Controllers;

use App\Models\Domain;
use App\Models\Scan;
use App\Services\BlacklistChecker;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;

class BlacklistScanController extends Controller
{
    public function __construct()
    {
        $this->middleware(['auth', 'verified']);
    }

    /**
     * Run a blacklist check for a specific domain.
     */
    public function run(Request $request, Domain $domain)
    {
        // Verify domain ownership
        if ($domain->user_id !== Auth::id()) {
            abort(403, 'Unauthorized access to domain.');
        }

        try {
            // Create a new scan record for blacklist check
            $scan = Scan::create([
                'domain_id' => $domain->id,
                'user_id' => Auth::id(),
                'status' => 'running',
                'progress_pct' => 0,
            ]);

            Log::info("Starting blacklist check", [
                'scan_id' => $scan->id,
                'domain' => $domain->domain,
                'user_id' => Auth::id()
            ]);

            // Run blacklist check
            $blacklistChecker = new BlacklistChecker();
            $scan->update(['progress_pct' => 50]);
            
            $results = $blacklistChecker->checkDomain($scan, $domain->domain);
            $summary = $blacklistChecker->getScanSummary($scan);
            
            // Calculate a simple score based on blacklist results
            $score = $summary['is_clean'] ? 100 : max(100 - ($summary['listed_count'] * 20), 0);
            
            // Update scan with results
            $scan->update([
                'status' => 'finished',
                'progress_pct' => 100,
                'score' => $score,
                'facts_json' => json_encode(['blacklist_summary' => $summary]),
                'finished_at' => now(),
            ]);

            Log::info("Blacklist check completed", [
                'scan_id' => $scan->id,
                'domain' => $domain->domain,
                'is_clean' => $summary['is_clean'],
                'listed_count' => $summary['listed_count']
            ]);

            return redirect()
                ->route('scans.show', $scan)
                ->with('success', 'Blacklist check completed successfully.');

        } catch (\Exception $e) {
            Log::error("Blacklist check failed", [
                'domain' => $domain->domain,
                'error' => $e->getMessage(),
                'user_id' => Auth::id()
            ]);

            if (isset($scan)) {
                $scan->update([
                    'status' => 'failed',
                    'finished_at' => now(),
                ]);
            }

            return redirect()
                ->back()
                ->with('error', 'Blacklist check failed: ' . $e->getMessage());
        }
    }

    /**
     * Get blacklist status for a domain (AJAX endpoint).
     */
    public function status(Domain $domain)
    {
        // Verify domain ownership
        if ($domain->user_id !== Auth::id()) {
            abort(403, 'Unauthorized access to domain.');
        }

        // Get latest scan with blacklist results
        $latestScan = $domain->scans()
            ->whereHas('blacklistResults')
            ->latest()
            ->first();

        if (!$latestScan) {
            return response()->json([
                'status' => 'not-checked',
                'message' => 'No blacklist check performed yet'
            ]);
        }

        $blacklistResults = $latestScan->blacklistResults;
        $listedCount = $blacklistResults->where('status', 'listed')->count();

        return response()->json([
            'status' => $listedCount > 0 ? 'listed' : 'clean',
            'listed_count' => $listedCount,
            'total_checks' => $blacklistResults->count(),
            'last_checked' => $latestScan->created_at->diffForHumans(),
            'scan_id' => $latestScan->id
        ]);
    }
}