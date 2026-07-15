<?php

namespace App\Http\Controllers;

use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistScanOrchestrator;
use App\Domain\EmailSecurity\Checks\Blacklist\Support\BlacklistAnalysisReader;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Models\Domain;
use App\Models\Scan;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;

class BlacklistScanController extends Controller
{
    public function __construct()
    {
        $this->middleware(['auth', 'verified']);
    }

    public function run(Request $request, Domain $domain, BlacklistScanOrchestrator $orchestrator)
    {
        if ($domain->user_id !== Auth::id()) {
            abort(403, 'Unauthorized access to domain.');
        }

        try {
            $scan = Scan::create([
                'domain_id' => $domain->id,
                'user_id' => Auth::id(),
                'type' => 'blacklist',
                'status' => 'running',
                'progress_pct' => 0,
            ]);

            Log::info('Starting blacklist check', [
                'scan_id' => $scan->id,
                'domain' => $domain->domain,
                'user_id' => Auth::id(),
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

            $domain->update([
                'blacklist_status' => $facts['blacklist_status'] ?? 'not-checked',
                'blacklist_count' => $facts['blacklist_count'] ?? 0,
            ]);

            return redirect()
                ->route('scans.show', $scan)
                ->with('success', 'Blacklist check completed successfully.');
        } catch (\Exception $e) {
            Log::error('Blacklist check failed', [
                'domain' => $domain->domain,
                'error' => $e->getMessage(),
                'user_id' => Auth::id(),
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

    public function status(Domain $domain)
    {
        if ($domain->user_id !== Auth::id()) {
            abort(403, 'Unauthorized access to domain.');
        }

        $latestScan = $domain->scans()
            ->whereNotNull('result_json')
            ->where('type', 'blacklist')
            ->latest()
            ->first();

        if ($latestScan === null) {
            $latestScan = $domain->scans()
                ->whereHas('blacklistResults')
                ->latest()
                ->first();
        }

        if (!$latestScan) {
            return response()->json([
                'status' => 'not_checked',
                'message' => 'No blacklist check performed yet',
            ]);
        }

        $blacklist = is_array($latestScan->result_json) ? ($latestScan->result_json['blacklist'] ?? null) : null;
        $facts = BlacklistAnalysisReader::facts(is_array($blacklist) ? $blacklist : null);

        return response()->json([
            'status' => $facts['blacklist_status'] ?? 'not-checked',
            'reputation_status' => $facts['blacklist_reputation_status'] ?? null,
            'message' => BlacklistAnalysisReader::summary(is_array($blacklist) ? $blacklist : null) ?? 'Blacklist status available',
            'data' => [
                'scan_id' => $latestScan->id,
                'usable_results' => $facts['blacklist_usable_results'] ?? 0,
                'listed_count' => $facts['blacklist_count'] ?? 0,
                'was_checked' => $facts['blacklist_was_checked'] ?? false,
                'last_checked' => $latestScan->created_at->diffForHumans(),
            ],
        ]);
    }
}
