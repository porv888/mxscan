<?php

namespace App\Http\Controllers;

use App\Models\Schedule;
use App\Models\Domain;
use App\Jobs\RunFullScan;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\Rule;

class AutomationController extends Controller
{
    public function __construct()
    {
        $this->middleware(['auth', 'verified']);
    }

    /**
     * Display a listing of automations (schedules).
     */
    public function index()
    {
        $schedules = Schedule::with('domain')
            ->where('user_id', Auth::id())
            ->orderBy('next_run_at', 'asc')
            ->get();

        return view('automations.index', compact('schedules'));
    }

    /**
     * Show the form for creating a new automation.
     */
    public function create()
    {
        $domains = Domain::where('user_id', Auth::id())
            ->orderBy('domain')
            ->get();

        return view('automations.create', compact('domains'));
    }

    /**
     * Store a newly created automation in storage.
     */
    public function store(Request $request)
    {
        $validated = $request->validate([
            'domain_id' => [
                'required',
                'exists:domains,id',
                Rule::exists('domains', 'id')->where('user_id', Auth::id())
            ],
            'scan_type' => 'required|in:dns,spf,blacklist,complete',
            'frequency' => 'required|in:daily,weekly,monthly,custom',
            'cron_expression' => 'nullable|string|max:100',
        ]);

        // Map scan_type to legacy format for Schedule model
        $scanTypeMap = [
            'dns' => 'dns_security',
            'spf' => 'dns_security',
            'blacklist' => 'blacklist',
            'complete' => 'both',
        ];

        $schedule = new Schedule([
            'domain_id' => $validated['domain_id'],
            'scan_type' => $scanTypeMap[$validated['scan_type']],
            'frequency' => $validated['frequency'],
            'cron_expression' => $validated['cron_expression'] ?? null,
        ]);
        
        $schedule->user_id = Auth::id();
        $schedule->next_run_at = $schedule->computeNextRun(now());
        $schedule->save();

        return redirect()->route('automations.index')
            ->with('success', 'Automation saved.');
    }

    /**
     * Show the form for editing the specified automation.
     */
    public function edit(Schedule $schedule)
    {
        // Ensure user can only edit their own schedules
        if ($schedule->user_id !== Auth::id()) {
            abort(403, 'Unauthorized access to automation.');
        }

        $domains = Domain::where('user_id', Auth::id())
            ->orderBy('domain')
            ->get();

        return view('automations.edit', compact('schedule', 'domains'));
    }

    /**
     * Update the specified automation in storage.
     */
    public function update(Request $request, Schedule $schedule)
    {
        // Ensure user can only update their own schedules
        if ($schedule->user_id !== Auth::id()) {
            abort(403, 'Unauthorized access to automation.');
        }

        $validated = $request->validate([
            'domain_id' => [
                'required',
                'exists:domains,id',
                Rule::exists('domains', 'id')->where('user_id', Auth::id())
            ],
            'scan_type' => 'required|in:dns,spf,blacklist,complete',
            'frequency' => 'required|in:daily,weekly,monthly,custom',
            'cron_expression' => 'nullable|string|max:100',
        ]);

        // Map scan_type to legacy format
        $scanTypeMap = [
            'dns' => 'dns_security',
            'spf' => 'dns_security',
            'blacklist' => 'blacklist',
            'complete' => 'both',
        ];

        $schedule->update([
            'domain_id' => $validated['domain_id'],
            'scan_type' => $scanTypeMap[$validated['scan_type']],
            'frequency' => $validated['frequency'],
            'cron_expression' => $validated['cron_expression'] ?? null,
        ]);
        
        // Recalculate next run if frequency changed
        if ($schedule->wasChanged(['frequency', 'cron_expression'])) {
            $schedule->update(['next_run_at' => $schedule->calculateNextRun()]);
        }

        return redirect()->route('automations.index')
            ->with('success', 'Automation saved.');
    }

    /**
     * Pause the specified automation.
     */
    public function pause(Schedule $schedule)
    {
        // Ensure user can only pause their own schedules
        if ($schedule->user_id !== Auth::id()) {
            abort(403, 'Unauthorized access to automation.');
        }

        $schedule->pause();

        return redirect()->route('automations.index')
            ->with('success', 'Automation paused.');
    }

    /**
     * Resume the specified automation.
     */
    public function resume(Schedule $schedule)
    {
        // Ensure user can only resume their own schedules
        if ($schedule->user_id !== Auth::id()) {
            abort(403, 'Unauthorized access to automation.');
        }

        $schedule->resume();

        return redirect()->route('automations.index')
            ->with('success', 'Automation resumed.');
    }

    /**
     * Run an automation immediately.
     */
    public function runNow(Schedule $schedule)
    {
        // Ensure user can only run their own schedules
        if ($schedule->user_id !== Auth::id()) {
            abort(403, 'Unauthorized access to automation.');
        }

        // Prevent double-run
        if ($schedule->is_running) {
            return back()->with('info', 'Automation is already running.');
        }

        // Update schedule immediately to reflect the manual trigger
        $schedule->update([
            'is_running' => true,
            'last_run_at' => now(),
            'next_run_at' => $schedule->computeNextRun(now()),
            'last_run_status' => null,
        ]);

        // Map schedule scan_type to scan options
        $options = match ($schedule->scan_type) {
            'dns_security' => ['dns' => true, 'spf' => true, 'blacklist' => false],
            'blacklist' => ['dns' => false, 'spf' => false, 'blacklist' => true],
            'both' => ['dns' => true, 'spf' => true, 'blacklist' => true],
            default => ['dns' => true, 'spf' => true, 'blacklist' => false],
        };

        // Run synchronously for immediate feedback
        try {
            $scanRunner = app(\App\Services\ScanRunner::class);
            $scan = $scanRunner->runSync($schedule->domain, $options);
            
            // Determine status based on scan results
            $status = 'ok';
            if ($scan && isset($scan->score)) {
                if ($scan->score < 50) {
                    $status = 'failed';
                } elseif ($scan->score < 80) {
                    $status = 'warning';
                }
            }
            
            $schedule->update([
                'last_run_status' => $status,
                'is_running' => false,
            ]);
            
            return redirect()->route('automations.index')
                ->with('success', 'Automation executed successfully. Check Reports for results.');
        } catch (\Exception $e) {
            \Log::error("Automation run failed for schedule {$schedule->id}: " . $e->getMessage());
            
            $schedule->update([
                'last_run_status' => 'failed',
                'is_running' => false,
            ]);
            
            return redirect()->route('automations.index')
                ->with('error', 'Automation execution failed. Please try again.');
        }
    }

    /**
     * Remove the specified automation from storage.
     */
    public function destroy(Schedule $schedule)
    {
        // Ensure user can only delete their own schedules
        if ($schedule->user_id !== Auth::id()) {
            abort(403, 'Unauthorized access to automation.');
        }

        $domainName = $schedule->domain->domain;
        $schedule->delete();

        return redirect()->route('automations.index')
            ->with('success', "Automation for '{$domainName}' deleted.");
    }
}
