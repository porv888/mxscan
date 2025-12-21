<?php

namespace App\Http\Controllers;

use App\Models\Schedule;
use App\Models\Domain;
use App\Models\Scan;
use App\Services\ScanRunner;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Validation\Rule;

class ScheduleController extends Controller
{
    public function __construct()
    {
        $this->middleware(['auth', 'verified']);
    }

    /**
     * Display a listing of the user's schedules.
     */
    public function index()
    {
        $schedules = Schedule::with(['domain', 'latestScan'])
            ->where('user_id', Auth::id())
            ->orderBy('next_run_at', 'asc')
            ->get();

        $domains = Domain::where('user_id', Auth::id())
            ->orderBy('domain')
            ->get();

        return view('schedules.index', compact('schedules', 'domains'));
    }

    /**
     * Show the form for creating a new schedule.
     */
    public function create()
    {
        $domains = Domain::where('user_id', Auth::id())
            ->orderBy('domain')
            ->get();

        return view('schedules.create', compact('domains'));
    }

    /**
     * Store a newly created schedule in storage.
     */
    public function store(Request $request)
    {
        $validated = $request->validate([
            'domain_id' => [
                'required',
                'exists:domains,id',
                Rule::exists('domains', 'id')->where('user_id', Auth::id())
            ],
            'scan_type' => 'required|in:dns_security,blacklist,both',
            'frequency' => 'required|in:daily,weekly,monthly,custom',
            'cron_expression' => 'nullable|string|max:100',
        ]);

        $schedule = new Schedule($validated);
        $schedule->user_id = Auth::id();
        $schedule->next_run_at = $schedule->calculateNextRun();
        $schedule->save();

        return redirect()->route('schedules.index')
            ->with('success', 'Schedule created successfully!');
    }

    /**
     * Show the form for editing the specified schedule.
     */
    public function edit(Schedule $schedule)
    {
        // Ensure user can only edit their own schedules
        if ($schedule->user_id !== Auth::id()) {
            abort(403, 'Unauthorized access to schedule.');
        }

        $domains = Domain::where('user_id', Auth::id())
            ->orderBy('domain')
            ->get();

        return view('schedules.edit', compact('schedule', 'domains'));
    }

    /**
     * Update the specified schedule in storage.
     */
    public function update(Request $request, Schedule $schedule)
    {
        // Ensure user can only update their own schedules
        if ($schedule->user_id !== Auth::id()) {
            abort(403, 'Unauthorized access to schedule.');
        }

        $validated = $request->validate([
            'domain_id' => [
                'required',
                'exists:domains,id',
                Rule::exists('domains', 'id')->where('user_id', Auth::id())
            ],
            'scan_type' => 'required|in:dns_security,blacklist,both',
            'frequency' => 'required|in:daily,weekly,monthly,custom',
            'cron_expression' => 'nullable|string|max:100',
        ]);

        $schedule->update($validated);
        
        // Recalculate next run if frequency changed
        if ($schedule->wasChanged(['frequency', 'cron_expression'])) {
            $schedule->update(['next_run_at' => $schedule->calculateNextRun()]);
        }
        
        // Invalidate cached schedules
        \Illuminate\Support\Facades\Cache::forget("schedules:user:{$schedule->user_id}");

        return redirect()->route('schedules.index')
            ->with('success', 'Schedule updated successfully!');
    }

    /**
     * Pause the specified schedule.
     */
    public function pause(Schedule $schedule)
    {
        // Ensure user can only pause their own schedules
        if ($schedule->user_id !== Auth::id()) {
            abort(403, 'Unauthorized access to schedule.');
        }

        $schedule->pause();
        
        // Invalidate cached schedules
        \Illuminate\Support\Facades\Cache::forget("schedules:user:{$schedule->user_id}");

        return redirect()->route('schedules.index')
            ->with('success', 'Schedule paused successfully!');
    }

    /**
     * Resume the specified schedule.
     */
    public function resume(Schedule $schedule)
    {
        // Ensure user can only resume their own schedules
        if ($schedule->user_id !== Auth::id()) {
            abort(403, 'Unauthorized access to schedule.');
        }

        $schedule->resume();
        
        // Invalidate cached schedules
        \Illuminate\Support\Facades\Cache::forget("schedules:user:{$schedule->user_id}");

        return redirect()->route('schedules.index')
            ->with('success', 'Schedule resumed successfully!');
    }

    /**
     * Remove the specified schedule from storage.
     */
    public function destroy(Schedule $schedule)
    {
        // Ensure user can only delete their own schedules
        if ($schedule->user_id !== Auth::id()) {
            abort(403, 'Unauthorized access to schedule.');
        }

        $domainName = $schedule->domain->domain;
        $schedule->delete();

        return redirect()->route('schedules.index')
            ->with('success', "Schedule for '{$domainName}' has been deleted successfully.");
    }

    /**
     * Run a schedule immediately.
     */
    public function runNow(Schedule $schedule, ScanRunner $scanRunner)
    {
        // Ensure user can only run their own schedules
        if ($schedule->user_id !== Auth::id()) {
            abort(403, 'Unauthorized access to schedule.');
        }

        try {
            $domain = $schedule->domain;
            
            // Determine scan options based on schedule scan_type
            $options = match ($schedule->scan_type) {
                'dns_security' => ['dns' => true, 'spf' => true, 'blacklist' => false],
                'blacklist' => ['dns' => false, 'spf' => false, 'blacklist' => true],
                'both' => ['dns' => true, 'spf' => true, 'blacklist' => true],
                default => ['dns' => true, 'spf' => true, 'blacklist' => false],
            };

            // Check plan permissions for blacklist scans
            if ($options['blacklist'] && !$domain->user->canUseBlacklist()) {
                $options['blacklist'] = false;
            }

            Log::info('Running scheduled scan immediately', [
                'schedule_id' => $schedule->id,
                'domain' => $domain->domain,
                'scan_type' => $schedule->scan_type,
                'options' => $options
            ]);

            // Run scan synchronously
            $scan = $scanRunner->runSync($domain, $options);
            
            // Link scan to schedule
            $scan->update(['schedule_id' => $schedule->id]);

            // Update schedule timestamps
            $schedule->forceFill([
                'last_run_at' => now(),
                'next_run_at' => $schedule->computeNextRun(now()),
                'last_run_status' => $scan->status === 'finished' ? 'ok' : 'failed',
            ])->save();
            
            // Invalidate cached schedules
            \Illuminate\Support\Facades\Cache::forget("schedules:user:{$schedule->user_id}");

            Log::info('Scheduled scan completed', [
                'schedule_id' => $schedule->id,
                'scan_id' => $scan->id,
                'status' => $scan->status
            ]);

            // Redirect to the scan report
            return redirect()
                ->route('scans.show', $scan)
                ->with('success', 'Scan started. This report will update as checks complete.');

        } catch (\Exception $e) {
            Log::error('Failed to run scheduled scan', [
                'schedule_id' => $schedule->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);

            // Update schedule with failed status
            $schedule->forceFill([
                'last_run_at' => now(),
                'next_run_at' => $schedule->computeNextRun(now()),
                'last_run_status' => 'failed',
            ])->save();
            
            // Invalidate cached schedules
            \Illuminate\Support\Facades\Cache::forget("schedules:user:{$schedule->user_id}");

            return redirect()
                ->route('schedules.index')
                ->with('error', 'Failed to run scan: ' . $e->getMessage());
        }
    }
}