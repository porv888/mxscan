<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Models\Schedule;
use App\Jobs\RunScan;
use App\Services\BlacklistChecker;
use App\Services\ScanRunner;
use App\Models\Scan;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Arr;

class RunScheduledScans extends Command
{
    /**
     * The name and signature of the console command.
     */
    protected $signature = 'scans:scheduled {--dry-run : Show what would be executed without running}';

    /**
     * The console command description.
     */
    protected $description = 'Run scheduled domain scans that are due';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $dryRun = $this->option('dry-run');
        
        $this->info('Checking for scheduled scans...');
        
        // Get all due schedules
        $dueSchedules = Schedule::with(['domain', 'user'])
            ->where('status', 'active')
            ->where('next_run_at', '<=', now())
            ->get();

        if ($dueSchedules->isEmpty()) {
            $this->info('No scheduled scans are due.');
            return 0;
        }

        $this->info("Found {$dueSchedules->count()} scheduled scan(s) due for execution:");

        foreach ($dueSchedules as $schedule) {
            $domain = $schedule->domain;
            $user = $schedule->user;
            
            if (!$domain || $domain->status !== 'active') {
                $this->warn("Skipping inactive domain: {$domain?->domain}");
                $this->bumpNextRun($schedule);
                continue;
            }
            
            // NEW: Read services from JSON settings if present
            $settings = is_array($schedule->settings) ? $schedule->settings : [];
            $services = collect(Arr::get($settings, 'services', []))
                ->filter(fn($k) => in_array($k, ['dns', 'spf', 'blacklist', 'delivery'], true))
                ->values();
            
            // Decide what scan options to use
            $scanOptions = $this->determineScanOptions($schedule, $services);
            
            $this->line("- {$domain->domain} (" . implode('+', array_keys(array_filter($scanOptions))) . ", {$schedule->frequency_display}) for {$user->name}");
            
            if ($dryRun) {
                continue;
            }

            try {
                // Use ScanRunner service for synchronous execution
                $scanRunner = app(ScanRunner::class);
                $scan = $scanRunner->runSync($domain, $scanOptions);
                
                // Mark schedule as completed
                $this->bumpNextRun($schedule);
                
                $this->info("✓ Executed scan for {$domain->domain} (scan #{$scan->id})");
                
                Log::info('Scheduled scan executed', [
                    'schedule_id' => $schedule->id,
                    'scan_id' => $scan->id,
                    'domain' => $domain->domain,
                    'options' => $scanOptions,
                    'services' => $services->toArray()
                ]);

            } catch (\Exception $e) {
                $this->error("✗ Failed to execute scan for {$domain->domain}: " . $e->getMessage());
                
                Log::error('Scheduled scan failed', [
                    'schedule_id' => $schedule->id,
                    'domain' => $domain->domain,
                    'error' => $e->getMessage(),
                    'trace' => $e->getTraceAsString()
                ]);
                
                // Still bump next run to avoid getting stuck
                $this->bumpNextRun($schedule);
            }
        }

        if ($dryRun) {
            $this->info('Dry run completed. Use without --dry-run to execute scans.');
        } else {
            $this->info('Scheduled scans completed.');
        }

        return 0;
    }

    /**
     * Determine scan options from schedule settings.
     * 
     * @param Schedule $schedule
     * @param \Illuminate\Support\Collection $services
     * @return array{dns: bool, spf: bool, blacklist: bool}
     */
    private function determineScanOptions(Schedule $schedule, $services): array
    {
        // If no services key present → legacy behavior
        if ($services->isEmpty()) {
            return match ($schedule->scan_type) {
                'dns_security' => ['dns' => true, 'spf' => false, 'blacklist' => false],
                'blacklist' => ['dns' => false, 'spf' => false, 'blacklist' => true],
                'both' => ['dns' => true, 'spf' => false, 'blacklist' => true],
                default => ['dns' => true, 'spf' => false, 'blacklist' => true],
            };
        }
        
        // NEW PATH – honor user selections
        // Note: delivery is ignored (IMAP collector runs separately)
        $hasDns = $services->contains('dns');
        $hasSpf = $services->contains('spf');
        $hasBlacklist = $services->contains('blacklist');
        
        // Build options array
        // If user selected SPF without DNS, we still run SPF scan
        // (many installs compute SPF inside DNS, but explicit SPF selection should be honored)
        return [
            'dns' => $hasDns,
            'spf' => $hasSpf,
            'blacklist' => $hasBlacklist,
        ];
    }
    
    /**
     * Bump next_run_at to the next scheduled time.
     * Respects frequency and optional settings.run_at ("HH:MM:SS").
     */
    protected function bumpNextRun(Schedule $schedule): void
    {
        $runAt = Arr::get($schedule->settings, 'run_at');
        $next = match ($schedule->frequency) {
            'daily' => now()->startOfDay()->addDay(),
            'weekly' => now()->startOfDay()->addWeek(),
            'monthly' => now()->startOfDay()->addMonth(),
            default => now()->addDay(), // safe default
        };
        
        // Apply specific time if configured
        if ($runAt && preg_match('/^\d{2}:\d{2}:\d{2}$/', $runAt)) {
            $next = $next->setTime(
                (int)substr($runAt, 0, 2),
                (int)substr($runAt, 3, 2),
                (int)substr($runAt, 6, 2)
            );
        }
        
        $schedule->forceFill([
            'last_run_at' => now(),
            'next_run_at' => $next
        ])->save();
    }
}