<?php

namespace App\Console\Commands;

use App\Models\Alert;
use App\Models\DeliveryCheck;
use App\Models\DeliveryMonitor;
use App\Notifications\DeliveryAlert;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

class DispatchAlerts extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'alerts:dispatch {--lookback=1 : Hours to look back for checks}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Scan recent delivery checks and dispatch alerts for DMARC failures, RBL listings, and high TTI';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $lookbackHours = (int) $this->option('lookback');
        $since = now()->subHours($lookbackHours);
        
        $this->info("Scanning delivery checks from the last {$lookbackHours} hour(s)...");
        
        $alertsCreated = 0;
        
        // Get all active monitors
        $monitors = DeliveryMonitor::where('status', 'active')->with('domain.user')->get();
        
        foreach ($monitors as $monitor) {
            if (!$monitor->domain || !$monitor->domain->user) {
                continue;
            }
            
            // Get recent checks for this monitor
            $checks = DeliveryCheck::where('delivery_monitor_id', $monitor->id)
                ->where('created_at', '>=', $since)
                ->get();
            
            if ($checks->isEmpty()) {
                continue;
            }
            
            // Check for DMARC failures
            $dmarcFailures = $checks->where('dmarc_pass', false);
            if ($dmarcFailures->count() >= 3) {
                $alert = $this->createAlert($monitor->domain->id, 'dmarc_fail', [
                    'monitor_id' => $monitor->id,
                    'monitor_label' => $monitor->label,
                    'failure_count' => $dmarcFailures->count(),
                    'total_checks' => $checks->count(),
                    'timeframe' => "{$lookbackHours}h",
                ]);
                
                if ($alert) {
                    $monitor->domain->user->notify(new DeliveryAlert($alert));
                    $alertsCreated++;
                    $this->line("  → DMARC alert for {$monitor->domain->domain}");
                }
            }
            
            // Check for high TTI P95
            $ttiValues = $checks->whereNotNull('tti_ms')->pluck('tti_ms')->sort()->values();
            if ($ttiValues->count() >= 5) {
                $p95Index = (int) ceil($ttiValues->count() * 0.95) - 1;
                $p95Tti = $ttiValues[$p95Index];
                $p95Seconds = (int) round($p95Tti / 1000);
                
                // Alert if P95 > 30 minutes
                if ($p95Seconds > 1800) {
                    $alert = $this->createAlert($monitor->domain->id, 'high_tti_p95', [
                        'monitor_id' => $monitor->id,
                        'monitor_label' => $monitor->label,
                        'p95_seconds' => $p95Seconds,
                        'p95_formatted' => $this->formatSeconds($p95Seconds),
                        'sample_size' => $ttiValues->count(),
                        'timeframe' => "{$lookbackHours}h",
                    ]);
                    
                    if ($alert) {
                        $monitor->domain->user->notify(new DeliveryAlert($alert));
                        $alertsCreated++;
                        $this->line("  → High TTI alert for {$monitor->domain->domain}");
                    }
                }
            }
        }
        
        $this->info("✓ Created {$alertsCreated} alert(s)");
        
        Log::info('alerts:dispatch completed', [
            'lookback_hours' => $lookbackHours,
            'alerts_created' => $alertsCreated,
        ]);
        
        return 0;
    }
    
    /**
     * Create alert with deduplication (24h window)
     */
    protected function createAlert(int $domainId, string $type, array $meta): ?Alert
    {
        // Check if similar alert exists in last 24 hours
        $existing = Alert::where('domain_id', $domainId)
            ->where('type', $type)
            ->where('created_at', '>=', now()->subDay())
            ->first();
        
        if ($existing) {
            return null; // Skip duplicate
        }
        
        return Alert::create([
            'domain_id' => $domainId,
            'type' => $type,
            'meta' => $meta,
        ]);
    }
    
    /**
     * Format seconds to human-readable string
     */
    protected function formatSeconds(int $seconds): string
    {
        if ($seconds < 60) {
            return "{$seconds}s";
        }
        
        $minutes = floor($seconds / 60);
        $remainingSeconds = $seconds % 60;
        
        return "{$minutes}m {$remainingSeconds}s";
    }
}
