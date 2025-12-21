<?php

namespace App\Console\Commands;

use App\Models\DeliveryCheck;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

class CleanupRawBodies extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'delivery:cleanup-raw-bodies {--days=30 : Days to retain raw bodies}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Trim raw_body and raw_headers from delivery checks older than specified days';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $retentionDays = (int) $this->option('days');
        $cutoffDate = now()->subDays($retentionDays);
        
        $this->info("Cleaning up raw bodies older than {$retentionDays} days (before {$cutoffDate->toDateString()})...");
        
        // Update checks older than retention period
        $updated = DeliveryCheck::where('created_at', '<', $cutoffDate)
            ->whereNotNull('raw_headers')
            ->update([
                'raw_headers' => null,
            ]);
        
        $this->info("✓ Cleaned up {$updated} delivery check(s)");
        
        Log::info('delivery:cleanup-raw-bodies completed', [
            'retention_days' => $retentionDays,
            'cutoff_date' => $cutoffDate->toDateString(),
            'checks_cleaned' => $updated,
        ]);
        
        return 0;
    }
}
