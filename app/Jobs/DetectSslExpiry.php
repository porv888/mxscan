<?php

namespace App\Jobs;

use App\Models\Domain;
use App\Services\Expiry\ExpiryCoordinator;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

class DetectSslExpiry implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public int $timeout = 3600; // 1 hour

    /**
     * Execute the job.
     */
    public function handle(ExpiryCoordinator $coordinator): void
    {
        if (!config('expiry.enabled', true)) {
            Log::info('SSL expiry detection disabled');
            return;
        }

        Log::info('DetectSslExpiry job started');

        $updated = 0;
        $failed = 0;
        $total = 0;
        $chunkSize = config('expiry.chunk_size_ssl', 200);

        Domain::query()
            ->where('status', 'active')
            ->orderBy('id')
            ->chunkById($chunkSize, function ($domains) use ($coordinator, &$updated, &$failed, &$total) {
                foreach ($domains as $domain) {
                    $total++;
                    
                    try {
                        $result = $coordinator->detectSslExpiry($domain, false);
                        
                        if ($result && $result->isValid()) {
                            $coordinator->updateDomain($domain, null, $result);
                            $updated++;
                        } else {
                            $failed++;
                        }
                    } catch (\Exception $e) {
                        Log::warning('SSL expiry detection failed', [
                            'domain' => $domain->domain,
                            'error' => $e->getMessage(),
                        ]);
                        $failed++;
                    }
                }
            });

        Log::info('DetectSslExpiry completed', [
            'updated' => $updated,
            'failed' => $failed,
            'total' => $total,
        ]);
    }
}
