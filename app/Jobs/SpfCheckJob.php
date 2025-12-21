<?php

namespace App\Jobs;

use App\Mail\SpfAlertMail;
use App\Models\Domain;
use App\Models\SpfCheck;
use App\Services\Spf\SpfResolver;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;

class SpfCheckJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public function __construct(
        public readonly int $domainId,
        public readonly string $domain
    ) {}

    /**
     * Execute the job.
     */
    public function handle(SpfResolver $spfResolver): void
    {
        try {
            Log::info("Starting SPF check for domain: {$this->domain}");
            
            // Resolve SPF record
            $result = $spfResolver->resolve($this->domain);
            
            // Get previous check for comparison
            $previousCheck = SpfCheck::where('domain_id', $this->domainId)
                ->orderBy('created_at', 'desc')
                ->first();
            
            // Determine if record changed
            $recordChanged = $previousCheck && $previousCheck->looked_up_record !== $result->currentRecord;
            
            // Create new SPF check record
            $spfCheck = SpfCheck::create([
                'domain_id' => $this->domainId,
                'looked_up_record' => $result->currentRecord,
                'lookup_count' => $result->lookupsUsed,
                'flattened_suggestion' => $result->flattenedSpf,
                'warnings' => $result->warnings,
                'resolved_ips' => $result->resolvedIps,
                'changed' => $recordChanged,
            ]);
            
            // Check if we need to send alerts
            $shouldAlert = false;
            $alertReasons = [];
            
            // Alert if lookup count is risky (≥9)
            if ($result->lookupsUsed >= 9) {
                $shouldAlert = true;
                $alertReasons[] = "High DNS lookup count: {$result->lookupsUsed}/10";
            }
            
            // Alert if SPF record changed
            if ($recordChanged) {
                $shouldAlert = true;
                $alertReasons[] = "SPF record changed";
            }
            
            // Send alert email if needed
            if ($shouldAlert) {
                $domain = Domain::find($this->domainId);
                if ($domain && $domain->user) {
                    Log::info("Sending SPF alert for {$this->domain}: " . implode(', ', $alertReasons));
                    
                    Mail::to($domain->user->email)->send(
                        new SpfAlertMail($domain, $spfCheck, $previousCheck, $alertReasons)
                    );
                }
            }
            
            Log::info("SPF check completed for domain: {$this->domain}");
            
        } catch (\Exception $e) {
            Log::error("SPF check failed for domain {$this->domain}: " . $e->getMessage());
            
            // Still create a record with error information
            SpfCheck::create([
                'domain_id' => $this->domainId,
                'looked_up_record' => null,
                'lookup_count' => 0,
                'flattened_suggestion' => null,
                'warnings' => ['Error: ' . $e->getMessage()],
                'resolved_ips' => [],
                'changed' => false,
            ]);
            
            throw $e;
        }
    }
}
