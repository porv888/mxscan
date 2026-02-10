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
            // Skip change detection entirely if DNS lookup failed (TIMEOUT warning)
            // This prevents false positives when DNS lookups fail/timeout
            $recordChanged = false;
            $dnsLookupFailed = in_array('TIMEOUT', $result->warnings);
            
            if ($previousCheck && !$dnsLookupFailed) {
                if ($result->currentRecord !== null && $previousCheck->looked_up_record !== null) {
                    // Both records exist - compare them
                    $recordChanged = $previousCheck->looked_up_record !== $result->currentRecord;
                } elseif ($result->currentRecord !== null && $previousCheck->looked_up_record === null) {
                    // New SPF record added (previous was null, now has record)
                    $recordChanged = true;
                } elseif ($result->currentRecord === null && $previousCheck->looked_up_record !== null) {
                    // Potential SPF removal - wait for second consecutive null to confirm
                    $recordChanged = false;
                } elseif ($result->currentRecord === null && $previousCheck->looked_up_record === null) {
                    // Both current and previous are null
                    // Check if there was a valid record before these two nulls
                    $lastValidCheck = SpfCheck::where('domain_id', $this->domainId)
                        ->whereNotNull('looked_up_record')
                        ->where('looked_up_record', '!=', '')
                        ->orderBy('created_at', 'desc')
                        ->first();
                    
                    if ($lastValidCheck && !$previousCheck->changed) {
                        // There was a valid record before, and previous check didn't already alert
                        // This is the second consecutive null - confirm as genuine removal
                        $recordChanged = true;
                    }
                }
            }
            
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
