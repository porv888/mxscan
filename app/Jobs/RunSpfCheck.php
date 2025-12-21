<?php

namespace App\Jobs;

use App\Models\Domain;
use App\Models\SpfCheck;
use App\Services\Spf\SpfResolver;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

class RunSpfCheck implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public function __construct(
        private int $domainId,
        private bool $forced = false
    ) {}

    /**
     * Execute the job.
     */
    public function handle(SpfResolver $spfResolver): void
    {
        $domain = Domain::find($this->domainId);
        
        if (!$domain) {
            Log::warning("Domain not found for SPF check", ['domain_id' => $this->domainId]);
            return;
        }

        try {
            // Resolve SPF record
            $result = $spfResolver->resolve($domain->domain);
            
            // Get previous check for comparison
            $previousCheck = $domain->latestSpfCheck;
            
            // Determine if the flattened suggestion has changed
            $changed = false;
            if ($previousCheck) {
                $changed = $previousCheck->flattened_suggestion !== $result->flattenedSpf;
            } else {
                // First check is always considered a change
                $changed = true;
            }
            
            // Create new SPF check record
            $spfCheck = SpfCheck::create([
                'domain_id' => $domain->id,
                'looked_up_record' => $result->currentRecord,
                'lookup_count' => $result->lookupsUsed,
                'warnings' => $result->warnings,
                'flattened_suggestion' => $result->flattenedSpf,
                'resolved_ips' => $result->resolvedIps,
                'changed' => $changed,
            ]);

            // Update domain's cached lookup count
            $domain->updateSpfLookupCount($result->lookupsUsed);

            // Log the completion
            Log::info("SPF check completed", [
                'domain' => $domain->domain,
                'lookup_count' => $result->lookupsUsed,
                'warnings_count' => count($result->warnings),
                'changed' => $changed,
                'spf_check_id' => $spfCheck->id
            ]);

            // Broadcast events if needed (for real-time updates)
            // event(new SpfCheckCompleted($spfCheck));

        } catch (\Exception $e) {
            Log::error("SPF check failed", [
                'domain' => $domain->domain,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            
            throw $e; // Re-throw to mark job as failed
        }
    }

    /**
     * Get the tags that should be assigned to the job.
     */
    public function tags(): array
    {
        return ['spf-check', "domain:{$this->domainId}"];
    }
}
