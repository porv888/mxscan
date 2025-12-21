<?php

namespace App\Jobs;

use App\Models\Incident;
use App\Notifications\IncidentRaised;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

class NotifyIncident implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public function __construct(public Incident $incident)
    {
        //
    }

    /**
     * Execute the job.
     */
    public function handle(): void
    {
        $domain = $this->incident->domain;
        $user = $domain->user;

        if (!$user) {
            Log::warning('No user found for incident notification', [
                'incident_id' => $this->incident->id,
                'domain_id' => $domain->id,
            ]);
            return;
        }

        // Check if user can receive monitoring notifications (plan-gated)
        if (!$user->canUseMonitoring()) {
            Log::info('User cannot receive monitoring notifications due to plan restrictions', [
                'user_id' => $user->id,
                'incident_id' => $this->incident->id,
                'plan' => $user->currentPlanKey(),
            ]);
            return;
        }

        try {
            $user->notify(new IncidentRaised($this->incident));
            
            Log::info('Incident notification sent', [
                'incident_id' => $this->incident->id,
                'user_id' => $user->id,
                'domain' => $domain->domain,
                'severity' => $this->incident->severity,
            ]);
        } catch (\Exception $e) {
            Log::error('Failed to send incident notification', [
                'incident_id' => $this->incident->id,
                'user_id' => $user->id,
                'error' => $e->getMessage(),
            ]);
            
            throw $e;
        }
    }

    /**
     * Handle a job failure.
     */
    public function failed(\Throwable $exception): void
    {
        Log::error('NotifyIncident job failed', [
            'incident_id' => $this->incident->id,
            'error' => $exception->getMessage(),
        ]);
    }
}
