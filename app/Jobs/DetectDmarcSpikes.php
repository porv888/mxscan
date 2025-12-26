<?php

namespace App\Jobs;

use App\Models\Domain;
use App\Models\DmarcAlertSetting;
use App\Models\DmarcEvent;
use App\Notifications\DmarcAlert;
use App\Services\Dmarc\DmarcAnalyticsService;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

class DetectDmarcSpikes implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public function __construct(public Domain $domain)
    {
    }

    /**
     * Execute the job.
     */
    public function handle(DmarcAnalyticsService $analytics): void
    {
        $user = $this->domain->user;
        
        if (!$user || !$user->canUseMonitoring()) {
            return;
        }

        $alertSettings = DmarcAlertSetting::where('domain_id', $this->domain->id)
            ->where('user_id', $user->id)
            ->first();

        if (!$alertSettings) {
            $alertSettings = DmarcAlertSetting::getOrCreate($this->domain->id, $user->id);
        }

        // Detect spikes
        $spikes = $analytics->detectFailSpikes(
            $this->domain,
            $alertSettings->spike_threshold_pct,
            $alertSettings->min_volume_threshold
        );

        foreach ($spikes as $spike) {
            $this->processSpike($spike, $alertSettings, $user);
        }

        // Detect new senders
        $this->detectNewSenders($alertSettings, $user);
    }

    /**
     * Process a detected spike.
     */
    protected function processSpike(array $spike, DmarcAlertSetting $settings, $user): void
    {
        $type = $spike['type'];

        // Check if this alert type is enabled
        $enabledField = match ($type) {
            DmarcEvent::TYPE_ALIGNMENT_DROP => 'alignment_drop_enabled',
            DmarcEvent::TYPE_DKIM_FAIL_SPIKE => 'dkim_fail_spike_enabled',
            DmarcEvent::TYPE_SPF_FAIL_SPIKE => 'spf_fail_spike_enabled',
            default => 'fail_spike_enabled',
        };

        if (!$settings->$enabledField) {
            return;
        }

        // Check throttling
        $throttleField = match ($type) {
            DmarcEvent::TYPE_ALIGNMENT_DROP => 'alignment_drop',
            DmarcEvent::TYPE_DKIM_FAIL_SPIKE => 'dkim_fail_spike',
            DmarcEvent::TYPE_SPF_FAIL_SPIKE => 'spf_fail_spike',
            default => 'fail_spike',
        };

        if (!$settings->canSendAlert($throttleField)) {
            Log::info('DetectDmarcSpikes: Alert throttled', [
                'domain' => $this->domain->domain,
                'type' => $type,
            ]);
            return;
        }

        // Check if event already exists for today
        $existingEvent = DmarcEvent::where('domain_id', $this->domain->id)
            ->where('type', $type)
            ->whereDate('event_date', now()->toDateString())
            ->first();

        if ($existingEvent) {
            return;
        }

        // Get top failing sender
        $analytics = app(DmarcAnalyticsService::class);
        $topFailingSenders = $analytics->getTopFailingSenders($this->domain, 1, 1);
        $topSender = $topFailingSenders->first();

        // Create event
        $event = DmarcEvent::createFailSpikeEvent(
            $this->domain,
            $type,
            $spike['previous_rate'],
            $spike['current_rate'],
            0, // Volume would need to be calculated
            $topSender
        );

        // Send notification
        try {
            $user->notify(new DmarcAlert($this->domain, $event));
            $event->markNotified();
            $settings->recordAlertSent($throttleField);

            Log::info('DetectDmarcSpikes: Alert sent', [
                'domain' => $this->domain->domain,
                'type' => $type,
                'event_id' => $event->id,
            ]);
        } catch (\Throwable $e) {
            Log::error('DetectDmarcSpikes: Failed to send alert', [
                'domain' => $this->domain->domain,
                'type' => $type,
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Detect and alert on new senders.
     */
    protected function detectNewSenders(DmarcAlertSetting $settings, $user): void
    {
        if (!$settings->new_sender_enabled) {
            return;
        }

        if (!$settings->canSendAlert('new_sender')) {
            return;
        }

        // Find new sender events that haven't been notified
        $unnotifiedEvents = DmarcEvent::where('domain_id', $this->domain->id)
            ->where('type', DmarcEvent::TYPE_NEW_SENDER)
            ->where('notified', false)
            ->whereDate('event_date', '>=', now()->subDays(1)->toDateString())
            ->get();

        foreach ($unnotifiedEvents as $event) {
            try {
                $user->notify(new DmarcAlert($this->domain, $event));
                $event->markNotified();
                $settings->recordAlertSent('new_sender');

                Log::info('DetectDmarcSpikes: New sender alert sent', [
                    'domain' => $this->domain->domain,
                    'event_id' => $event->id,
                    'source_ip' => $event->source_ip,
                ]);

                // Only send one new sender alert per throttle period
                break;
            } catch (\Throwable $e) {
                Log::error('DetectDmarcSpikes: Failed to send new sender alert', [
                    'domain' => $this->domain->domain,
                    'event_id' => $event->id,
                    'error' => $e->getMessage(),
                ]);
            }
        }
    }
}
