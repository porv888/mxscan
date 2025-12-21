<?php

namespace App\Services\Monitoring;

use App\Models\DeliveryCheck;
use App\Models\Incident;
use Illuminate\Support\Facades\Log;

class IncidentWriter
{
    /**
     * Analyze delivery check and create incidents as needed
     */
    public function processCheck(DeliveryCheck $check): void
    {
        $monitor = $check->monitor;
        $domain = $monitor->domain;
        
        if (!$domain) {
            return;
        }

        $authMeta = $check->auth_meta ?? [];
        $occurredAt = $check->received_at ?? $check->created_at;

        // DMARC fail => incident
        if ($check->dmarc_pass === false) {
            $this->createIncident([
                'domain_id' => $domain->id,
                'delivery_check_id' => $check->id,
                'type' => 'dmarc_fail',
                'severity' => 'incident',
                'message' => 'DMARC authentication failed for delivery check',
                'meta' => [
                    'monitor_id' => $monitor->id,
                    'monitor_label' => $monitor->label,
                    'from_addr' => $check->from_addr,
                    'dmarc_result' => $authMeta['dmarc'] ?? null,
                ],
                'occurred_at' => $occurredAt,
            ]);
        }

        // SPF fail with DMARC none => warning
        if ($check->spf_pass === false) {
            $dmarcPolicy = $authMeta['dmarc']['policy'] ?? 'none';
            $severity = ($dmarcPolicy === 'none') ? 'warning' : 'incident';
            
            $this->createIncident([
                'domain_id' => $domain->id,
                'delivery_check_id' => $check->id,
                'type' => 'spf_fail',
                'severity' => $severity,
                'message' => 'SPF authentication failed for delivery check',
                'meta' => [
                    'monitor_id' => $monitor->id,
                    'monitor_label' => $monitor->label,
                    'from_addr' => $check->from_addr,
                    'spf_result' => $authMeta['spf'] ?? null,
                    'dmarc_policy' => $dmarcPolicy,
                ],
                'occurred_at' => $occurredAt,
            ]);
        }

        // DKIM fail (if verified) => warning
        if ($check->dkim_pass === false) {
            $dkimCount = $authMeta['dkim']['count'] ?? 0;
            
            // Only create incident if DKIM was actually attempted
            if ($dkimCount > 0) {
                $this->createIncident([
                    'domain_id' => $domain->id,
                    'delivery_check_id' => $check->id,
                    'type' => 'dkim_fail',
                    'severity' => 'warning',
                    'message' => 'DKIM signature verification failed',
                    'meta' => [
                        'monitor_id' => $monitor->id,
                        'monitor_label' => $monitor->label,
                        'from_addr' => $check->from_addr,
                        'dkim_result' => $authMeta['dkim'] ?? null,
                        'signature_count' => $dkimCount,
                    ],
                    'occurred_at' => $occurredAt,
                ]);
            }
        }

        // High TTI => warning
        $ttiThresholdMinutes = config('mxscan.tti_slow_minutes', 30);
        if ($check->tti_ms && $check->tti_ms > ($ttiThresholdMinutes * 60 * 1000)) {
            $this->createIncident([
                'domain_id' => $domain->id,
                'delivery_check_id' => $check->id,
                'type' => 'high_tti',
                'severity' => 'warning',
                'message' => sprintf('High time-to-inbox detected: %s', $check->getFormattedTti()),
                'meta' => [
                    'monitor_id' => $monitor->id,
                    'monitor_label' => $monitor->label,
                    'tti_ms' => $check->tti_ms,
                    'tti_minutes' => round($check->tti_ms / 60000, 2),
                    'threshold_minutes' => $ttiThresholdMinutes,
                ],
                'occurred_at' => $occurredAt,
            ]);
        }

        Log::info('incident.process_check', [
            'check_id' => $check->id,
            'monitor_id' => $monitor->id,
            'domain' => $domain->domain,
            'verdict' => $check->verdict,
        ]);
    }

    /**
     * Create incident with deduplication
     */
    protected function createIncident(array $data): void
    {
        // Check if similar incident exists in last hour (prevent spam)
        $existing = Incident::where('domain_id', $data['domain_id'])
            ->where('type', $data['type'])
            ->where('occurred_at', '>=', now()->subHour())
            ->whereNull('resolved_at')
            ->first();

        if ($existing) {
            Log::debug('incident.deduplicated', [
                'type' => $data['type'],
                'domain_id' => $data['domain_id'],
            ]);
            return;
        }

        Incident::create($data);

        Log::info('incident.create', [
            'type' => $data['type'],
            'severity' => $data['severity'],
            'domain_id' => $data['domain_id'],
            'delivery_check_id' => $data['delivery_check_id'] ?? null,
        ]);
    }
}
