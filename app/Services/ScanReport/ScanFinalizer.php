<?php

namespace App\Services\ScanReport;

use App\Models\Domain;
use App\Models\Scan;
use App\Services\MonitoringService;
use Illuminate\Support\Facades\Log;

/**
 * Shared post-scan finalization for monitored domain scans.
 */
class ScanFinalizer
{
    public function __construct(
        protected MonitoringService $monitoringService
    ) {
    }

    /**
     * @param array<string, mixed> $results result_json payload
     */
    public function finalizeMonitoredScan(
        Domain $domain,
        Scan $scan,
        array $results,
        string $scanType,
        bool $raiseIncidents = true
    ): void {
        if (!$raiseIncidents) {
            return;
        }

        try {
            $snapshot = $this->monitoringService->persistSnapshot($domain, $scanType, $results);
            $this->monitoringService->computeDeltaAndIncidents($domain, $snapshot);
        } catch (\Throwable $e) {
            Log::error('Failed to finalize monitored scan', [
                'scan_id' => $scan->id,
                'domain' => $domain->domain,
                'error' => $e->getMessage(),
            ]);
        }
    }
}
