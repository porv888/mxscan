<?php

namespace App\Services\ScanReport;

use App\Domain\EmailSecurity\Checks\Bimi\BimiAnalysisReader;
use App\Domain\EmailSecurity\Checks\Bimi\Monitoring\BimiMonitoringService;
use App\Domain\EmailSecurity\Checks\Certificates\Monitoring\CertificateMonitoringService;
use App\Domain\EmailSecurity\Checks\Certificates\Support\CertificateAnalysisReader;
use App\Jobs\NotifyIncident;
use App\Models\Domain;
use App\Models\Incident;
use App\Models\Scan;
use App\Services\MonitoringService;
use Illuminate\Support\Facades\Log;

/**
 * Shared post-scan finalization for monitored domain scans.
 */
class ScanFinalizer
{
    public function __construct(
        protected MonitoringService $monitoringService,
        protected CertificateMonitoringService $certificateMonitoringService,
        protected BimiMonitoringService $bimiMonitoringService,
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

        $this->evaluateCertificateMonitoring($domain, $scan, $results);
        $this->evaluateBimiMonitoring($domain, $scan, $results);
    }

    /**
     * @param array<string, mixed> $results
     */
    private function evaluateCertificateMonitoring(Domain $domain, Scan $scan, array $results): void
    {
        $currentNative = CertificateAnalysisReader::toNativeResult(
            $domain->domain,
            is_array($results['certificates'] ?? null) ? $results['certificates'] : null,
        );

        if ($currentNative === null) {
            return;
        }

        try {
            $previousCertificatesInfo = $this->previousCertificatesSection($domain, $scan);
            $alreadySent = $this->openCertificateDedupKeys($domain);
            $delta = $this->certificateMonitoringService->evaluateMonitoringDelta(
                $domain->domain,
                $currentNative,
                $previousCertificatesInfo,
                $alreadySent,
            );

            foreach ($delta['alerts'] as $alert) {
                if (!is_array($alert)) {
                    continue;
                }

                $this->raiseCertificateAlert($domain, $alert);
            }

            foreach ($delta['resolved_dedup_keys'] as $dedupKey) {
                $this->resolveCertificateAlert($domain, (string) $dedupKey);
            }
        } catch (\Throwable $e) {
            Log::error('Certificate monitoring evaluation failed', [
                'scan_id' => $scan->id,
                'domain' => $domain->domain,
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * @return array<string, mixed>|null
     */
    private function previousCertificatesSection(Domain $domain, Scan $currentScan): ?array
    {
        $previousScan = Scan::query()
            ->where('domain_id', $domain->id)
            ->where('status', 'finished')
            ->where('id', '!=', $currentScan->id)
            ->latest('finished_at')
            ->first();

        if ($previousScan === null) {
            return null;
        }

        $resultJson = $previousScan->result_json ?? [];
        if (!is_array($resultJson)) {
            return null;
        }

        $certificates = $resultJson['certificates'] ?? null;

        return is_array($certificates) ? $certificates : null;
    }

    /**
     * @return list<string>
     */
    private function openCertificateDedupKeys(Domain $domain): array
    {
        return Incident::query()
            ->where('domain_id', $domain->id)
            ->where('type', 'certificate_expiring')
            ->whereNull('resolved_at')
            ->get()
            ->map(fn (Incident $incident) => (string) ($incident->meta['dedup_key'] ?? ''))
            ->filter(fn (string $key) => $key !== '')
            ->values()
            ->all();
    }

    /**
     * @param array<string, mixed> $alert
     */
    private function raiseCertificateAlert(Domain $domain, array $alert): void
    {
        $dedupKey = (string) ($alert['dedup_key'] ?? '');
        if ($dedupKey === '') {
            return;
        }

        $existing = Incident::query()
            ->where('domain_id', $domain->id)
            ->where('type', 'certificate_expiring')
            ->whereNull('resolved_at')
            ->where('meta->dedup_key', $dedupKey)
            ->first();

        if ($existing) {
            $existing->update([
                'occurred_at' => now(),
                'severity' => (string) ($alert['severity'] ?? 'warning'),
                'message' => (string) ($alert['message'] ?? 'Certificate alert'),
            ]);

            return;
        }

        $incident = Incident::create([
            'domain_id' => $domain->id,
            'type' => 'certificate_expiring',
            'severity' => (string) ($alert['severity'] ?? 'warning'),
            'message' => (string) ($alert['message'] ?? 'Certificate alert'),
            'meta' => [
                'dedup_key' => $dedupKey,
                'threshold' => $alert['threshold'] ?? null,
                'endpoint_key' => $alert['endpoint_key'] ?? null,
                'hostname' => $alert['hostname'] ?? null,
                'days_remaining' => $alert['days_remaining'] ?? null,
            ],
            'occurred_at' => now(),
        ]);

        NotifyIncident::dispatch($incident);
    }

    private function resolveCertificateAlert(Domain $domain, string $dedupKey): void
    {
        if ($dedupKey === '') {
            return;
        }

        Incident::query()
            ->where('domain_id', $domain->id)
            ->where('type', 'certificate_expiring')
            ->whereNull('resolved_at')
            ->where('meta->dedup_key', $dedupKey)
            ->update(['resolved_at' => now()]);
    }

    /**
     * @param array<string, mixed> $results
     */
    private function evaluateBimiMonitoring(Domain $domain, Scan $scan, array $results): void
    {
        $currentNative = BimiAnalysisReader::toNativeResult(
            $domain->domain,
            is_array($results['bimi'] ?? null) ? $results['bimi'] : null,
        );

        if ($currentNative === null) {
            return;
        }

        try {
            $previousBimiInfo = $this->previousBimiSection($domain, $scan);
            $alreadySent = $this->openBimiDedupKeys($domain);
            $delta = $this->bimiMonitoringService->evaluateMonitoringDelta(
                $domain->domain,
                $currentNative,
                $previousBimiInfo,
                $alreadySent,
            );

            foreach ($delta['alerts'] as $alert) {
                if (!is_array($alert)) {
                    continue;
                }

                $this->raiseBimiAlert($domain, $alert);
            }

            foreach ($delta['resolved_dedup_keys'] as $dedupKey) {
                $this->resolveBimiAlert($domain, (string) $dedupKey);
            }
        } catch (\Throwable $e) {
            Log::error('BIMI monitoring evaluation failed', [
                'scan_id' => $scan->id,
                'domain' => $domain->domain,
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * @return array<string, mixed>|null
     */
    private function previousBimiSection(Domain $domain, Scan $currentScan): ?array
    {
        $previousScan = Scan::query()
            ->where('domain_id', $domain->id)
            ->where('status', 'finished')
            ->where('id', '!=', $currentScan->id)
            ->latest('finished_at')
            ->first();

        if ($previousScan === null) {
            return null;
        }

        $resultJson = $previousScan->result_json ?? [];
        if (!is_array($resultJson)) {
            return null;
        }

        $bimi = $resultJson['bimi'] ?? null;

        return is_array($bimi) ? $bimi : null;
    }

    /**
     * @return list<string>
     */
    private function openBimiDedupKeys(Domain $domain): array
    {
        return Incident::query()
            ->where('domain_id', $domain->id)
            ->where('type', 'bimi_change')
            ->whereNull('resolved_at')
            ->get()
            ->map(fn (Incident $incident) => (string) ($incident->meta['dedup_key'] ?? ''))
            ->filter(fn (string $key) => $key !== '')
            ->values()
            ->all();
    }

    /**
     * @param array<string, mixed> $alert
     */
    private function raiseBimiAlert(Domain $domain, array $alert): void
    {
        $dedupKey = (string) ($alert['dedup_key'] ?? '');
        if ($dedupKey === '') {
            return;
        }

        $existing = Incident::query()
            ->where('domain_id', $domain->id)
            ->where('type', 'bimi_change')
            ->whereNull('resolved_at')
            ->where('meta->dedup_key', $dedupKey)
            ->first();

        if ($existing) {
            $existing->update([
                'occurred_at' => now(),
                'severity' => (string) ($alert['severity'] ?? 'warning'),
                'message' => (string) ($alert['message'] ?? 'BIMI configuration change'),
            ]);

            return;
        }

        $incident = Incident::create([
            'domain_id' => $domain->id,
            'type' => 'bimi_change',
            'severity' => (string) ($alert['severity'] ?? 'warning'),
            'message' => (string) ($alert['message'] ?? 'BIMI configuration change'),
            'meta' => [
                'dedup_key' => $dedupKey,
                'threshold' => $alert['threshold'] ?? null,
                'selector' => $alert['selector'] ?? null,
                'resource_hash' => $alert['resource_hash'] ?? null,
            ],
            'occurred_at' => now(),
        ]);

        NotifyIncident::dispatch($incident);
    }

    private function resolveBimiAlert(Domain $domain, string $dedupKey): void
    {
        if ($dedupKey === '') {
            return;
        }

        Incident::query()
            ->where('domain_id', $domain->id)
            ->where('type', 'bimi_change')
            ->whereNull('resolved_at')
            ->where('meta->dedup_key', $dedupKey)
            ->update(['resolved_at' => now()]);
    }
}
