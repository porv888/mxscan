<?php

namespace App\Services;

use App\Domain\EmailSecurity\Contracts\ScanPersisterInterface;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Domain\EmailSecurity\Support\ScanPayloadBuilder;
use App\Models\Domain;
use App\Models\Scan;
use App\Services\Expiry\ExpiryCoordinator;
use App\Services\ScanReport\ScanFinalizer;
use Exception;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Log;

class ScanRunner
{
    public function __construct(
        private EmailSecurityScanService $scanService,
        private ExpiryCoordinator $expiryCoordinator,
        private ScanFinalizer $scanFinalizer,
        private ScanPersisterInterface $persister,
    ) {
    }

    /**
     * @param array{dns:bool, spf:bool, blacklist:bool} $options
     */
    public function runSync(Domain $domain, array $options): Scan
    {
        $startTime = microtime(true);

        $options = array_merge([
            'dns' => true,
            'spf' => true,
            'blacklist' => true,
        ], $options);

        $scanOptions = ScanOptionsDTO::fromArray([
            'dns' => Arr::get($options, 'dns', true),
            'spf' => Arr::get($options, 'spf', true),
            'blacklist' => Arr::get($options, 'blacklist', true),
            'monitoring' => Arr::get($options, 'monitoring', true),
        ]);

        $scanType = ScanPayloadBuilder::determineScanType([
            'dns' => $scanOptions->dns,
            'spf' => $scanOptions->spf,
            'blacklist' => $scanOptions->blacklist,
        ]);

        $scan = Scan::create([
            'domain_id' => $domain->id,
            'user_id' => $domain->user_id,
            'type' => $scanType,
            'status' => 'running',
            'progress_pct' => 0,
            'started_at' => now(),
        ]);

        try {
            Log::info('Starting synchronous scan', [
                'scan_id' => $scan->id,
                'domain' => $domain->domain,
                'options' => $options,
            ]);

            $onProgress = function (string $stage, array $payload) use ($scan, $domain, $scanOptions): void {
                if ($stage === 'dns_done' && $scanOptions->dns) {
                    $this->persister->updateProgress($scan, 33);
                    $domain->update([
                        'last_scanned_at' => now(),
                        'score_last' => $payload['score'] ?? null,
                        'status' => 'active',
                    ]);
                }

                if ($stage === 'spf_done') {
                    $this->persister->updateProgress($scan, 66);
                }

                if ($stage === 'blacklist_done' && $scanOptions->blacklist) {
                    $this->persister->updateProgress($scan, 90);
                    $domain->update([
                        'blacklist_status' => ScanPayloadBuilder::blacklistStatusLabel($payload),
                        'blacklist_count' => $payload['listed_count'] ?? 0,
                    ]);
                }
            };

            $execution = $this->scanService->execute($domain, $scan, $scanOptions, $startTime, $onProgress);

            $facts = ScanPayloadBuilder::buildFactsForSyncRunner(
                $execution->resultJson,
                $execution->spfRawResult
            );

            $this->persister->saveFinished($scan, $domain, $execution, $scanOptions, $facts);

            Log::info('Synchronous scan completed successfully', [
                'scan_id' => $scan->id,
                'domain' => $domain->domain,
                'duration_ms' => $execution->durationMs,
                'score' => $execution->score,
            ]);

            $this->runPostScanSideEffects($domain, $scan, $execution->resultJson, $scanType, $scanOptions->monitoring);
        } catch (Exception $e) {
            Log::error('Synchronous scan failed', [
                'scan_id' => $scan->id,
                'domain' => $domain->domain,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            $this->persister->markFailed($scan, (int) round((microtime(true) - $startTime) * 1000));

            throw $e;
        }

        return $scan->fresh();
    }

    /**
     * @param array<string, mixed> $results
     */
    private function runPostScanSideEffects(
        Domain $domain,
        Scan $scan,
        array $results,
        string $scanType,
        bool $raiseIncidents,
    ): void {
        try {
            $domainExpiryResult = $this->expiryCoordinator->detectDomainExpiry($domain, true);
            $sslExpiryResult = $this->expiryCoordinator->detectSslExpiry($domain, true);
            $this->expiryCoordinator->updateDomain($domain, $domainExpiryResult, $sslExpiryResult);
        } catch (Exception $e) {
            Log::warning('Fast-path expiry detection failed', [
                'scan_id' => $scan->id,
                'domain' => $domain->domain,
                'error' => $e->getMessage(),
            ]);
        }

        $this->scanFinalizer->finalizeMonitoredScan(
            $domain,
            $scan->fresh(),
            $results,
            $scanType,
            $raiseIncidents
        );

        try {
            $domain->refresh();
            $wasVerified = $domain->dmarc_rua_verified_at !== null;
            $isConfigured = $domain->verifyAndSyncDmarcRua();

            if ($isConfigured && !$wasVerified) {
                Log::info('DMARC RUA verified from scan', [
                    'scan_id' => $scan->id,
                    'domain' => $domain->domain,
                ]);
            } elseif (!$isConfigured && $wasVerified) {
                Log::info('DMARC RUA no longer configured', [
                    'scan_id' => $scan->id,
                    'domain' => $domain->domain,
                ]);
            }
        } catch (Exception $e) {
            Log::warning('Failed to sync DMARC RUA verification', [
                'scan_id' => $scan->id,
                'domain' => $domain->domain,
                'error' => $e->getMessage(),
            ]);
        }
    }
}
