<?php

namespace App\Jobs;

use App\Domain\EmailSecurity\Contracts\ScanPersisterInterface;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Domain\EmailSecurity\Support\ScanPayloadBuilder;
use App\Events\ScanProgressed;
use App\Models\Domain;
use App\Models\Scan;
use App\Services\EmailSecurityScanService;
use App\Services\ScanReport\ScanFinalizer;
use Exception;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

class RunFullScan implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public function __construct(
        public int $domainId,
        public array $options = []
    ) {}

    public function handle(
        EmailSecurityScanService $scanService,
        ScanPersisterInterface $persister,
        ScanFinalizer $scanFinalizer,
    ): void {
        $domain = Domain::findOrFail($this->domainId);
        $options = ScanOptionsDTO::fromArray($this->options);
        $startTime = microtime(true);
        $scanType = ScanPayloadBuilder::determineScanType([
            'dns' => $options->dns,
            'spf' => $options->spf,
            'blacklist' => $options->blacklist,
            'dkim' => $options->dkim,
        ]);

        $scan = $this->resolveScanRecord($domain, $scanType);

        Log::info('Starting full scan', [
            'domain_id' => $domain->id,
            'domain' => $domain->domain,
            'scan_id' => $scan->id,
            'options' => $this->options,
        ]);

        try {
            $onProgress = function (string $stage, array $payload) use ($scan, $domain, $options, $persister): void {
                if ($stage === 'dns_done' && $options->dns) {
                    $persister->updateProgress($scan, 33);
                    $domain->update([
                        'last_scanned_at' => now(),
                        'score_last' => $payload['score'] ?? null,
                        'status' => 'active',
                    ]);
                }

                if ($stage === 'spf_done') {
                    $persister->updateProgress($scan, 66);
                }

                if ($stage === 'blacklist_done' && $options->blacklist) {
                    $persister->updateProgress($scan, 90);
                    $domain->update([
                        'blacklist_status' => ScanPayloadBuilder::blacklistStatusLabel($payload),
                        'blacklist_count' => $payload['listed_count'] ?? 0,
                    ]);
                }

                event(new ScanProgressed($domain->id, $stage, $payload));
            };

            $execution = $scanService->execute($domain, $scan, $options, $startTime, $onProgress);

            $facts = ScanPayloadBuilder::buildFactsForAsyncJob($execution->resultJson);

            $persister->saveFinished($scan, $domain, $execution, $options, $facts);

            $raiseIncidents = $options->monitoring;
            $scanFinalizer->finalizeMonitoredScan(
                $domain,
                $scan->fresh(),
                $execution->resultJson,
                $execution->scanType,
                $raiseIncidents
            );

            Log::info('Full scan completed successfully', [
                'domain_id' => $domain->id,
                'domain' => $domain->domain,
                'results_summary' => [
                    'dns_score' => $execution->score,
                    'spf_lookups' => $execution->resultJson['spf']['lookups'] ?? null,
                    'blacklist_count' => $execution->resultJson['blacklist']['listed_count'] ?? null,
                ],
            ]);
        } catch (Exception $e) {
            $persister->markFailed(
                $scan,
                (int) round((microtime(true) - $startTime) * 1000),
                'The scan could not be completed. Please try again.'
            );

            Log::error('Full scan failed', [
                'domain_id' => $domain->id,
                'domain' => $domain->domain,
                'scan_id' => $scan->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            event(new ScanProgressed($domain->id, 'failed', [
                'error' => 'The scan could not be completed. Please try again.',
            ]));

            throw $e;
        }
    }

    private function resolveScanRecord(Domain $domain, string $scanType): Scan
    {
        if ($this->options['scan_id'] ?? null) {
            $scan = Scan::query()
                ->where('id', $this->options['scan_id'])
                ->where('domain_id', $domain->id)
                ->firstOrFail();
            $scan->update([
                'status' => 'running',
                'type' => $scanType,
                'progress_pct' => 0,
                'started_at' => now(),
            ]);

            return $scan;
        }

        return Scan::create([
            'domain_id' => $domain->id,
            'user_id' => $domain->user_id,
            'type' => $scanType,
            'status' => 'running',
            'progress_pct' => 0,
            'started_at' => now(),
        ]);
    }
}
