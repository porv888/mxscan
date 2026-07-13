<?php

namespace App\Jobs;

use App\Models\Domain;
use App\Models\Scan;
use App\Services\ScannerService;
use App\Services\Spf\SpfResolver;
use App\Services\BlacklistChecker;
use App\Services\ScanReport\ScanFinalizer;
use App\Services\ScanReport\ScanRecommendationService;
use App\Events\ScanProgressed;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;
use Exception;

class RunFullScan implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public function __construct(
        public int $domainId,
        public array $options = [] // e.g. ['dns' => true, 'spf' => true, 'blacklist' => true, 'monitoring' => true, 'scan_id' => uuid]
    ) {}

    public function handle(): void
    {
        $domain = Domain::findOrFail($this->domainId);
        $results = [];
        $startTime = microtime(true);
        $scanType = $this->determineScanType();

        $scanId = $this->options['scan_id'] ?? null;
        if ($scanId) {
            $scan = Scan::query()
                ->where('id', $scanId)
                ->where('domain_id', $domain->id)
                ->firstOrFail();
            $scan->update([
                'status' => 'running',
                'type' => $scanType,
                'progress_pct' => 0,
                'started_at' => now(),
            ]);
        } else {
            $scan = Scan::create([
                'domain_id' => $domain->id,
                'user_id' => $domain->user_id,
                'type' => $scanType,
                'status' => 'running',
                'progress_pct' => 0,
                'started_at' => now(),
            ]);
        }

        Log::info('Starting full scan', [
            'domain_id' => $domain->id,
            'domain' => $domain->domain,
            'scan_id' => $scan->id,
            'options' => $this->options
        ]);

        try {
            // DNS Scan (Email Security)
            if ($this->options['dns'] ?? true) {
                Log::info('Running DNS scan', ['domain' => $domain->domain]);
                $results['dns'] = app(ScannerService::class)->scanDomain($domain->domain);
                event(new ScanProgressed($domain->id, 'dns_done', $results['dns']));
                $scan->update(['progress_pct' => 33]);
                
                // Update domain with DNS scan results
                $domain->update([
                    'last_scanned_at' => now(),
                    'score_last' => $results['dns']['score'] ?? null,
                    'status' => 'active',
                ]);
            }

            // SPF Analysis
            if ($this->options['spf'] ?? true) {
                Log::info('Running SPF analysis', ['domain' => $domain->domain]);
                $spfResolver = app(SpfResolver::class);
                $spfResult = $spfResolver->resolve($domain->domain);
                
                $results['spf'] = $this->buildSpfResultPayload($spfResult);
                
                event(new ScanProgressed($domain->id, 'spf_done', $results['spf']));
                $scan->update(['progress_pct' => 66]);
            }

            // Blacklist Check
            if ($this->options['blacklist'] ?? true) {
                Log::info('Running blacklist check', ['domain' => $domain->domain]);

                $blacklistChecker = app(BlacklistChecker::class);
                $blacklistChecker->checkDomain($scan, $domain->domain);
                $blacklistSummary = $blacklistChecker->getScanSummary($scan);

                $results['blacklist'] = $blacklistSummary;
                event(new ScanProgressed($domain->id, 'blacklist_done', $results['blacklist']));
                $scan->update(['progress_pct' => 90]);
                
                // Update domain with blacklist results
                $domain->update([
                    'blacklist_status' => $this->blacklistStatusLabel($blacklistSummary),
                    'blacklist_count' => $blacklistSummary['listed_count'] ?? 0,
                ]);
            }

            // Build final report
            $report = $this->buildReport($domain, $results);
            event(new ScanProgressed($domain->id, 'complete', $report));

            $recommendations = app(ScanRecommendationService::class)->build($domain, $results);

            $scan->update([
                'status' => 'finished',
                'progress_pct' => 100,
                'score' => $results['dns']['score'] ?? null,
                'facts_json' => [
                    'spf_record' => $results['spf']['record'] ?? null,
                    'spf_lookups' => $results['spf']['lookups'] ?? null,
                    'blacklist_status' => isset($results['blacklist'])
                        ? $this->blacklistStatusLabel($results['blacklist'])
                        : null,
                    'blacklist_count' => $results['blacklist']['listed_count'] ?? null,
                ],
                'result_json' => $results,
                'recommendations_json' => $recommendations,
                'finished_at' => now(),
                'duration_ms' => (int) round((microtime(true) - $startTime) * 1000),
            ]);

            $raiseIncidents = (bool) ($this->options['monitoring'] ?? true);
            app(ScanFinalizer::class)->finalizeMonitoredScan(
                $domain,
                $scan,
                $results,
                $scanType,
                $raiseIncidents
            );

            Log::info('Full scan completed successfully', [
                'domain_id' => $domain->id,
                'domain' => $domain->domain,
                'results_summary' => [
                    'dns_score' => $results['dns']['score'] ?? null,
                    'spf_lookups' => $results['spf']['lookups'] ?? null,
                    'blacklist_count' => $results['blacklist']['listed_count'] ?? null,
                ]
            ]);

        } catch (Exception $e) {
            $scan->update([
                'status' => 'failed',
                'finished_at' => now(),
                'duration_ms' => (int) round((microtime(true) - $startTime) * 1000),
                'result_json' => array_merge(
                    is_array($scan->result_json) ? $scan->result_json : [],
                    ['user_error' => 'The scan could not be completed. Please try again.']
                ),
            ]);

            Log::error('Full scan failed', [
                'domain_id' => $domain->id,
                'domain' => $domain->domain,
                'scan_id' => $scan->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);

            event(new ScanProgressed($domain->id, 'failed', [
                'error' => 'The scan could not be completed. Please try again.',
            ]));

            throw $e;
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function buildSpfResultPayload(\App\Services\Spf\DTOs\SpfResultDTO $spfResult): array
    {
        $warnings = $spfResult->warnings;
        $invalid = in_array(SpfResolver::WARNING_PLUS_ALL, $warnings, true)
            || in_array(SpfResolver::WARNING_MULTIPLE_SPF, $warnings, true);
        $error = null;
        if (in_array(SpfResolver::WARNING_PLUS_ALL, $warnings, true)) {
            $error = 'SPF uses +all which allows any sender.';
        } elseif (in_array(SpfResolver::WARNING_MULTIPLE_SPF, $warnings, true)) {
            $error = 'Multiple SPF records found; only one is allowed.';
        }

        $lookups = $spfResult->lookupsUsed;
        $status = $lookups >= 10 ? 'error' : ($lookups >= 9 ? 'warning' : 'safe');
        if ($invalid) {
            $status = 'error';
        }

        return [
            'record' => $spfResult->currentRecord,
            'lookups' => $lookups,
            'flattened' => $spfResult->flattenedSpf,
            'status' => $status,
            'valid' => !$invalid && $spfResult->currentRecord !== null,
            'error' => $error,
            'warnings' => $warnings,
        ];
    }

    /**
     * @param array<string, mixed> $summary
     */
    private function blacklistStatusLabel(array $summary): string
    {
        if (($summary['total_checks'] ?? 0) <= 0) {
            return 'not-checked';
        }

        return !empty($summary['is_clean']) ? 'clean' : 'listed';
    }

    private function buildReport(Domain $domain, array $results): array
    {
        $report = [
            'domain' => $domain->domain,
            'timestamp' => now()->toISOString(),
            'summary' => []
        ];

        if (isset($results['dns'])) {
            $report['summary']['dns_score'] = $results['dns']['score'];
            $report['dns'] = $results['dns'];
        }

        if (isset($results['spf'])) {
            $report['summary']['spf_status'] = $results['spf']['status'];
            $report['summary']['spf_lookups'] = $results['spf']['lookups'];
            $report['spf'] = $results['spf'];
        }

        if (isset($results['blacklist'])) {
            $report['summary']['blacklist_status'] = $this->blacklistStatusLabel($results['blacklist']);
            $report['summary']['blacklist_count'] = $results['blacklist']['listed_count'] ?? 0;
            $report['blacklist'] = $results['blacklist'];
        }

        return $report;
    }

    private function determineScanType(): string
    {
        $dns = $this->options['dns'] ?? true;
        $spf = $this->options['spf'] ?? true;
        $blacklist = $this->options['blacklist'] ?? true;

        $enabledCount = ($dns ? 1 : 0) + ($spf ? 1 : 0) + ($blacklist ? 1 : 0);

        if ($enabledCount === 1) {
            if ($dns) return 'dns';
            if ($spf) return 'spf';
            if ($blacklist) return 'blacklist';
        }

        return 'full';
    }
}
