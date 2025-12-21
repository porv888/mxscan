<?php

namespace App\Jobs;

use App\Models\Domain;
use App\Models\Scan;
use App\Services\ScannerService;
use App\Services\Spf\SpfResolver;
use App\Services\BlacklistChecker;
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
        public array $options = [] // e.g. ['dns' => true, 'spf' => true, 'blacklist' => true]
    ) {}

    public function handle(): void
    {
        $domain = Domain::findOrFail($this->domainId);
        $results = [];

        Log::info('Starting full scan', [
            'domain_id' => $domain->id,
            'domain' => $domain->domain,
            'options' => $this->options
        ]);

        try {
            // DNS Scan (Email Security)
            if ($this->options['dns'] ?? true) {
                Log::info('Running DNS scan', ['domain' => $domain->domain]);
                $results['dns'] = app(ScannerService::class)->scanDomain($domain->domain);
                event(new ScanProgressed($domain->id, 'dns_done', $results['dns']));
                
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
                
                $results['spf'] = [
                    'record' => $spfResult->currentRecord,
                    'lookups' => $spfResult->lookupsUsed,
                    'flattened' => $spfResult->flattenedSpf,
                    'status' => $spfResult->lookupsUsed >= 10 ? 'error' : ($spfResult->lookupsUsed >= 9 ? 'warning' : 'safe')
                ];
                
                event(new ScanProgressed($domain->id, 'spf_done', $results['spf']));
            }

            // Blacklist Check
            if ($this->options['blacklist'] ?? true) {
                Log::info('Running blacklist check', ['domain' => $domain->domain]);
                
                // Create a Scan record for blacklist results
                $scan = Scan::create([
                    'domain_id' => $domain->id,
                    'user_id' => $domain->user_id,
                    'status' => 'running',
                    'progress_pct' => 0,
                    'started_at' => now(),
                ]);
                
                $blacklistChecker = app(BlacklistChecker::class);
                $blacklistResults = $blacklistChecker->checkDomain($scan, $domain->domain);
                $blacklistSummary = $blacklistChecker->getScanSummary($scan);
                
                // Update scan status
                $scan->update([
                    'status' => 'finished',
                    'progress_pct' => 100,
                    'finished_at' => now(),
                ]);
                
                $results['blacklist'] = $blacklistSummary;
                event(new ScanProgressed($domain->id, 'blacklist_done', $results['blacklist']));
                
                // Update domain with blacklist results
                $domain->update([
                    'blacklist_status' => $blacklistSummary['is_clean'] ? 'clean' : 'listed',
                    'blacklist_count' => $blacklistSummary['listed_count'] ?? 0,
                ]);
            }

            // Build final report
            $report = $this->buildReport($domain, $results);
            event(new ScanProgressed($domain->id, 'complete', $report));

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
            Log::error('Full scan failed', [
                'domain_id' => $domain->id,
                'domain' => $domain->domain,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);

            event(new ScanProgressed($domain->id, 'failed', [
                'error' => $e->getMessage()
            ]));

            throw $e;
        }
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
            $report['summary']['blacklist_status'] = $results['blacklist']['is_clean'] ? 'clean' : 'listed';
            $report['summary']['blacklist_count'] = $results['blacklist']['listed_count'] ?? 0;
            $report['blacklist'] = $results['blacklist'];
        }

        return $report;
    }
}
