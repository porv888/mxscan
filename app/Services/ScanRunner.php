<?php

namespace App\Services;

use App\Models\Domain;
use App\Models\Scan;
use App\Services\ScannerService;
use App\Services\Spf\SpfResolver;
use App\Services\BlacklistChecker;
use App\Services\Expiry\ExpiryCoordinator;
use App\Services\ScanReport\ScanFinalizer;
use App\Services\ScanReport\ScanRecommendationService;
use App\Services\Spf\SpfResolver;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Log;
use Exception;

class ScanRunner
{
    public function __construct(
        private ScannerService $scannerService,
        private SpfResolver $spfResolver,
        private BlacklistChecker $blacklistChecker,
        private ExpiryCoordinator $expiryCoordinator,
        private ScanRecommendationService $recommendationService,
        private ScanFinalizer $scanFinalizer
    ) {}

    /**
     * Run a scan synchronously and return the Scan model
     *
     * @param Domain $domain
     * @param array{dns:bool, spf:bool, blacklist:bool} $options
     */
    public function runSync(Domain $domain, array $options): Scan
    {
        $startTime = microtime(true);
        
        // Map 'full' to dns+spf+blacklist (defensive programming)
        $options = array_merge([
            'dns' => true,
            'spf' => true,
            'blacklist' => true,
        ], $options);
        
        // Determine scan type from options
        $scanType = $this->determineScanType($options);
        
        // Create initial scan record (status=running)
        $scan = Scan::create([
            'domain_id' => $domain->id,
            'user_id' => $domain->user_id,
            'type' => $scanType,
            'status' => 'running',
            'progress_pct' => 0,
            'started_at' => now(),
        ]);

        $results = [];
        $facts = [];
        $recommendations = [];
        $score = null;

        try {
            Log::info('Starting synchronous scan', [
                'scan_id' => $scan->id,
                'domain' => $domain->domain,
                'options' => $options
            ]);

            // DNS Scan
            if (Arr::get($options, 'dns', true)) {
                Log::info('Running DNS scan', ['scan_id' => $scan->id, 'domain' => $domain->domain]);
                
                $dnsResults = $this->scannerService->scanDomain($domain->domain);
                $results['dns'] = $dnsResults;
                $facts = array_merge($facts, $dnsResults['facts'] ?? []);
                $score = $dnsResults['score'] ?? null;
                
                $scan->update(['progress_pct' => 33]);
                
                // Update domain with DNS results
                $domain->update([
                    'last_scanned_at' => now(),
                    'score_last' => $score,
                    'status' => 'active',
                ]);
            }

            // SPF Analysis
            if (Arr::get($options, 'spf', true)) {
                Log::info('Running SPF analysis', ['scan_id' => $scan->id, 'domain' => $domain->domain]);
                
                $spfResult = $this->spfResolver->resolve($domain->domain);
                
                $spfData = $this->buildSpfResultPayload($spfResult);
                
                $results['spf'] = $spfData;
                
                // Add SPF facts and recommendations
                $facts['spf_record'] = $spfResult->currentRecord ?: 'No SPF record found';
                $facts['spf_lookups'] = $spfResult->lookupsUsed;
                
                $scan->update(['progress_pct' => 66]);
            }

            // Blacklist Check
            if (Arr::get($options, 'blacklist', true)) {
                Log::info('Running blacklist check', ['scan_id' => $scan->id, 'domain' => $domain->domain]);
                
                $blacklistResults = $this->blacklistChecker->checkDomain($scan, $domain->domain);
                $blacklistSummary = $this->blacklistChecker->getScanSummary($scan);
                
                $results['blacklist'] = $blacklistSummary;
                
                // Add blacklist facts
                $facts['blacklist_status'] = $this->blacklistStatusLabel($blacklistSummary);
                $facts['blacklist_count'] = $blacklistSummary['listed_count'] ?? 0;
                
                // Update domain with blacklist results
                $domain->update([
                    'blacklist_status' => $this->blacklistStatusLabel($blacklistSummary),
                    'blacklist_count' => $blacklistSummary['listed_count'] ?? 0,
                ]);
                
                $scan->update(['progress_pct' => 90]);
            }

            $recommendations = $this->recommendationService->build($domain, $results);

            // Calculate duration
            $endTime = microtime(true);
            $durationMs = round(($endTime - $startTime) * 1000);

            // Update scan with final results
            $scan->update([
                'status' => 'finished',
                'progress_pct' => 100,
                'score' => $score,
                'facts_json' => $facts,
                'result_json' => $results,
                'recommendations_json' => $recommendations,
                'finished_at' => now(),
                'duration_ms' => $durationMs,
            ]);

            Log::info('Synchronous scan completed successfully', [
                'scan_id' => $scan->id,
                'domain' => $domain->domain,
                'duration_ms' => $durationMs,
                'score' => $score
            ]);

            // Fast-path expiry detection (best provider only, short timeout)
            try {
                $domainExpiryResult = $this->expiryCoordinator->detectDomainExpiry($domain, true);
                $sslExpiryResult = $this->expiryCoordinator->detectSslExpiry($domain, true);
                
                $this->expiryCoordinator->updateDomain($domain, $domainExpiryResult, $sslExpiryResult);
                
                Log::info('Fast-path expiry detection completed', [
                    'scan_id' => $scan->id,
                    'domain' => $domain->domain,
                    'domain_expiry' => $domainExpiryResult?->isValid() ? 'detected' : 'failed',
                    'ssl_expiry' => $sslExpiryResult?->isValid() ? 'detected' : 'failed',
                ]);
            } catch (Exception $e) {
                Log::warning('Fast-path expiry detection failed', [
                    'scan_id' => $scan->id,
                    'domain' => $domain->domain,
                    'error' => $e->getMessage()
                ]);
                // Don't fail the scan if expiry check fails
            }

            // Create monitoring snapshot and check for incidents (shared finalizer)
            $raiseIncidents = (bool) Arr::get($options, 'monitoring', true);
            $this->scanFinalizer->finalizeMonitoredScan(
                $domain,
                $scan,
                $results,
                $scanType,
                $raiseIncidents
            );

            // Sync DMARC RUA verification state based on scan results
            // This ensures DMARC Activity page reflects DNS confirmation from scans
            try {
                $domain->refresh(); // Ensure we have latest scan data
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
                    'error' => $e->getMessage()
                ]);
                // Don't fail the scan if DMARC sync fails
            }

        } catch (Exception $e) {
            Log::error('Synchronous scan failed', [
                'scan_id' => $scan->id,
                'domain' => $domain->domain,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);

            $scan->update([
                'status' => 'failed',
                'finished_at' => now(),
                'duration_ms' => round((microtime(true) - $startTime) * 1000),
            ]);
            
            throw $e;
        }

        return $scan->fresh();
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

    /**
     * Determine scan type from options
     */
    private function determineScanType(array $options): string
    {
        $dns = $options['dns'] ?? false;
        $spf = $options['spf'] ?? false;
        $blacklist = $options['blacklist'] ?? false;
        
        // Count enabled options
        $enabledCount = ($dns ? 1 : 0) + ($spf ? 1 : 0) + ($blacklist ? 1 : 0);
        
        // If only one option is enabled, return that type
        if ($enabledCount === 1) {
            if ($dns) return 'dns';
            if ($spf) return 'spf';
            if ($blacklist) return 'blacklist';
        }
        
        // If multiple options or all options are enabled, it's a full scan
        return 'full';
    }
}
