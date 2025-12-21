<?php

namespace App\Jobs;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Support\Facades\Log;
use App\Models\Scan;
use App\Services\BlacklistChecker;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Http;

class RunScan implements ShouldQueue
{
    use Queueable, InteractsWithQueue, SerializesModels;

    protected $scan;

    public function __construct(Scan $scan)
    {
        $this->scan = $scan;
    }

    public function handle()
    {
        $scan = Scan::find($this->scan->id);
        $domain = $scan->domain->domain;
        $facts = [];
        $score = 0;

        // Log job start
        Log::info('RunScan job started', ['scan_id' => $scan->id, 'domain' => $domain]);

        try {
            // Start the scan
            $scan->update(['status' => 'running', 'progress_pct' => 10]);
            Log::info('Scan status updated to running');
            sleep(1); // Simulate processing time
            
            $mx = dns_get_record($domain, DNS_MX);
            $facts['mx'] = $mx ?: [];
            if ($mx && count($mx) > 0) {
                $score += 30;
            }

            // --- Phase 2: SPF Record ---
            $scan->update(['progress_pct' => 30]);
            sleep(1);
            
            $txt = dns_get_record($domain, DNS_TXT);
            $spf = null;
            if ($txt) {
                foreach ($txt as $record) {
                    if (isset($record['txt']) && str_starts_with($record['txt'], 'v=spf1')) {
                        $spf = $record['txt'];
                        break;
                    }
                }
            }
            $facts['spf'] = $spf;
            
            if ($spf) {
                $score += 20;
                if (str_contains($spf, '-all')) {
                    $score += 10;
                } elseif (str_contains($spf, '~all')) {
                    $score += 5;
                }
            }

            // --- Phase 3: DMARC Record ---
            $scan->update(['progress_pct' => 50]);
            sleep(1);
            
            $dmarc_records = dns_get_record("_dmarc.$domain", DNS_TXT);
            $dmarc = null;
            if ($dmarc_records && count($dmarc_records) > 0) {
                $dmarc = $dmarc_records[0]['txt'] ?? null;
            }
            $facts['dmarc'] = $dmarc;
            
            if ($dmarc) {
                $score += 20;
                if (str_contains($dmarc, 'p=reject')) {
                    $score += 10;
                } elseif (str_contains($dmarc, 'p=quarantine')) {
                    $score += 5;
                }
            }

            // --- Phase 4: TLS-RPT Record ---
            $scan->update(['progress_pct' => 70]);
            sleep(1);
            
            $tlsrpt_records = dns_get_record("_smtp._tls.$domain", DNS_TXT);
            $tlsrpt = null;
            if ($tlsrpt_records && count($tlsrpt_records) > 0) {
                $tlsrpt = $tlsrpt_records[0]['txt'] ?? null;
            }
            $facts['tlsrpt'] = $tlsrpt;
            
            if ($tlsrpt) {
                $score += 10;
            }

            // --- Phase 5: MTA-STS Record ---
            $scan->update(['progress_pct' => 80]);
            sleep(1);
            
            $mtasts_records = dns_get_record("_mta-sts.$domain", DNS_TXT);
            $mtasts = null;
            $mtasts_policy = null;
            
            if ($mtasts_records && count($mtasts_records) > 0) {
                $mtasts = $mtasts_records[0]['txt'] ?? null;
                
                // Try to fetch MTA-STS policy
                try {
                    $response = Http::timeout(5)->get("https://mta-sts.$domain/.well-known/mta-sts.txt");
                    if ($response->successful()) {
                        $mtasts_policy = $response->body();
                        $score += 20;
                    }
                } catch (\Exception $e) {
                    // Policy fetch failed, but DNS record exists
                }
            }
            
            $facts['mta_sts'] = $mtasts;
            $facts['mta_sts_policy'] = $mtasts_policy;

            // --- Phase 6: Blacklist Check ---
            $scan->update(['progress_pct' => 90]);
            sleep(1);
            
            $blacklistChecker = new BlacklistChecker();
            $blacklistResults = $blacklistChecker->checkDomain($scan, $domain);
            $blacklistSummary = $blacklistChecker->getScanSummary($scan);
            
            $facts['blacklist_summary'] = $blacklistSummary;
            
            // Adjust score based on blacklist results
            if ($blacklistSummary['is_clean']) {
                $score += config('rbl.settings.clean_reputation_bonus', 10);
            } else {
                // Penalty for being listed (more severe for multiple listings)
                $penaltyPerListing = config('rbl.settings.score_penalty_per_listing', 5);
                $maxPenalty = config('rbl.settings.max_score_penalty', 30);
                $penalty = min($blacklistSummary['listed_count'] * $penaltyPerListing, $maxPenalty);
                $score = max($score - $penalty, 0);
            }

            // Cap score at 100
            $score = min($score, 100);

            // Generate recommendations
            try {
                $recommendations = $this->generateRecommendations($domain, $facts);
                Log::info('Scan debug - facts:', $facts);
                Log::info('Scan debug - recommendations:', $recommendations);
            } catch (\Exception $e) {
                Log::error('Error generating recommendations: ' . $e->getMessage());
                $recommendations = [];
            }

            Log::debug('Before save', [
                'facts' => $facts,
                'recommendations' => $recommendations,
            ]);

            // Save final results
            $recommendationsJson = json_encode($recommendations, JSON_PRETTY_PRINT);
            Log::info('Saving recommendations JSON', ['json' => $recommendationsJson]);
            
            $scan->update([
                'status' => 'finished',
                'progress_pct' => 100,
                'score' => $score,
                'facts_json' => json_encode($facts, JSON_PRETTY_PRINT),
                'recommendations_json' => $recommendationsJson,
                'finished_at' => now(),
            ]);

            // Verify save
            $scan->refresh();
            Log::debug('After save', [
                'facts_json' => $scan->facts_json,
                'recommendations_json' => $scan->recommendations_json,
            ]);

        } catch (\Exception $e) {
            // Handle scan failure
            $scan->update([
                'status' => 'failed',
                'progress_pct' => 0,
                'error_message' => $e->getMessage(),
            ]);
        }
    }

    private function generateRecommendations($domain, $facts)
    {
        $recommendations = [];

        if (empty($facts['mx'])) {
            $recommendations['MX'] = [
                'title' => 'Missing MX Record',
                'record' => $domain,
                'type' => 'MX',
                'priority' => 10,
                'value' => 'mail.' . $domain,
                'ttl' => 3600,
            ];
        }

        if (empty($facts['spf'])) {
            $recommendations['SPF'] = [
                'title' => 'Missing SPF Record',
                'record' => $domain,
                'type' => 'TXT',
                'value' => 'v=spf1 -all',
                'ttl' => 3600,
            ];
        }

        if (empty($facts['dmarc'])) {
            $recommendations['DMARC'] = [
                'title' => 'Missing DMARC Record',
                'record' => '_dmarc.' . $domain,
                'type' => 'TXT',
                'value' => 'v=DMARC1; p=quarantine; rua=mailto:postmaster@' . $domain,
                'ttl' => 3600,
            ];
        }

        if (empty($facts['tlsrpt'])) {
            $recommendations['TLS-RPT'] = [
                'title' => 'Missing TLS-RPT Record',
                'record' => '_smtp._tls.' . $domain,
                'type' => 'TXT',
                'value' => 'v=TLSRPTv1; rua=mailto:reports@' . $domain,
                'ttl' => 3600,
            ];
        }

        if (empty($facts['mta_sts'])) {
            $recommendations['MTA-STS'] = [
                'title' => 'Missing MTA-STS Record',
                'record' => '_mta-sts.' . $domain,
                'type' => 'TXT',
                'value' => 'v=STSv1; id=20250910',
                'policy_url' => 'https://mta-sts.' . $domain . '/.well-known/mta-sts.txt',
                'ttl' => 3600,
            ];
        }

        return $recommendations;
    }
}
