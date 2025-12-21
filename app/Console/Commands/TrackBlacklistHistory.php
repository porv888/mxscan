<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Models\Domain;
use App\Models\BlacklistResult;
use Illuminate\Support\Facades\DB;
use Carbon\Carbon;

class TrackBlacklistHistory extends Command
{
    /**
     * The name and signature of the console command.
     */
    protected $signature = 'blacklist:track-history {--days=30 : Number of days to analyze}';

    /**
     * The console command description.
     */
    protected $description = 'Track blacklist status changes over time for all domains';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $days = $this->option('days');
        $startDate = Carbon::now()->subDays($days);
        
        $this->info("Analyzing blacklist history for the last {$days} days...");
        
        // Get all domains with blacklist results
        $domains = Domain::whereHas('scans.blacklistResults')->get();
        
        if ($domains->isEmpty()) {
            $this->info('No domains with blacklist data found.');
            return 0;
        }

        $this->info("Found {$domains->count()} domains with blacklist data:");
        
        $historyData = [];
        
        foreach ($domains as $domain) {
            $this->line("Analyzing {$domain->domain}...");
            
            // Get blacklist results over time
            $results = BlacklistResult::whereHas('scan', function($query) use ($domain, $startDate) {
                $query->where('domain_id', $domain->id)
                      ->where('created_at', '>=', $startDate);
            })
            ->with('scan')
            ->orderBy('created_at')
            ->get();
            
            if ($results->isEmpty()) {
                continue;
            }
            
            // Group by date and analyze changes
            $dailyStatus = $results->groupBy(function($result) {
                return $result->created_at->format('Y-m-d');
            });
            
            $statusChanges = [];
            $previousStatus = null;
            
            foreach ($dailyStatus as $date => $dayResults) {
                $listedCount = $dayResults->where('status', 'listed')->count();
                $currentStatus = $listedCount > 0 ? 'listed' : 'clean';
                
                if ($previousStatus && $previousStatus !== $currentStatus) {
                    $statusChanges[] = [
                        'date' => $date,
                        'from' => $previousStatus,
                        'to' => $currentStatus,
                        'listed_count' => $listedCount
                    ];
                }
                
                $previousStatus = $currentStatus;
            }
            
            $historyData[$domain->domain] = [
                'total_checks' => $results->count(),
                'status_changes' => $statusChanges,
                'current_status' => $previousStatus,
                'first_check' => $results->first()->created_at->format('Y-m-d'),
                'last_check' => $results->last()->created_at->format('Y-m-d')
            ];
        }
        
        // Display summary
        $this->displayHistorySummary($historyData);
        
        return 0;
    }

    /**
     * Display history summary.
     */
    private function displayHistorySummary(array $historyData)
    {
        $this->newLine();
        $this->info('=== Blacklist History Summary ===');
        
        $totalDomains = count($historyData);
        $domainsWithChanges = collect($historyData)->filter(function($data) {
            return !empty($data['status_changes']);
        })->count();
        
        $currentlyListed = collect($historyData)->filter(function($data) {
            return $data['current_status'] === 'listed';
        })->count();
        
        $this->table(
            ['Metric', 'Value'],
            [
                ['Total Domains Analyzed', $totalDomains],
                ['Domains with Status Changes', $domainsWithChanges],
                ['Currently Listed', $currentlyListed],
                ['Currently Clean', $totalDomains - $currentlyListed],
            ]
        );
        
        if ($domainsWithChanges > 0) {
            $this->newLine();
            $this->info('Domains with Status Changes:');
            
            foreach ($historyData as $domain => $data) {
                if (!empty($data['status_changes'])) {
                    $this->line("• {$domain}:");
                    foreach ($data['status_changes'] as $change) {
                        $icon = $change['to'] === 'listed' ? '🔴' : '🟢';
                        $this->line("  {$icon} {$change['date']}: {$change['from']} → {$change['to']}");
                    }
                }
            }
        }
    }
}