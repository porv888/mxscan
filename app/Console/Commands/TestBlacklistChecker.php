<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Services\BlacklistChecker;
use App\Models\Scan;
use App\Models\Domain;
use App\Models\User;

class TestBlacklistChecker extends Command
{
    /**
     * The name and signature of the console command.
     */
    protected $signature = 'blacklist:test {domain} {--user-id=1}';

    /**
     * The console command description.
     */
    protected $description = 'Test the blacklist checker with a specific domain';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $domainName = $this->argument('domain');
        $userId = $this->option('user-id');

        $this->info("Testing blacklist checker for domain: {$domainName}");

        // Create a test scan
        $user = User::find($userId);
        if (!$user) {
            $this->error("User with ID {$userId} not found");
            return 1;
        }

        // Find or create domain
        $domain = Domain::firstOrCreate([
            'domain' => $domainName,
            'user_id' => $userId,
        ]);

        // Create a test scan
        $scan = Scan::create([
            'domain_id' => $domain->id,
            'user_id' => $userId,
            'status' => 'running',
        ]);

        $this->info("Created test scan: {$scan->id}");

        // Run blacklist check
        $checker = new BlacklistChecker();
        
        $this->info("Checking blacklist status...");
        $results = $checker->checkDomain($scan, $domainName);
        
        $this->info("Blacklist check completed. Results:");
        
        // Display results
        $summary = $checker->getScanSummary($scan);
        
        $this->table(
            ['Metric', 'Value'],
            [
                ['Total Checks', $summary['total_checks']],
                ['Listed Count', $summary['listed_count']],
                ['OK Count', $summary['ok_count']],
                ['Unique IPs', $summary['unique_ips']],
                ['Providers Checked', $summary['providers_checked']],
                ['Is Clean', $summary['is_clean'] ? 'Yes' : 'No'],
            ]
        );

        if ($results) {
            $this->info("\nDetailed Results:");
            
            foreach ($results as $result) {
                $status = $result->isListed() ? '❌ LISTED' : '✅ OK';
                $this->line("{$result->ip_address} - {$result->provider}: {$status}");
                
                if ($result->isListed() && $result->message) {
                    $this->line("  Reason: {$result->message}");
                }
                if ($result->removal_url) {
                    $this->line("  Removal: {$result->removal_url}");
                }
            }
        }

        // Clean up test scan
        $scan->delete();
        $this->info("\nTest scan cleaned up.");

        return 0;
    }
}