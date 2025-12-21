<?php

namespace App\Console\Commands;

use App\Models\Domain;
use App\Models\SpfCheck as SpfCheckModel;
use App\Services\Spf\SpfResolver;
use Illuminate\Console\Command;

class SpfCheck extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'spf:check {domain : The domain to check SPF for}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Check SPF record for a domain and analyze DNS lookups';

    /**
     * Execute the console command.
     */
    public function handle(SpfResolver $spfResolver): int
    {
        $domainName = $this->argument('domain');
        
        $this->info("Checking SPF record for: {$domainName}");
        
        try {
            // Resolve SPF record
            $result = $spfResolver->resolve($domainName);
            
            // Find domain in database if it exists
            $domain = Domain::where('domain', $domainName)->first();
            
            // Create SPF check record
            $spfCheck = SpfCheckModel::create([
                'domain_id' => $domain?->id,
                'domain' => $domainName,
                'current_record' => $result->currentRecord,
                'lookups_used' => $result->lookupsUsed,
                'flattened_spf' => $result->flattenedSpf,
                'warnings' => $result->warnings,
                'resolved_ips' => $result->resolvedIps,
                'checked_at' => now(),
            ]);
            
            // Output results as JSON
            $this->line(json_encode([
                'domain' => $domainName,
                'current_record' => $result->currentRecord,
                'lookups_used' => $result->lookupsUsed,
                'flattened_spf' => $result->flattenedSpf,
                'warnings' => $result->warnings,
                'resolved_ips' => $result->resolvedIps,
                'checked_at' => $spfCheck->checked_at->toISOString(),
            ], JSON_PRETTY_PRINT));
            
            $this->info("SPF check completed and saved to database.");
            
            return Command::SUCCESS;
        } catch (\Exception $e) {
            $this->error("Failed to check SPF for {$domainName}: " . $e->getMessage());
            return Command::FAILURE;
        }
    }
}
