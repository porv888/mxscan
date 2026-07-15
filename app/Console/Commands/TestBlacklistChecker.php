<?php

namespace App\Console\Commands;

use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistScanOrchestrator;
use App\Domain\EmailSecurity\Checks\Blacklist\Support\BlacklistAnalysisReader;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Models\Scan;
use Illuminate\Console\Command;

class TestBlacklistChecker extends Command
{
    protected $signature = 'blacklist:test {domain}';
    protected $description = 'Test native blacklist checking for a domain';

    public function handle(BlacklistScanOrchestrator $orchestrator): int
    {
        $domainName = (string) $this->argument('domain');
        $scan = Scan::create([
            'status' => 'running',
            'progress_pct' => 0,
        ]);

        $context = new CheckContextDTO(
            domainName: $domainName,
            domainId: null,
            scanId: $scan->id,
            scanType: 'blacklist',
            enabledServices: ['dns' => false, 'spf' => false, 'blacklist' => true],
            environment: app()->environment(),
            correlationId: (string) $scan->id,
            executedAt: now()->toIso8601String(),
        );

        $execution = $orchestrator->run($scan, $context);
        $payload = $execution['payload'];
        $facts = BlacklistAnalysisReader::facts($payload);

        $this->info('Reputation: ' . ($facts['blacklist_reputation_status'] ?? 'unknown'));
        $this->info('Usable results: ' . ($facts['blacklist_usable_results'] ?? 0));
        $this->info('Listed results: ' . ($facts['blacklist_listed_results'] ?? 0));
        $this->line(json_encode($payload['analysis'] ?? [], JSON_PRETTY_PRINT));

        return self::SUCCESS;
    }
}
