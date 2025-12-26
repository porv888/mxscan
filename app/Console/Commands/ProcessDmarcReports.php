<?php

namespace App\Console\Commands;

use App\Jobs\DetectDmarcSpikes;
use App\Jobs\ProcessDmarcReport;
use App\Models\DmarcIngest;
use App\Models\Domain;
use App\Services\DmarcIngestService;
use Illuminate\Console\Command;

class ProcessDmarcReports extends Command
{
    /**
     * The name and signature of the console command.
     */
    protected $signature = 'dmarc:process 
                            {--fetch : Fetch new reports from mailbox}
                            {--parse : Parse stored reports}
                            {--detect : Run spike detection}
                            {--all : Run all steps}
                            {--limit=50 : Maximum reports to process}';

    /**
     * The console command description.
     */
    protected $description = 'Process DMARC aggregate reports';

    /**
     * Execute the console command.
     */
    public function handle(DmarcIngestService $ingestService): int
    {
        $runAll = $this->option('all');
        $limit = (int) $this->option('limit');

        // Step 1: Fetch new reports from mailbox
        if ($runAll || $this->option('fetch')) {
            $this->info('Fetching DMARC reports from mailbox...');
            
            try {
                $fetched = $ingestService->fetchAndStore($limit);
                $this->info("Fetched {$fetched} new report(s)");
            } catch (\Throwable $e) {
                $this->error('Failed to fetch reports: ' . $e->getMessage());
            }
        }

        // Step 2: Parse stored reports
        if ($runAll || $this->option('parse')) {
            $this->info('Processing stored reports...');
            
            $pending = DmarcIngest::where('status', 'stored')
                ->orWhere('status', 'forwarded')
                ->limit($limit)
                ->get();

            $this->info("Found {$pending->count()} report(s) to process");

            foreach ($pending as $ingest) {
                ProcessDmarcReport::dispatch($ingest);
                $this->line("  Queued: {$ingest->attachment_name}");
            }
        }

        // Step 3: Run spike detection
        if ($runAll || $this->option('detect')) {
            $this->info('Running spike detection...');
            
            $domains = Domain::whereNotNull('dmarc_last_report_at')
                ->where('dmarc_last_report_at', '>=', now()->subDays(2))
                ->get();

            $this->info("Checking {$domains->count()} domain(s) for spikes");

            foreach ($domains as $domain) {
                DetectDmarcSpikes::dispatch($domain);
                $this->line("  Queued spike detection: {$domain->domain}");
            }
        }

        $this->info('Done.');
        return Command::SUCCESS;
    }
}
