<?php

namespace App\Console\Commands;

use App\Services\Monitoring\ImapCollector;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

class CollectDeliveryMail extends Command
{
    protected $signature = 'monitoring:collect 
        {--all : Process ALL messages (not just UNSEEN)} 
        {--backfill : On first run of a folder (no cursor), process ALL once, then switch to UID-based}';
    protected $description = 'Collect incoming test mails from INBOX.* folders, parse, and store delivery checks';

    public function handle()
    {
        $cfg = config('monitoring.imap');

        // Validate configuration
        if (empty($cfg['host']) || empty($cfg['username']) || empty($cfg['password'])) {
            $this->error('IMAP configuration incomplete. Please set IMAP_HOST, IMAP_USERNAME, and IMAP_PASSWORD.');
            return Command::FAILURE;
        }

        // Add additional config
        $cfg['tti_threshold_ms'] = config('monitoring.tti_threshold_ms');
        $cfg['from_hint'] = config('monitoring.from_hint', '');

        // Create collector instance
        $collector = new ImapCollector($cfg);
        
        if ($this->getOutput()->isVerbose()) {
            $collector->setVerbose(true);
        }

        // Pass options to collector
        $collector->setOptions([
            'all' => $this->option('all'),
            'backfill' => $this->option('backfill'),
        ]);

        // Collect messages
        $result = $collector->collect();

        if (!$result['success']) {
            $this->error($result['error'] ?? 'Collection failed');
            return Command::FAILURE;
        }

        // Display results
        if ($this->getOutput()->isVerbose() && !empty($result['folders'])) {
            foreach ($result['folders'] as $folderStat) {
                $this->info("Folder '{$folderStat['folder']}': Processed {$folderStat['processed']} emails, matched {$folderStat['matched']} monitors.");
            }
        }

        $this->info("Total: Processed {$result['processed']} emails across all INBOX folders, matched {$result['matched']} monitors.");
        
        Log::info('Delivery monitoring collection completed', [
            'processed' => $result['processed'],
            'matched' => $result['matched'],
            'folders' => count($result['folders'] ?? []),
        ]);

        return Command::SUCCESS;
    }
}
