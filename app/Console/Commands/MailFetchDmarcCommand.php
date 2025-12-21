<?php

namespace App\Console\Commands;

use App\Services\DmarcIngestService;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

class MailFetchDmarcCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'mail:fetch-dmarc';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Fetch DMARC attachments from IMAP inbox and forward';

    /**
     * Execute the console command.
     */
    public function handle(DmarcIngestService $svc): int
    {
        if (!env('MAIL_POLL_ENABLED', true)) {
            $this->info('MAIL_POLL_ENABLED=false — skipping.');
            return self::SUCCESS;
        }

        // Leaky lock to prevent overlap
        $lock = Cache::lock('mail:fetch-dmarc', 60);
        if (!$lock->get()) {
            $this->info('Another fetch is in-flight, skipping.');
            return self::SUCCESS;
        }

        try {
            $max = (int) env('DMARC_MAX_ATTACHMENTS', 50);
            $count = $svc->fetchAndStore($max);
            $this->info("Fetched & forwarded {$count} attachment(s).");
            return self::SUCCESS;
        } catch (\Throwable $e) {
            Log::error('DMARC poller crashed: ' . $e->getMessage(), ['trace' => $e->getTraceAsString()]);
            $this->error($e->getMessage());
            return self::FAILURE;
        } finally {
            optional($lock)->release();
        }
    }
}
