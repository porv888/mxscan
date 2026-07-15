<?php

namespace App\Jobs;

use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistScanOrchestrator;
use App\Domain\EmailSecurity\Checks\Blacklist\Support\BlacklistAnalysisReader;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Domain\EmailSecurity\Support\ScanPayloadBuilder;
use App\Models\Domain;
use App\Models\Scan;
use App\Notifications\BlacklistAlert;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

class RunBlacklistScan implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public function __construct(
        public int $domainId,
    ) {
    }

    public function handle(BlacklistScanOrchestrator $orchestrator): void
    {
        $domain = Domain::query()->find($this->domainId);
        if ($domain === null) {
            return;
        }

        $scan = Scan::create([
            'domain_id' => $domain->id,
            'user_id' => $domain->user_id,
            'type' => 'blacklist',
            'status' => 'running',
            'progress_pct' => 0,
            'started_at' => now(),
        ]);

        try {
            $context = CheckContextDTO::fromExecution(
                $domain,
                $scan,
                new ScanOptionsDTO(dns: false, spf: false, blacklist: true),
            );

            $execution = $orchestrator->run($scan, $context);
            $payload = $execution['payload'];
            $facts = BlacklistAnalysisReader::facts($payload);

            $scan->update([
                'status' => 'finished',
                'progress_pct' => 100,
                'result_json' => ['blacklist' => $payload],
                'facts_json' => $facts,
                'finished_at' => now(),
            ]);

            $domain->update([
                'blacklist_status' => $facts['blacklist_status'] ?? 'not-checked',
                'blacklist_count' => $facts['blacklist_count'] ?? 0,
            ]);

            if (($facts['blacklist_is_listed'] ?? false) === true) {
                $user = $domain->user;
                if ($user !== null) {
                    $user->notify(new BlacklistAlert($domain, $scan, collect($scan->blacklistResults)));
                }
            }
        } catch (\Throwable $e) {
            Log::error('RunBlacklistScan failed', [
                'domain_id' => $domain->id,
                'error' => $e->getMessage(),
            ]);

            $scan->update([
                'status' => 'failed',
                'finished_at' => now(),
            ]);
        }
    }
}
