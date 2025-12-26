<?php

namespace App\Jobs;

use App\Models\DmarcIngest;
use App\Services\Dmarc\DmarcReportProcessor;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

class ProcessDmarcReport implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public int $tries = 3;
    public int $backoff = 60;

    public function __construct(public DmarcIngest $ingest)
    {
    }

    /**
     * Execute the job.
     */
    public function handle(DmarcReportProcessor $processor): void
    {
        Log::info('ProcessDmarcReport: Starting', ['ingest_id' => $this->ingest->id]);

        try {
            $success = $processor->processIngest($this->ingest);

            if ($success) {
                Log::info('ProcessDmarcReport: Completed successfully', [
                    'ingest_id' => $this->ingest->id,
                ]);
            } else {
                Log::warning('ProcessDmarcReport: Processing returned false', [
                    'ingest_id' => $this->ingest->id,
                ]);
            }
        } catch (\Throwable $e) {
            Log::error('ProcessDmarcReport: Failed', [
                'ingest_id' => $this->ingest->id,
                'error' => $e->getMessage(),
            ]);

            throw $e;
        }
    }

    /**
     * Handle a job failure.
     */
    public function failed(\Throwable $exception): void
    {
        Log::error('ProcessDmarcReport job failed permanently', [
            'ingest_id' => $this->ingest->id,
            'error' => $exception->getMessage(),
        ]);

        $this->ingest->update([
            'status' => 'failed',
            'error' => 'Job failed: ' . $exception->getMessage(),
        ]);
    }
}
