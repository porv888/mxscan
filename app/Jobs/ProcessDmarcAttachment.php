<?php

namespace App\Jobs;

use App\Models\DmarcIngest;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;

class ProcessDmarcAttachment implements ShouldQueue
{
    use InteractsWithQueue, Queueable, SerializesModels;

    /**
     * Create a new job instance.
     */
    public function __construct(public int $ingestId)
    {
        //
    }

    /**
     * Execute the job.
     */
    public function handle(): void
    {
        $ingest = DmarcIngest::findOrFail($this->ingestId);
        $absolutePath = storage_path('app/' . $ingest->stored_path);

        // TODO: call your internal DMARC parser service here.
        // On success:
        $ingest->update(['status' => 'parsed']);
        // On failure: throw exception (will retry), or set failed status.
    }
}
