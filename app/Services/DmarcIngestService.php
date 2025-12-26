<?php

namespace App\Services;

use App\Models\DmarcIngest;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Http;
use Webklex\IMAP\Facades\Client;

class DmarcIngestService
{
    /** Allowed mime/types and extensions */
    private array $allowedMimes = [
        'application/zip',
        'application/x-zip-compressed',
        'application/x-zip',
        'text/xml',
        'application/xml'
    ];
    
    private array $allowedExt = ['zip', 'xml', 'gz'];

    public function fetchAndStore(int $max = 50): int
    {
        if (!config('imap.enabled', true)) {
            // webklex doesn't use this flag—just a sanity check
        }

        $client = Client::account('dmarc');
        $client->connect();

        $inbox = $client->getFolder('INBOX');

        // unread only to avoid reprocessing; adjust if needed
        $messages = $inbox->messages()->unseen()->get();

        $storedCount = 0;

        foreach ($messages as $message) {
            $messageId = $message->getMessageId() ?: null;

            foreach ($message->getAttachments() as $attachment) {
                // basic gating on ext/mime
                $ext = strtolower(pathinfo($attachment->getName(), PATHINFO_EXTENSION));
                $mime = $attachment->getMimeType();

                if (!$this->isAllowed($ext, $mime)) {
                    continue;
                }

                $content = $attachment->getContent();
                $sha1 = sha1($content);

                // dedupe on message + sha1
                $exists = DmarcIngest::where('message_id', $messageId)
                    ->where('attachment_sha1', $sha1)
                    ->exists();

                if ($exists) {
                    continue;
                }

                // store file
                $dir = trim(config('filesystems.dmarc_dir', env('DMARC_STORAGE_DIR', 'dmarc')), '/');
                $fileName = date('Ymd_His') . '_' . $sha1 . '.' . $ext;
                $path = $dir . '/' . $fileName;
                Storage::disk('local')->put($path, $content);

                $ingest = DmarcIngest::create([
                    'message_id' => $messageId,
                    'attachment_name' => $attachment->getName(),
                    'attachment_sha1' => $sha1,
                    'mime' => $mime,
                    'stored_path' => $path,
                    'size_bytes' => strlen($content),
                    'status' => 'stored',
                ]);

                // Queue job to process the report
                try {
                    \App\Jobs\ProcessDmarcReport::dispatch($ingest);
                    $ingest->update(['status' => 'queued']);
                } catch (\Throwable $e) {
                    Log::error('DMARC job dispatch failed', ['id' => $ingest->id, 'e' => $e->getMessage()]);
                    // Try forwarding as fallback
                    try {
                        $this->forward($ingest);
                        $ingest->update(['status' => 'forwarded']);
                    } catch (\Throwable $e2) {
                        Log::error('DMARC forward failed', ['id' => $ingest->id, 'e' => $e2->getMessage()]);
                        $ingest->update(['status' => 'failed', 'error' => $e2->getMessage()]);
                    }
                }

                $storedCount++;
                if ($storedCount >= $max) {
                    break 2; // stop both loops
                }
            }

            // mark message seen AFTER processing
            $message->setFlag('Seen');
        }

        return $storedCount;
    }

    private function isAllowed(string $ext, ?string $mime): bool
    {
        if (in_array($ext, $this->allowedExt, true)) {
            return true;
        }
        if ($mime && in_array(strtolower($mime), $this->allowedMimes, true)) {
            return true;
        }
        return false;
    }

    private function forward(DmarcIngest $ingest): void
    {
        $url = trim((string) env('DMARC_FORWARD_URL', ''));

        if ($url === '') {
            // optional: dispatch a Job instead
            // dispatch(new \App\Jobs\ProcessDmarcAttachment($ingest->id));
            return;
        }

        $absolutePath = storage_path('app/' . $ingest->stored_path);

        $headers = [];
        $token = env('DMARC_FORWARD_TOKEN');
        if ($token) {
            $headers['Authorization'] = 'Bearer ' . $token;
        }

        $response = Http::withHeaders($headers)
            ->attach('file', file_get_contents($absolutePath), basename($absolutePath))
            ->post($url, [
                'message_id' => $ingest->message_id,
                'sha1' => $ingest->attachment_sha1,
                'original' => $ingest->attachment_name,
                'mime' => $ingest->mime,
            ]);

        if (!$response->successful()) {
            throw new \RuntimeException('Forward HTTP ' . $response->status() . ' ' . $response->body());
        }
    }
}
