<?php

namespace App\Console\Commands;

use App\Models\DeliveryMonitor;
use App\Models\DeliveryCheck;
use App\Services\EmailAuthEvaluator;
use App\Support\SubaddressToken;
use Illuminate\Console\Command;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Log;
use Webklex\IMAP\Facades\Client;

class MonitorCollectCommand extends Command
{
    protected $signature = 'monitor:collect {--days=7} {--mark-seen=1} {--limit=0} {--debug=1}';
    protected $description = 'Collect monitor emails from INBOX and all INBOX.* subfolders';

    public function handle(): int
    {
        $sinceDays = (int)$this->option('days');
        $markSeen  = (bool)$this->option('mark-seen');
        $limit     = (int)$this->option('limit');
        $debug     = (bool)$this->option('debug');

        try {
            $client = Client::account(config('imap.default', 'monitor'));
            $client->connect();
        } catch (\Throwable $e) {
            $this->error('IMAP connection failed: ' . $e->getMessage());
            Log::error('[monitor:collect] Connection failed', ['error' => $e->getMessage()]);
            return self::FAILURE;
        }

        // Build flat list of all folders that start with INBOX
        $all = $client->getFolders(false); // non-recursive
        $folders = $this->flattenFolders($all);

        // Filter only INBOX + subfolders (support both . and / delimiters)
        $folders = array_values(array_filter($folders, function ($f) {
            $name = $f->path;
            return $name === 'INBOX' || preg_match('#^INBOX[./]#', $name);
        }));

        $since = Carbon::now()->subDays($sinceDays);
        $totalFolders = count($folders);
        $totalMsgs = 0;
        $matched = 0;

        if ($debug) {
            $this->info("Scanning $totalFolders folder(s) since " . $since->toDateTimeString());
        }

        foreach ($folders as $folder) {
            try {
                // Using query builder for reliability
                $query = $folder->query()->since($since);

                // Don't restrict to UNSEEN - we want to process all messages in time window
                // If you want only unseen: $query->unseen();

                if ($limit > 0) {
                    $query->limit($limit);
                }

                $messages = $query->get();
                $count = $messages->count();
                $totalMsgs += $count;

                if ($debug) {
                    $this->line(sprintf("- %s: %d msg(s)", $folder->path, $count));
                }

                foreach ($messages as $msg) {
                    try {
                        // Basic fields (handle Webklex v6 Attribute objects)
                        $uid     = $msg->getUid();
                        $subjectRaw = $msg->getSubject();
                        $subject = is_object($subjectRaw) && method_exists($subjectRaw, '__toString') ? (string)$subjectRaw : ($subjectRaw ?? '');
                        $from    = optional($msg->getFrom()[0] ?? null)->mail ?? '';
                        $date    = optional($msg->getDate())->toString() ?? '';

                        // Extract token from folder name (INBOX.TOKEN format)
                        $token = null;
                        if (preg_match('#^INBOX[./](.+)$#', $folder->path, $m)) {
                            $token = $m[1];
                        }

                        $matchResult = $this->processMessage($token, $subject, $from, $date, $msg, $debug);
                        $matched += $matchResult;

                        if ($markSeen) {
                            try {
                                $msg->setFlag('Seen');
                            } catch (\Throwable $e) {
                                if ($debug) {
                                    $this->warn("Could not mark message as seen: " . $e->getMessage());
                                }
                            }
                        }
                    } catch (\Throwable $e) {
                        if ($debug) {
                            $this->warn("Error processing message in {$folder->path}: " . $e->getMessage());
                        }
                        Log::warning('[monitor:collect] Message processing error', [
                            'folder' => $folder->path,
                            'error' => $e->getMessage(),
                        ]);
                        continue;
                    }
                }
            } catch (\Throwable $e) {
                if ($debug) {
                    $this->warn("Error processing folder {$folder->path}: " . $e->getMessage());
                }
                Log::warning('[monitor:collect] Folder processing error', [
                    'folder' => $folder->path,
                    'error' => $e->getMessage(),
                ]);
                continue;
            }
        }

        $summary = "Total: Processed {$totalMsgs} emails across all INBOX folders, matched {$matched} monitors.";
        $this->info($summary);
        Log::info('[monitor:collect] ' . $summary);

        return self::SUCCESS;
    }

    /**
     * Recursively flatten folder tree
     */
    private function flattenFolders($folders): array
    {
        $out = [];
        foreach ($folders as $f) {
            $out[] = $f;
            if ($f->hasChildren()) {
                foreach ($this->flattenFolders($f->children) as $c) {
                    $out[] = $c;
                }
            }
        }
        return $out;
    }

    /**
     * Process a single message and store delivery check
     */
    private function processMessage(?string $token, string $subject, string $from, string $date, $msg, bool $debug): int
    {
        if (!$token) {
            // Try to extract token from To header as fallback
            $toAddr = optional($msg->getTo()[0] ?? null)->mail ?? '';
            if (preg_match('/^monitor\+([A-Za-z0-9._+=-]+)@mxscan\.me$/i', $toAddr, $m)) {
                $token = $m[1];
            }
            
            if (!$token) {
                return 0;
            }
        }

        // Try to find monitor by token directly first (for folder-based tokens)
        $monitor = DeliveryMonitor::where('token', $token)
            ->where('status', 'active')
            ->first();

        // If not found, try parsing as encoded token
        if (!$monitor) {
            $monitorId = SubaddressToken::parse($token, config('app.key'));
            if ($monitorId) {
                $monitor = DeliveryMonitor::find($monitorId);
            }
        }

        if (!$monitor || $monitor->status !== 'active') {
            if ($debug) {
                Log::debug('[monitor:collect] Monitor not found or inactive', [
                    'token' => $token,
                ]);
            }
            return 0;
        }

        // Extract message details (handle Webklex v6 Attribute objects)
        $messageIdRaw = $msg->getMessageId();
        $messageId = null;
        if ($messageIdRaw) {
            $messageId = is_object($messageIdRaw) && method_exists($messageIdRaw, '__toString') ? (string)$messageIdRaw : $messageIdRaw;
            $messageId = trim($messageId, '<>');
        }
        $toAddr = optional($msg->getTo()[0] ?? null)->mail ?? "monitor+{$token}@mxscan.me";
        
        // Check if already processed
        if ($messageId && DeliveryCheck::where('message_id', $messageId)
            ->where('delivery_monitor_id', $monitor->id)
            ->exists()) {
            if ($debug) {
                Log::debug('[monitor:collect] Duplicate message_id', ['message_id' => $messageId]);
            }
            return 0;
        }

        // Parse authentication results from headers using EmailAuthEvaluator
        $rawHeaders = $msg->getHeader()->raw ?? '';
        $rawBody = $msg->getHTMLBody() ?? $msg->getTextBody() ?? '';
        
        // Use EmailAuthEvaluator
        $evaluator = app(EmailAuthEvaluator::class);
        $authResult = null;
        try {
            $authResult = $evaluator->evaluate([
                'raw_headers'   => $rawHeaders,
                'raw_body'      => $rawBody,
                'header_from'   => $from,
                'envelope_from' => $from,
            ]);
            
            if ($debug) {
                Log::info('[monitor:collect] Auth evaluation result', [
                    'monitor_id' => $monitor->id,
                    'has_result' => $authResult !== null,
                    'spf_pass' => $authResult['spf']['pass'] ?? 'missing',
                    'dkim_pass' => $authResult['dkim']['pass'] ?? 'missing',
                    'dmarc_pass' => $authResult['dmarc']['pass'] ?? 'missing',
                    'has_body' => !empty($rawBody),
                ]);
            }
        } catch (\Throwable $e) {
            if ($debug) {
                Log::error('[monitor:collect] Auth evaluation failed', [
                    'monitor_id' => $monitor->id,
                    'error' => $e->getMessage(),
                    'trace' => $e->getTraceAsString(),
                ]);
            }
        }
        
        // Extract pass/fail from auth result
        $ar = [
            'spf' => $authResult['spf']['pass'] ?? null,
            'dkim' => $authResult['dkim']['pass'] ?? null,
            'dmarc' => $authResult['dmarc']['pass'] ?? null,
        ];
        $authMeta = $authResult ? json_encode($authResult) : null;
        
        // Calculate TTI
        $receivedAt = now();
        $ttiMs = null;
        if ($msg->getDate()) {
            try {
                $sentDate = Carbon::parse($msg->getDate());
                $ttiMs = max(0, $receivedAt->diffInMilliseconds($sentDate));
            } catch (\Throwable $e) {
                // Ignore date parsing errors
            }
        }

        // Determine verdict
        $ttiThreshold = config('monitoring.tti_threshold_ms', 900000);
        $verdict = 'ok';
        if ($ar['spf'] === false || $ar['dkim'] === false || $ar['dmarc'] === false) {
            $verdict = 'incident';
        } elseif ($ttiMs !== null && $ttiMs > $ttiThreshold) {
            $verdict = 'warning';
        }

        // Store delivery check
        try {
            DeliveryCheck::create([
                'delivery_monitor_id' => $monitor->id,
                'message_id'          => $messageId,
                'received_at'         => $receivedAt,
                'from_addr'           => $from,
                'to_addr'             => $toAddr,
                'subject'             => $subject,
                'spf_pass'            => $ar['spf'],
                'dkim_pass'           => $ar['dkim'],
                'dmarc_pass'          => $ar['dmarc'],
                'tti_ms'              => $ttiMs,
                'mx_host'             => null,
                'mx_ip'               => null,
                'verdict'             => $verdict,
                'raw_headers'         => $this->compactHeaders($rawHeaders),
                'auth_meta'           => $authMeta,
            ]);

            $monitor->update(['last_check_at' => now()]);

            if ($debug) {
                $this->line("  ✓ Stored check for monitor #{$monitor->id}: {$from} -> {$toAddr} (verdict: {$verdict})");
            }

            return 1;
        } catch (\Illuminate\Database\QueryException $e) {
            // Handle duplicate message_id (unique constraint violation)
            if ($e->getCode() == 23000) {
                if ($debug) {
                    Log::debug('[monitor:collect] Skipping duplicate message_id', ['message_id' => $messageId]);
                }
                return 0;
            }
            throw $e;
        }
    }

    /**
     * Extract authentication results from headers
     */
    private function extractAuthResults(string $raw): array
    {
        $out = ['spf' => null, 'dkim' => null, 'dmarc' => null];
        
        if (preg_match_all('/^Authentication-Results:\s*(.+?)(?=\r?\n(?:[^ \t]|$))/mis', $raw, $m)) {
            $line = implode(' ', $m[1]);
            
            foreach (['spf', 'dkim', 'dmarc'] as $k) {
                if (preg_match('/\b' . $k . '=([a-z]+)/i', $line, $mm)) {
                    $result = strtolower($mm[1]);
                    $out[$k] = ($result === 'pass') ? true : (($result === 'none') ? null : false);
                }
            }
        }
        
        return $out;
    }

    /**
     * Compact headers for storage (returns string, not array)
     */
    private function compactHeaders(string $raw): string
    {
        $lines = [];
        foreach (['Date', 'From', 'To', 'Subject', 'Message-ID', 'Authentication-Results', 'Received'] as $h) {
            if (preg_match_all('/^' . preg_quote($h, '/') . ':\s*(.+?)(?=\r?\n(?:[^ \t]|$))/mis', $raw, $m)) {
                $lines[] = $h . ': ' . implode("\r\n\t", $m[1]);
            }
        }
        return implode("\r\n", $lines);
    }
}
