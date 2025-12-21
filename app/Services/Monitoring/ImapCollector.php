<?php

namespace App\Services\Monitoring;

use App\Models\DeliveryMonitor;
use App\Models\DeliveryCheck;
use App\Models\MonitorFolderPosition;
use App\Services\EmailAuthEvaluator;
use App\Support\SubaddressToken;
use Illuminate\Support\Facades\Log;

class ImapCollector
{
    protected $connection;
    protected $config;
    protected $verbose = false;
    protected $options = [];

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    /**
     * Helper: Convert value to string or null (handles arrays and objects)
     */
    private function strOrNull($v): ?string
    {
        if ($v === null) return null;
        if (is_object($v) && method_exists($v, '__toString')) return (string)$v;
        if (is_array($v)) return implode("\r\n", array_map('strval', $v));
        return (string)$v;
    }

    /**
     * Helper: Get first element if array, or string value
     */
    private function firstOrNull($v): ?string
    {
        if ($v === null) return null;
        if (is_array($v)) return isset($v[0]) ? (string)$v[0] : null;
        if (is_object($v) && method_exists($v, '__toString')) return (string)$v;
        return (string)$v;
    }

    /**
     * Enable verbose output
     */
    public function setVerbose(bool $verbose): self
    {
        $this->verbose = $verbose;
        return $this;
    }

    /**
     * Set collection options
     */
    public function setOptions(array $options): self
    {
        $this->options = $options;
        return $this;
    }

    /**
     * Connect to IMAP server
     */
    protected function connect(): bool
    {
        $mailboxRoot = "{" . $this->config['host'] . ":" . $this->config['port'] . "/imap/" . $this->config['encryption'] . "}";
        
        $this->connection = @imap_open($mailboxRoot, $this->config['username'], $this->config['password']);
        
        if (!$this->connection) {
            $error = imap_last_error();
            Log::error('IMAP connection failed for delivery monitoring', ['error' => $error]);
            return false;
        }

        return true;
    }

    /**
     * Disconnect from IMAP server
     */
    protected function disconnect(): void
    {
        if ($this->connection) {
            @imap_close($this->connection);
            $this->connection = null;
        }
    }

    /**
     * Get list of INBOX folders (INBOX and INBOX.*)
     */
    protected function getInboxFolders(): array
    {
        if (!$this->connection) {
            return [];
        }

        $mailboxRoot = "{" . $this->config['host'] . ":" . $this->config['port'] . "/imap/" . $this->config['encryption'] . "}";
        
        // List all folders
        $allFolders = imap_list($this->connection, $mailboxRoot, '*');
        
        if (!$allFolders) {
            return [];
        }

        $inboxFolders = [];
        
        foreach ($allFolders as $folder) {
            $folderName = str_replace($mailboxRoot, '', $folder);
            
            // Only process INBOX or INBOX.* folders
            if ($folderName === 'INBOX' || str_starts_with($folderName, 'INBOX.')) {
                $inboxFolders[] = [
                    'name' => $folderName,
                    'path' => $folder,
                ];
            }
        }

        return $inboxFolders;
    }

    /**
     * Process all INBOX folders
     */
    public function collect(): array
    {
        if (!$this->connect()) {
            return [
                'success' => false,
                'error' => 'Failed to connect to IMAP server',
                'processed' => 0,
                'matched' => 0,
            ];
        }

        $folders = $this->getInboxFolders();
        
        if (empty($folders)) {
            $this->disconnect();
            return [
                'success' => false,
                'error' => 'No INBOX folders found',
                'processed' => 0,
                'matched' => 0,
            ];
        }

        $totalProcessed = 0;
        $totalMatched = 0;
        $folderStats = [];

        foreach ($folders as $folderInfo) {
            try {
                $stats = $this->processFolder($folderInfo['name'], $folderInfo['path']);
                $totalProcessed += $stats['processed'];
                $totalMatched += $stats['matched'];
                
                if ($stats['processed'] > 0) {
                    $folderStats[] = [
                        'folder' => $folderInfo['name'],
                        'processed' => $stats['processed'],
                        'matched' => $stats['matched'],
                    ];
                }
            } catch (\Throwable $e) {
                Log::warning('Error processing folder', [
                    'folder' => $folderInfo['name'],
                    'error' => $e->getMessage(),
                ]);
                continue;
            }
        }

        $this->disconnect();

        return [
            'success' => true,
            'processed' => $totalProcessed,
            'matched' => $totalMatched,
            'folders' => $folderStats,
        ];
    }

    /**
     * Process a single folder
     */
    protected function processFolder(string $folderName, string $folderPath): array
    {
        // Open folder in read-write mode
        $folderConnection = @imap_open($folderPath, $this->config['username'], $this->config['password']);
        
        if (!$folderConnection) {
            Log::warning('Could not open folder', ['folder' => $folderName]);
            return ['processed' => 0, 'matched' => 0];
        }

        // Get folder position (last processed UID)
        $position = MonitorFolderPosition::getPosition($folderName);
        $lastUid = $position->last_uid;
        $hasCursor = $lastUid > 0;

        // Determine search criteria based on options and cursor state
        if ($this->options['all'] ?? false) {
            // Explicit override: process ALL messages
            $searchCriteria = 'ALL';
        } elseif ($hasCursor) {
            // NORMAL steady-state: Use UNSEEN instead of UID search for better compatibility
            // We'll filter by UID in the loop below
            $searchCriteria = 'UNSEEN';
        } else {
            // FIRST TIME for this folder:
            // - If backfill requested, ingest ALL once (good for historical load)
            // - Otherwise, only UNSEEN (current behavior)
            $searchCriteria = ($this->options['backfill'] ?? false) ? 'ALL' : 'UNSEEN';
        }

        if ($this->verbose) {
            Log::info("Folder '{$folderName}': Using search criteria '{$searchCriteria}' (hasCursor={$hasCursor}, lastUid={$lastUid})");
        }

        $messageNumbers = imap_search($folderConnection, $searchCriteria);

        if (!$messageNumbers) {
            imap_close($folderConnection);
            return ['processed' => 0, 'matched' => 0];
        }

        $processed = 0;
        $matched = 0;
        $maxUid = $lastUid;

        foreach ($messageNumbers as $msgNum) {
            try {
                // Get message UID
                $uid = imap_uid($folderConnection, $msgNum);
                
                // Skip if we've already processed this UID
                if ($uid <= $lastUid) {
                    continue;
                }

                $maxUid = max($maxUid, $uid);

                // Get message header
                $header = imap_headerinfo($folderConnection, $msgNum);
                if (!$header) {
                    continue;
                }

                // Extract original recipient
                $recipient = $this->extractOriginalRecipient($folderConnection, $msgNum, $header);
                
                if (!$recipient) {
                    // Mark as seen even if no recipient found
                    @imap_setflag_full($folderConnection, (string)$msgNum, "\\Seen");
                    continue;
                }

                // Parse token from recipient (try address first, then folder)
                $addrToken = $this->parseToken($recipient);
                
                // Fallback to folder name if no token in address
                $folderToken = null;
                if (!$addrToken && preg_match('/INBOX\.("?)([A-Za-z0-9=_-]+)\1$/i', $folderName, $f)) {
                    $folderToken = $f[2];
                }
                
                $token = $addrToken ?: $folderToken;
                
                if (!$token) {
                    Log::warning('monitor.match_failed', [
                        'folder' => $folderName,
                        'recipient' => $recipient,
                        'addr_token' => $addrToken,
                        'folder_token' => $folderToken,
                    ]);
                    @imap_setflag_full($folderConnection, (string)$msgNum, "\\Seen");
                    continue;
                }

                // Find monitor by token
                $monitorId = SubaddressToken::parse($token, config('app.key'));
                if (!$monitorId) {
                    Log::warning('monitor.token_decrypt_failed', [
                        'token' => $token,
                        'source' => $addrToken ? 'address' : 'folder',
                    ]);
                    @imap_setflag_full($folderConnection, (string)$msgNum, "\\Seen");
                    continue;
                }

                $monitor = DeliveryMonitor::find($monitorId);
                if (!$monitor || $monitor->status !== 'active') {
                    Log::warning('monitor.not_found_or_inactive', [
                        'monitor_id' => $monitorId,
                        'status' => $monitor->status ?? 'not_found',
                    ]);
                    @imap_setflag_full($folderConnection, (string)$msgNum, "\\Seen");
                    continue;
                }

                // Store the check
                $this->storeCheck($folderConnection, $msgNum, $header, $monitor, $recipient);
                $monitor->update(['last_check_at' => now()]);
                
                $matched++;
                $processed++;

                // Mark as seen and answered
                @imap_setflag_full($folderConnection, (string)$msgNum, "\\Seen \\Answered");

            } catch (\Throwable $e) {
                Log::warning('Error processing message', [
                    'folder' => $folderName,
                    'message' => $msgNum,
                    'error' => $e->getMessage(),
                ]);
                continue;
            }
        }

        // Update folder position
        if ($maxUid > $lastUid) {
            $position->updateLastUid($maxUid);
        }

        imap_close($folderConnection);

        return ['processed' => $processed, 'matched' => $matched];
    }

    /**
     * Extract original recipient from message headers
     * Priority: X-Original-To > Delivered-To > To
     * Note: Preserves case for token extraction (base64 is case-sensitive)
     */
    protected function extractOriginalRecipient($connection, int $msgNum, $header): ?string
    {
        $rawHeaders = imap_fetchheader($connection, $msgNum);

        // Try X-Original-To first
        if (preg_match('/^X-Original-To:\s*(.+)$/mi', $rawHeaders, $m)) {
            $addr = trim($m[1], " <>\"\t\r\n");
            if ($addr) {
                return $addr; // Preserve case for token parsing
            }
        }

        // Try Delivered-To
        if (preg_match('/^Delivered-To:\s*(.+)$/mi', $rawHeaders, $m)) {
            $addr = trim($m[1], " <>\"\t\r\n");
            if ($addr) {
                return $addr; // Preserve case for token parsing
            }
        }

        // Fallback to To header
        if (isset($header->to) && is_array($header->to) && count($header->to) > 0) {
            $first = $header->to[0];
            $mailbox = $first->mailbox ?? '';
            $host = $first->host ?? '';
            if ($mailbox && $host) {
                return $mailbox . '@' . $host; // Preserve case for token parsing
            }
        }

        return null;
    }

    /**
     * Parse token from email address
     * Expects: monitor+TOKEN@mxscan.me
     * Case-sensitive for local-part (token), case-insensitive for domain
     */
    protected function parseToken(string $email): ?string
    {
        // Normalize domain to lowercase for comparison
        $parts = explode('@', $email, 2);
        if (count($parts) !== 2) {
            return null;
        }
        
        [$localPart, $domain] = $parts;
        
        // Check domain (case-insensitive)
        if (strtolower($domain) !== 'mxscan.me') {
            return null;
        }
        
        // Extract token from local-part (case-sensitive)
        // Accept A-Z a-z 0-9 _ - + = . (common in base64/base64url/hash tokens)
        if (preg_match('/^monitor\+([A-Za-z0-9._+=-]+)$/', $localPart, $m)) {
            return $m[1]; // Preserve exact case
        }
        
        return null;
    }

    /**
     * Store a delivery check record
     */
    protected function storeCheck($connection, int $msgNum, $header, DeliveryMonitor $monitor, string $toAddr): void
    {
        // Get raw headers and body (preserve original formatting for DKIM)
        $rawHeaders = imap_fetchheader($connection, $msgNum);
        $rawBody = imap_body($connection, $msgNum);
        
        // Extract subject (handle Webklex v6 Attribute objects)
        $subject = '';
        if (isset($header->subject)) {
            $subjectRaw = $this->strOrNull($header->subject);
            $subject = $subjectRaw ? imap_utf8($subjectRaw) : '';
        }
        
        $fromObj = $header->from[0] ?? null;
        $from = $fromObj ? ($fromObj->mailbox . '@' . $fromObj->host) : null;

        // Optional from filter
        $hint = trim($this->config['from_hint'] ?? '');
        if ($hint !== '' && $from && stripos($from, $hint) === false) {
            return;
        }

        // Extract message ID (handle Webklex v6 Attribute objects)
        $msgId = null;
        if (isset($header->message_id)) {
            $msgId = $this->strOrNull($header->message_id);
            if ($msgId) {
                $msgId = trim($msgId, "<>");
            }
        }

        // Check if already processed
        if ($msgId && DeliveryCheck::where('message_id', $msgId)
            ->where('delivery_monitor_id', $monitor->id)
            ->exists()) {
            if ($this->verbose) {
                Log::debug('[monitor:collect] Duplicate message_id', ['message_id' => $msgId]);
            }
            return;
        }

        // Use EmailAuthEvaluator with new array signature
        $evaluator = app(EmailAuthEvaluator::class);
        try {
            $auth = $evaluator->evaluate([
                'raw_headers'   => $rawHeaders,
                'raw_body'      => $rawBody,
                'header_from'   => $from,
                'envelope_from' => $from, // Use From as fallback if Return-Path not available
            ]);
            
            // Log what we got back
            if ($this->verbose) {
                Log::info('collector.auth_result', [
                    'monitor_id' => $monitor->id,
                    'auth_is_null' => $auth === null,
                    'auth_is_array' => is_array($auth),
                    'auth_keys' => is_array($auth) ? array_keys($auth) : 'not_array',
                    'has_spf' => isset($auth['spf']),
                    'has_dkim' => isset($auth['dkim']),
                    'has_dmarc' => isset($auth['dmarc']),
                ]);
            }
        } catch (\Throwable $e) {
            Log::error('collector.auth_eval_failed', [
                'monitor_id' => $monitor->id,
                'from' => $from,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);
            // Use empty auth results as fallback
            $auth = [
                'spf' => ['pass' => null],
                'dkim' => ['pass' => null],
                'dmarc' => ['pass' => null],
                'metrics' => [],
                'analysis' => ['verdict' => 'warning'],
            ];
        }

        // Extract results with explicit checks (guaranteed to be boolean or null)
        $spfPass = array_key_exists('pass', $auth['spf'] ?? []) ? $auth['spf']['pass'] : null;
        $dkimPass = array_key_exists('pass', $auth['dkim'] ?? []) ? $auth['dkim']['pass'] : null;
        $dmarcPass = array_key_exists('pass', $auth['dmarc'] ?? []) ? $auth['dmarc']['pass'] : null;
        
        $metrics = $auth['metrics'] ?? [];
        $analysis = $auth['analysis'] ?? [];
        $mxHost = $analysis['mx_host'] ?? null;
        $mxIp = $analysis['mx_ip'] ?? null;
        $verdict = $analysis['verdict'] ?? 'ok';
        $ttiMs = $metrics['tti_ms'] ?? null;
        
        // Log what we extracted for debugging
        Log::info('collector.auth_extract', [
            'monitor_id' => $monitor->id,
            'auth_keys' => array_keys($auth),
            'spf_pass' => $spfPass,
            'dkim_pass' => $dkimPass,
            'dmarc_pass' => $dmarcPass,
            'has_spf_key' => isset($auth['spf']),
            'has_dkim_key' => isset($auth['dkim']),
            'has_dmarc_key' => isset($auth['dmarc']),
        ]);

        // Debug logging
        if ($this->verbose) {
            Log::info('auth-eval', [
                'monitor_id' => $monitor->id,
                'ip' => $mxIp,
                'header_from' => $from,
                'dkim_count' => $auth['dkim']['count'] ?? 0,
                'spf_pass' => $spfPass,
                'dkim_pass' => $dkimPass,
                'dmarc_pass' => $dmarcPass,
                'tti_ms' => $ttiMs,
                'verdict' => $verdict,
            ]);
        }

        // Prepare payload with proper type normalization
        $payload = [
            'delivery_monitor_id' => (int)$monitor->id,
            'message_id'          => $msgId ? (string)$msgId : null,
            'received_at'         => now(),
            'from_addr'           => $this->firstOrNull($from),
            'to_addr'             => $this->firstOrNull($toAddr),
            'subject'             => $this->strOrNull($subject),
            'spf_pass'            => $spfPass,
            'dkim_pass'           => $dkimPass,
            'dmarc_pass'          => $dmarcPass,
            'tti_ms'              => $ttiMs !== null ? (int)$ttiMs : null,
            'mx_host'             => $this->firstOrNull($mxHost),
            'mx_ip'               => $this->firstOrNull($mxIp),
            'verdict'             => (string)$verdict,
            'raw_headers'         => $this->strOrNull($rawHeaders),  // Must be TEXT string
            'raw_body'            => $this->strOrNull($rawBody),     // Must be TEXT string
            'auth_meta'           => $auth ?: null,
            'ar_raw'              => null, // Deprecated, evaluator doesn't use Authentication-Results
        ];
        
        // Debug: Log types before insert to identify array fields
        if ($this->verbose) {
            $types = [];
            foreach ($payload as $key => $value) {
                $type = gettype($value);
                if ($type === 'array' || $type === 'object') {
                    $types[$key] = $type . (is_array($value) ? ' ['.count($value).']' : '');
                }
            }
            if (!empty($types)) {
                Log::warning('Non-scalar fields detected before insert', [
                    'monitor_id' => $monitor->id,
                    'fields' => $types,
                ]);
            }
        }

        try {
            $deliveryCheck = DeliveryCheck::create($payload);

            // Clear monitor stats cache after successful insert
            \Illuminate\Support\Facades\Cache::forget("monitor:stats:{$monitor->id}");

            // Process incidents
            try {
                $incidentWriter = app(\App\Services\Monitoring\IncidentWriter::class);
                $incidentWriter->processCheck($deliveryCheck);
            } catch (\Throwable $e) {
                Log::error('incident.process_failed', [
                    'check_id' => $deliveryCheck->id,
                    'error' => $e->getMessage(),
                ]);
            }

            if ($this->verbose) {
                $spfStr = $spfPass === true ? 'pass' : ($spfPass === false ? 'fail' : 'none');
                $dkimStr = $dkimPass === true ? 'pass' : ($dkimPass === false ? 'fail' : 'none');
                $dmarcStr = $dmarcPass === true ? 'pass' : ($dmarcPass === false ? 'fail' : 'none');
                Log::info("Stored check for monitor #{$monitor->id}: {$from} -> {$toAddr} (verdict: {$verdict}, SPF: {$spfStr}, DKIM: {$dkimStr}, DMARC: {$dmarcStr})");
            }
        } catch (\Illuminate\Database\QueryException $e) {
            // Handle duplicate message_id (unique constraint violation)
            if ($e->getCode() == 23000) {
                Log::debug("Skipping duplicate message_id: {$msgId}");
                return;
            }
            throw $e;
        } catch (\Throwable $e) {
            // Log field types for debugging
            Log::error('delivery_checks.insert_failed', [
                'error' => $e->getMessage(),
                'types' => array_map(fn($v) => gettype($v), $payload),
                'monitor_id' => $monitor->id,
                'from' => $from,
            ]);
            // Don't throw - prevents loop spam
            return;
        }

        // Send notification if incident and not recently notified
        if ($verdict === 'incident') {
            $this->maybeNotifyIncident($monitor);
        }
    }

    /**
     * Extract Authentication-Results header (raw text for reference)
     */
    protected function extractAuthResultsHeader(string $raw): ?string
    {
        if (preg_match('/^Authentication-Results:\s*(.+?)(?=\r?\n(?:[^ \t]|$))/mis', $raw, $m)) {
            return trim($m[0]);
        }
        return null;
    }

    /**
     * Extract authentication results from headers (legacy method, kept for compatibility)
     */
    protected function extractAuthResults(string $raw): array
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
     * Compact headers for storage
     */
    protected function compactHeaders(string $raw): array
    {
        $lines = [];
        foreach (['Date', 'From', 'To', 'Subject', 'Message-ID', 'Authentication-Results', 'Received'] as $h) {
            if (preg_match_all('/^' . preg_quote($h, '/') . ':\s*(.+?)(?=\r?\n(?:[^ \t]|$))/mis', $raw, $m)) {
                $lines[$h] = $m[1];
            }
        }
        return $lines;
    }

    /**
     * Send notification if not recently notified
     */
    protected function maybeNotifyIncident(DeliveryMonitor $monitor): void
    {
        // Check if we've notified in the last hour
        if ($monitor->last_incident_notified_at && 
            $monitor->last_incident_notified_at->gt(now()->subHour())) {
            return;
        }

        // Update notification timestamp
        $monitor->update(['last_incident_notified_at' => now()]);

        // Send email notification
        try {
            $monitor->user->notify(new \App\Notifications\DeliveryIncidentAlert($monitor));
        } catch (\Exception $e) {
            Log::error('Failed to send delivery incident notification', [
                'monitor_id' => $monitor->id,
                'error' => $e->getMessage(),
            ]);
        }
    }
}
