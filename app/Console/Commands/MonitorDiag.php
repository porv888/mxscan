<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;

class MonitorDiag extends Command
{
    protected $signature = 'monitor:diag {--sample=1 : How many messages to sample per folder}';
    protected $description = 'IMAP diagnostics for monitor mailbox: connection, folders, counts, header samples';

    public function handle(): int
    {
        if (!function_exists('imap_open')) {
            $this->error('PHP IMAP extension not enabled for CLI. Enable ext-imap for the PHP version used by artisan.');
            return self::FAILURE;
        }

        // Try MONITOR_IMAP_* first, fallback to IMAP_* (existing config)
        $host  = env('MONITOR_IMAP_HOST') ?: env('IMAP_HOST', '127.0.0.1');
        $port  = (int) (env('MONITOR_IMAP_PORT') ?: env('IMAP_PORT', 993));
        $user  = env('MONITOR_IMAP_USER') ?: env('IMAP_USERNAME');
        $pass  = env('MONITOR_IMAP_PASS') ?: env('IMAP_PASSWORD');
        $encryption = env('IMAP_ENCRYPTION', 'ssl');
        
        // Build flags based on encryption setting
        if (env('MONITOR_IMAP_FLAGS')) {
            $flags = env('MONITOR_IMAP_FLAGS');
        } else {
            $flags = '/imap';
            if ($encryption === 'ssl') {
                $flags .= '/ssl';
            } elseif ($encryption === 'tls') {
                $flags .= '/tls';
            }
            $flags .= '/novalidate-cert';
        }

        if (!$user || !$pass) {
            $this->error('Set IMAP_USERNAME and IMAP_PASSWORD (or MONITOR_IMAP_USER/PASS) in .env');
            return self::FAILURE;
        }

        $base = '{'.$host.':'.$port.$flags.'}';
        $root = $base.'INBOX';
        $this->line("IMAP: $root as $user");

        $mbox = @imap_open($root, $user, $pass);
        if (!$mbox) {
            $this->error('IMAP open failed: '.imap_last_error());
            return self::FAILURE;
        }

        $folders = @imap_list($mbox, $base, 'INBOX*') ?: [];
        natsort($folders);

        $this->line("Folders (INBOX*):");
        foreach ($folders as $f) {
            $this->line('  - '.preg_replace('#^\Q'.$base.'\E#', '', $f));
        }
        if (empty($folders)) {
            $this->warn('No INBOX folders. Try MONITOR_IMAP_FLAGS=/imap/ssl or /imap/notls, or host=localhost.');
            imap_close($mbox);
            return self::SUCCESS;
        }

        $sampleN = max(0, (int)$this->option('sample'));

        foreach ($folders as $mailbox) {
            if (!@imap_reopen($mbox, $mailbox)) {
                $this->warn('Cannot open mailbox: '.$mailbox.' ('.imap_last_error().')');
                continue;
            }
            $short = preg_replace('#^\Q'.$base.'\E#', '', $mailbox);

            $all   = @imap_search($mbox, 'ALL')   ?: [];
            $unseen= @imap_search($mbox, 'UNSEEN')?: [];

            $this->line(sprintf("[%s] ALL=%d  UNSEEN=%d", $short, count($all), count($unseen)));

            // header samples
            if ($sampleN > 0 && !empty($all)) {
                $max = min($sampleN, count($all));
                for ($i = 0; $i < $max; $i++) {
                    $msgno = $all[$i];
                    $raw = @imap_fetchheader($mbox, $msgno) ?: '';
                    $hdr = @imap_headerinfo($mbox, $msgno);
                    $del = self::matchHeader($raw, 'Delivered-To');
                    $xot = self::matchHeader($raw, 'X-Original-To');
                    $to  = self::firstTo($hdr);
                    $sub = trim(mb_decode_mimeheader(@imap_utf8($hdr->subject ?? '')));
                    $this->line("  #$msgno  Delivered-To: ".($del ?: '-'));
                    $this->line("       X-Original-To: ".($xot ?: '-'));
                    $this->line("                 To: ".($to ?: '-'));
                    $this->line("           Subject: ".($sub ?: '-'));
                }
            }
        }

        imap_close($mbox);
        $this->line("Diagnostics complete.");
        return self::SUCCESS;
    }

    private static function matchHeader(string $raw, string $name): ?string
    {
        if (preg_match('/^'.preg_quote($name,'/').':\s*([^\r\n]+)/mi', $raw, $m)) {
            return self::normalizeEmail($m[1]);
        }
        return null;
    }

    private static function firstTo($hdr): ?string
    {
        if (!empty($hdr->to)) {
            $first = $hdr->to[0] ?? null;
            if ($first && isset($first->mailbox, $first->host)) {
                // Preserve local-part case, lowercase domain only
                return $first->mailbox . '@' . strtolower($first->host);
            }
        }
        return null;
    }

    private static function normalizeEmail(string $s): ?string
    {
        if (preg_match('/<([^>]+)>/', $s, $m)) $s = $m[1];
        $s = trim($s);

        // Basic email validation
        if (!filter_var($s, FILTER_VALIDATE_EMAIL)) {
            return null;
        }

        // Preserve local-part case, lowercase domain only
        [$local, $domain] = explode('@', $s, 2);
        return $local . '@' . strtolower($domain);
    }
}
