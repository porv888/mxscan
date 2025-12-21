<?php

namespace App\Support;

use Carbon\Carbon;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class RdapClient
{
    /**
     * Tries RDAP first; returns expiry date (UTC) or null.
     * RDAP JSON commonly contains events with eventAction "expiration".
     * Fallback WHOIS parser is optional.
     */
    public function getDomainExpiry(string $domain): ?Carbon
    {
        $domain = strtolower($domain);

        // 1) RDAP (generic aggregator or registry RDAP; both return JSON)
        // Use a generic RDAP gateway; keep timeout tight.
        try {
            $resp = Http::timeout(8)->acceptJson()->get("https://rdap.org/domain/{$domain}");
            
            if ($resp->ok()) {
                $json = $resp->json();
                
                if (is_array($json) && !empty($json['events'])) {
                    foreach ($json['events'] as $ev) {
                        if (($ev['eventAction'] ?? '') === 'expiration' && !empty($ev['eventDate'])) {
                            Log::debug("RDAP found expiry for {$domain}: {$ev['eventDate']}");
                            return Carbon::parse($ev['eventDate'])->utc();
                        }
                    }
                }
            }
        } catch (\Exception $e) {
            Log::debug("RDAP failed for {$domain}: {$e->getMessage()}");
        }

        // 2) Optional WHOIS fallback (very best-effort; varies by TLD)
        // Requires shell whois installed OR skip if you don't want this.
        if ($this->isWhoisAvailable()) {
            return $this->getWhoisExpiry($domain);
        }

        return null;
    }

    /**
     * Check if WHOIS command is available.
     */
    protected function isWhoisAvailable(): bool
    {
        static $available = null;
        
        if ($available === null) {
            $available = !empty(shell_exec('which whois 2>/dev/null'));
        }
        
        return $available;
    }

    /**
     * Fallback WHOIS parser for domains where RDAP isn't available.
     */
    protected function getWhoisExpiry(string $domain): ?Carbon
    {
        try {
            $out = @shell_exec('whois ' . escapeshellarg($domain) . ' 2>/dev/null');
            
            if (!$out) {
                return null;
            }

            // Common patterns (add more as needed):
            $patterns = [
                '/Registry Expiry Date:\s*([0-9T:\-\.Z]+)/i',
                '/Registrar Registration Expiration Date:\s*([0-9T:\-\.Z]+)/i',
                '/Expiry Date:\s*([0-9\-:TZ\.]+)/i',
                '/Expiration Date:\s*([0-9\-:TZ\.]+)/i',
                '/paid\-till:\s*([0-9\.\- :]+)/i', // .ru example
                '/expire:\s*([0-9\-]+)/i', // some ccTLDs
            ];

            foreach ($patterns as $rx) {
                if (preg_match($rx, $out, $m)) {
                    try {
                        $date = Carbon::parse(trim($m[1]))->utc();
                        Log::debug("WHOIS found expiry for {$domain}: {$date->toDateString()}");
                        return $date;
                    } catch (\Throwable $e) {
                        Log::debug("Failed to parse WHOIS date for {$domain}: {$m[1]}");
                    }
                }
            }
        } catch (\Exception $e) {
            Log::debug("WHOIS failed for {$domain}: {$e->getMessage()}");
        }

        return null;
    }
}
