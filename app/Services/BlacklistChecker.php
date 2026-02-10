<?php

namespace App\Services;

use App\Models\BlacklistResult;
use App\Models\Scan;
use App\Notifications\BlacklistAlert;
use Illuminate\Support\Facades\Log;

class BlacklistChecker
{
    private int $concurrency;
    private int $timeoutMs;

    public function __construct(int $concurrency = 20, int $timeoutMs = 3000)
    {
        $this->concurrency = $concurrency;
        $this->timeoutMs = $timeoutMs;
    }

    /**
     * Get enabled RBL providers from configuration.
     */
    private function getRblProviders(): array
    {
        $providers = config('rbl.providers', []);
        
        // Filter only enabled providers
        return array_filter($providers, function ($provider) {
            return $provider['enabled'] ?? false;
        });
    }

    /**
     * Check all IPs for a domain against RBL providers (parallelized).
     */
    public function checkDomain(Scan $scan, string $domain): array
    {
        Log::info("Starting blacklist check for domain: {$domain}");
        
        $results = [];
        $ips = $this->getDomainIPs($domain);
        
        if (empty($ips)) {
            Log::warning("No IPs found for domain: {$domain}");
            return $results;
        }

        Log::info("Found IPs for {$domain}: " . implode(', ', $ips));

        // Build all lookup jobs
        $jobs = [];
        $providers = $this->getRblProviders();
        foreach ($ips as $ip) {
            $reversedIP = $this->reverseIP($ip);
            if (!$reversedIP) continue;

            foreach ($providers as $providerId => $provider) {
                $jobs[] = [
                    'ip' => $ip,
                    'provider' => $provider,
                    'provider_id' => $providerId,
                    'lookup_host' => $reversedIP . '.' . $provider['host'],
                ];
            }
        }

        // Execute lookups in parallel batches
        $lookupResults = $this->parallelDnsLookup($jobs);

        // Persist results
        foreach ($lookupResults as $lr) {
            $blacklistResult = BlacklistResult::create([
                'scan_id' => $scan->id,
                'provider' => $lr['provider']['name'],
                'ip_address' => $lr['ip'],
                'status' => $lr['listed'] ? 'listed' : 'ok',
                'message' => $lr['message'],
                'removal_url' => $lr['provider']['delist_url'] ?? null,
            ]);

            $results[] = $blacklistResult;
        }

        $listedCount = collect($results)->where('status', 'listed')->count();
        Log::info("Blacklist check completed for {$domain}: {$listedCount} listed out of " . count($results) . " checks");

        // Check if we should send alerts
        $this->checkForAlerts($scan, $results);

        return $results;
    }

    /**
     * Perform DNS lookups in parallel using curl_multi with DNS-over-HTTPS.
     */
    private function parallelDnsLookup(array $jobs): array
    {
        $results = [];
        $batches = array_chunk($jobs, $this->concurrency);

        foreach ($batches as $batch) {
            $mh = curl_multi_init();
            $handles = [];

            foreach ($batch as $idx => $job) {
                // Use Google Public DNS DoH to resolve A record
                $url = 'https://dns.google/resolve?name=' . urlencode($job['lookup_host']) . '&type=A';

                $ch = curl_init();
                curl_setopt_array($ch, [
                    CURLOPT_URL => $url,
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_TIMEOUT_MS => $this->timeoutMs,
                    CURLOPT_CONNECTTIMEOUT_MS => 1500,
                    CURLOPT_HTTPHEADER => ['Accept: application/dns-json'],
                    CURLOPT_FOLLOWLOCATION => true,
                    CURLOPT_SSL_VERIFYPEER => true,
                ]);

                curl_multi_add_handle($mh, $ch);
                $handles[$idx] = ['ch' => $ch, 'job' => $job];
            }

            // Execute all handles
            $running = null;
            do {
                curl_multi_exec($mh, $running);
                curl_multi_select($mh, 0.1);
            } while ($running > 0);

            // Collect results
            foreach ($handles as $idx => $h) {
                $job = $h['job'];
                $response = curl_multi_getcontent($h['ch']);
                $httpCode = curl_getinfo($h['ch'], CURLINFO_HTTP_CODE);
                curl_multi_remove_handle($mh, $h['ch']);
                curl_close($h['ch']);

                $listed = false;
                $message = null;

                if ($httpCode === 200 && $response) {
                    $data = json_decode($response, true);
                    if (isset($data['Answer']) && !empty($data['Answer'])) {
                        $listed = true;
                        $message = 'Listed on ' . $job['provider']['name'];
                    }
                }

                $results[] = [
                    'ip' => $job['ip'],
                    'provider' => $job['provider'],
                    'listed' => $listed,
                    'message' => $message,
                ];
            }

            curl_multi_close($mh);
        }

        return $results;
    }

    /**
     * Get all IPs for a domain (MX records + A record).
     */
    private function getDomainIPs(string $domain): array
    {
        $ips = [];

        try {
            // Get MX records and resolve to IPs
            $mxRecords = dns_get_record($domain, DNS_MX);
            if ($mxRecords) {
                foreach ($mxRecords as $mx) {
                    $mxIps = $this->resolveHostToIPs($mx['target']);
                    $ips = array_merge($ips, $mxIps);
                }
            }

            // Also check A record for the domain itself
            $aIps = $this->resolveHostToIPs($domain);
            $ips = array_merge($ips, $aIps);

        } catch (\Exception $e) {
            Log::error("Error resolving IPs for domain {$domain}: " . $e->getMessage());
        }

        return array_unique($ips);
    }

    /**
     * Resolve hostname to IP addresses.
     */
    private function resolveHostToIPs(string $hostname): array
    {
        $ips = [];

        try {
            // Get A records
            $aRecords = dns_get_record($hostname, DNS_A);
            if ($aRecords) {
                foreach ($aRecords as $record) {
                    $ips[] = $record['ip'];
                }
            }

            // Get AAAA records (IPv6)
            $aaaaRecords = dns_get_record($hostname, DNS_AAAA);
            if ($aaaaRecords) {
                foreach ($aaaaRecords as $record) {
                    $ips[] = $record['ipv6'];
                }
            }
        } catch (\Exception $e) {
            Log::error("Error resolving hostname {$hostname}: " . $e->getMessage());
        }

        return $ips;
    }

    /**
     * Reverse an IP address for RBL lookup.
     */
    private function reverseIP(string $ip): ?string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            // IPv4: reverse octets
            $parts = explode('.', $ip);
            return implode('.', array_reverse($parts));
        } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            // IPv6: more complex reversal (not implemented for simplicity)
            // Most RBLs focus on IPv4 anyway
            return null;
        }

        return null;
    }

    /**
     * Get summary of blacklist results for a scan.
     */
    public function getScanSummary(Scan $scan): array
    {
        $results = BlacklistResult::where('scan_id', $scan->id)->get();
        
        $summary = [
            'total_checks' => $results->count(),
            'listed_count' => $results->where('status', 'listed')->count(),
            'ok_count' => $results->where('status', 'ok')->count(),
            'unique_ips' => $results->pluck('ip_address')->unique()->count(),
            'providers_checked' => $results->pluck('provider')->unique()->count(),
        ];

        $summary['is_clean'] = $summary['listed_count'] === 0;
        
        return $summary;
    }

    /**
     * Check if alerts should be sent for blacklist results.
     */
    private function checkForAlerts(Scan $scan, array $results): void
    {
        $listedResults = collect($results)->where('status', 'listed');
        
        if ($listedResults->isEmpty()) {
            return; // No blacklists found, no alert needed
        }

        // Check if this is a new blacklisting (not already alerted)
        $domain = $scan->domain;
        $user = $scan->user;
        
        // Get previous scan to compare
        $previousScan = $domain->scans()
            ->whereHas('blacklistResults')
            ->where('id', '!=', $scan->id)
            ->latest()
            ->first();
        
        $shouldAlert = true;
        
        if ($previousScan) {
            $previousListedIPs = $previousScan->blacklistResults
                ->where('status', 'listed')
                ->pluck('ip_address')
                ->unique();
            
            $currentListedIPs = $listedResults->pluck('ip_address')->unique();
            
            // Only alert if there are new blacklisted IPs
            $newBlacklistedIPs = $currentListedIPs->diff($previousListedIPs);
            $shouldAlert = $newBlacklistedIPs->isNotEmpty();
        }
        
        if ($shouldAlert) {
            Log::info("Sending blacklist alert for domain: {$domain->domain}");
            $user->notify(new BlacklistAlert($domain, $scan, collect($results)));
        }
    }
}