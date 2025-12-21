<?php

namespace App\Services;

use App\Models\BlacklistResult;
use App\Models\Scan;
use App\Notifications\BlacklistAlert;
use Illuminate\Support\Facades\Log;

class BlacklistChecker
{
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
     * Check all IPs for a domain against RBL providers.
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

        foreach ($ips as $ip) {
            foreach ($this->getRblProviders() as $providerId => $provider) {
                $result = $this->checkIPAgainstRBL($ip, $provider);
                
                // Store result in database
                $blacklistResult = BlacklistResult::create([
                    'scan_id' => $scan->id,
                    'provider' => $provider['name'],
                    'ip_address' => $ip,
                    'status' => $result['listed'] ? 'listed' : 'ok',
                    'message' => $result['message'],
                    'removal_url' => $provider['delist_url'] ?? null,
                ]);

                $results[] = $blacklistResult;
                
                Log::info("Checked {$ip} against {$provider['name']}: " . ($result['listed'] ? 'LISTED' : 'OK'));
            }
        }

        // Check if we should send alerts
        $this->checkForAlerts($scan, $results);

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
     * Check a single IP against an RBL provider.
     */
    private function checkIPAgainstRBL(string $ip, array $provider): array
    {
        $result = [
            'listed' => false,
            'message' => null,
        ];

        try {
            // Reverse the IP for RBL lookup
            $reversedIP = $this->reverseIP($ip);
            if (!$reversedIP) {
                return $result;
            }

            $lookupHost = $reversedIP . '.' . $provider['host'];
            
            // Perform DNS lookup
            $dnsResult = dns_get_record($lookupHost, DNS_A);
            
            if (!empty($dnsResult)) {
                $result['listed'] = true;
                
                // Try to get TXT record for more details
                $txtRecords = dns_get_record($lookupHost, DNS_TXT);
                if (!empty($txtRecords)) {
                    $result['message'] = $txtRecords[0]['txt'] ?? 'Listed on ' . $provider['name'];
                } else {
                    $result['message'] = 'Listed on ' . $provider['name'];
                }
            }

        } catch (\Exception $e) {
            Log::error("Error checking IP {$ip} against {$provider['name']}: " . $e->getMessage());
        }

        return $result;
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