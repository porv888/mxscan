<?php

namespace App\Services\Dns;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

class DnsClient
{
    private array $memoCache = [];
    private int $timeout;
    private int $retries;

    public function __construct(int $timeout = 1500, int $retries = 2)
    {
        $this->timeout = $timeout;
        $this->retries = $retries;
        
        // Set socket timeout for DNS queries
        ini_set('default_socket_timeout', ceil($timeout / 1000));
    }

    /**
     * Get TXT records for a domain with caching and memoization.
     */
    public function getTxt(string $domain): array
    {
        $domain = strtolower(trim($domain));
        
        // Check in-memory cache first
        $memoKey = "txt_{$domain}";
        if (isset($this->memoCache[$memoKey])) {
            return $this->memoCache[$memoKey];
        }

        // Check Laravel cache
        $cacheKey = "dns_txt_{$domain}";
        $result = Cache::remember($cacheKey, 900, function () use ($domain) { // 15 minutes
            return $this->performTxtLookup($domain);
        });

        // Store in memo cache for this request
        $this->memoCache[$memoKey] = $result;

        return $result;
    }

    /**
     * Get A records for a domain with caching and memoization.
     */
    public function getA(string $domain): array
    {
        $domain = strtolower(trim($domain));
        
        // Check in-memory cache first
        $memoKey = "a_{$domain}";
        if (isset($this->memoCache[$memoKey])) {
            return $this->memoCache[$memoKey];
        }

        // Check Laravel cache
        $cacheKey = "dns_a_{$domain}";
        $result = Cache::remember($cacheKey, 900, function () use ($domain) { // 15 minutes
            return $this->performALookup($domain);
        });

        // Store in memo cache for this request
        $this->memoCache[$memoKey] = $result;

        return $result;
    }

    /**
     * Get AAAA records for a domain with caching and memoization.
     */
    public function getAAAA(string $domain): array
    {
        $domain = strtolower(trim($domain));
        
        // Check in-memory cache first
        $memoKey = "aaaa_{$domain}";
        if (isset($this->memoCache[$memoKey])) {
            return $this->memoCache[$memoKey];
        }

        // Check Laravel cache
        $cacheKey = "dns_aaaa_{$domain}";
        $result = Cache::remember($cacheKey, 900, function () use ($domain) { // 15 minutes
            return $this->performAAAALookup($domain);
        });

        // Store in memo cache for this request
        $this->memoCache[$memoKey] = $result;

        return $result;
    }

    /**
     * Get MX records for a domain with caching and memoization.
     */
    public function getMx(string $domain): array
    {
        $domain = strtolower(trim($domain));
        
        // Check in-memory cache first
        $memoKey = "mx_{$domain}";
        if (isset($this->memoCache[$memoKey])) {
            return $this->memoCache[$memoKey];
        }

        // Check Laravel cache
        $cacheKey = "dns_mx_{$domain}";
        $result = Cache::remember($cacheKey, 900, function () use ($domain) { // 15 minutes
            return $this->performMxLookup($domain);
        });

        // Store in memo cache for this request
        $this->memoCache[$memoKey] = $result;

        return $result;
    }

    /**
     * Perform TXT record lookup with retries and timeout handling.
     */
    private function performTxtLookup(string $domain): array
    {
        $records = [];
        
        for ($attempt = 0; $attempt <= $this->retries; $attempt++) {
            try {
                $dnsRecords = dns_get_record($domain, DNS_TXT);
                
                if ($dnsRecords === false) {
                    if ($attempt === $this->retries) {
                        Log::warning("TXT lookup failed for {$domain} after {$this->retries} retries");
                    }
                    continue;
                }

                foreach ($dnsRecords as $record) {
                    if (isset($record['txt'])) {
                        $records[] = $record['txt'];
                    }
                }

                return $records;
            } catch (\Exception $e) {
                if ($attempt === $this->retries) {
                    Log::warning("TXT lookup exception for {$domain}: " . $e->getMessage());
                }
                
                if ($attempt < $this->retries) {
                    usleep(100000); // 100ms delay before retry
                }
            }
        }

        return $records;
    }

    /**
     * Perform A record lookup with retries and timeout handling.
     */
    private function performALookup(string $domain): array
    {
        $ips = [];
        
        for ($attempt = 0; $attempt <= $this->retries; $attempt++) {
            try {
                $records = dns_get_record($domain, DNS_A);
                
                if ($records === false) {
                    if ($attempt === $this->retries) {
                        Log::warning("A record lookup failed for {$domain} after {$this->retries} retries");
                    }
                    continue;
                }

                foreach ($records as $record) {
                    if (isset($record['ip'])) {
                        $ips[] = $record['ip'];
                    }
                }

                return $ips;
            } catch (\Exception $e) {
                if ($attempt === $this->retries) {
                    Log::warning("A record lookup exception for {$domain}: " . $e->getMessage());
                }
                
                if ($attempt < $this->retries) {
                    usleep(100000); // 100ms delay before retry
                }
            }
        }

        return $ips;
    }

    /**
     * Perform AAAA record lookup with retries and timeout handling.
     */
    private function performAAAALookup(string $domain): array
    {
        $ips = [];
        
        for ($attempt = 0; $attempt <= $this->retries; $attempt++) {
            try {
                $records = dns_get_record($domain, DNS_AAAA);
                
                if ($records === false) {
                    if ($attempt === $this->retries) {
                        Log::warning("AAAA record lookup failed for {$domain} after {$this->retries} retries");
                    }
                    continue;
                }

                foreach ($records as $record) {
                    if (isset($record['ipv6'])) {
                        $ips[] = $record['ipv6'];
                    }
                }

                return $ips;
            } catch (\Exception $e) {
                if ($attempt === $this->retries) {
                    Log::warning("AAAA record lookup exception for {$domain}: " . $e->getMessage());
                }
                
                if ($attempt < $this->retries) {
                    usleep(100000); // 100ms delay before retry
                }
            }
        }

        return $ips;
    }

    /**
     * Perform MX record lookup with retries and timeout handling.
     */
    private function performMxLookup(string $domain): array
    {
        $hosts = [];
        
        for ($attempt = 0; $attempt <= $this->retries; $attempt++) {
            try {
                $records = dns_get_record($domain, DNS_MX);
                
                if ($records === false) {
                    if ($attempt === $this->retries) {
                        Log::warning("MX record lookup failed for {$domain} after {$this->retries} retries");
                    }
                    continue;
                }

                foreach ($records as $record) {
                    if (isset($record['target'])) {
                        $hosts[] = $record['target'];
                    }
                }

                return $hosts;
            } catch (\Exception $e) {
                if ($attempt === $this->retries) {
                    Log::warning("MX record lookup exception for {$domain}: " . $e->getMessage());
                }
                
                if ($attempt < $this->retries) {
                    usleep(100000); // 100ms delay before retry
                }
            }
        }

        return $hosts;
    }

    /**
     * Clear the in-memory memo cache.
     */
    public function clearMemoCache(): void
    {
        $this->memoCache = [];
    }

    /**
     * Get the current memo cache size.
     */
    public function getMemoCacheSize(): int
    {
        return count($this->memoCache);
    }
}
