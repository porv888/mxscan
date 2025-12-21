<?php

namespace App\Services\Expiry\Providers;

use App\Services\Expiry\Contracts\DomainExpiryProvider;
use App\Services\Expiry\DTOs\ExpiryResult;
use Carbon\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class RdapRegistryProvider implements DomainExpiryProvider
{
    private const IANA_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
    private const BOOTSTRAP_CACHE_KEY = 'expiry:rdap:bootstrap';
    private const BOOTSTRAP_CACHE_TTL = 86400; // 24 hours

    public function detect(string $domain): ExpiryResult
    {
        $start = microtime(true);

        try {
            // Get RDAP server for this domain
            $rdapServer = $this->resolveRdapServer($domain);
            
            if (!$rdapServer) {
                return ExpiryResult::failure(
                    $this->getName(),
                    'No RDAP server found for TLD',
                    (microtime(true) - $start) * 1000
                );
            }

            // Query RDAP server
            $url = rtrim($rdapServer, '/') . '/domain/' . $domain;
            
            $response = Http::timeout(config('expiry.http_timeout', 8))
                ->withHeaders([
                    'User-Agent' => 'MXScan/1.0 (+https://mxscan.me)',
                    'Accept' => 'application/rdap+json',
                ])
                ->get($url);

            if (!$response->successful()) {
                return ExpiryResult::failure(
                    $this->getName(),
                    "HTTP {$response->status()}",
                    (microtime(true) - $start) * 1000
                );
            }

            $data = $response->json();
            
            // Extract expiration date from events
            $expiryDate = $this->extractExpiryDate($data);
            
            if (!$expiryDate) {
                return ExpiryResult::failure(
                    $this->getName(),
                    'No expiration event found in RDAP response',
                    (microtime(true) - $start) * 1000
                );
            }

            return ExpiryResult::success(
                $expiryDate,
                $this->getName(),
                (microtime(true) - $start) * 1000
            );

        } catch (\Exception $e) {
            Log::warning('RDAP Registry detection failed', [
                'domain' => $domain,
                'error' => $e->getMessage(),
            ]);

            return ExpiryResult::failure(
                $this->getName(),
                $e->getMessage(),
                (microtime(true) - $start) * 1000
            );
        }
    }

    private function resolveRdapServer(string $domain): ?string
    {
        try {
            // Get TLD
            $parts = explode('.', $domain);
            $tld = end($parts);

            // Get bootstrap data (cached)
            $bootstrap = Cache::remember(
                self::BOOTSTRAP_CACHE_KEY,
                self::BOOTSTRAP_CACHE_TTL,
                fn() => Http::timeout(10)->get(self::IANA_BOOTSTRAP_URL)->json()
            );

            if (!isset($bootstrap['services'])) {
                return null;
            }

            // Find matching service
            foreach ($bootstrap['services'] as $service) {
                [$tlds, $servers] = $service;
                
                if (in_array($tld, $tlds) && !empty($servers)) {
                    return $servers[0];
                }
            }

            return null;

        } catch (\Exception $e) {
            Log::warning('RDAP bootstrap resolution failed', [
                'domain' => $domain,
                'error' => $e->getMessage(),
            ]);
            return null;
        }
    }

    private function extractExpiryDate(array $data): ?Carbon
    {
        if (!isset($data['events']) || !is_array($data['events'])) {
            return null;
        }

        foreach ($data['events'] as $event) {
            if (isset($event['eventAction']) && 
                $event['eventAction'] === 'expiration' && 
                isset($event['eventDate'])) {
                
                try {
                    $date = Carbon::parse($event['eventDate']);
                    
                    // Only accept future dates
                    if ($date->isFuture()) {
                        return $date;
                    }
                } catch (\Exception $e) {
                    Log::warning('Failed to parse RDAP expiry date', [
                        'date' => $event['eventDate'],
                        'error' => $e->getMessage(),
                    ]);
                }
            }
        }

        return null;
    }

    public function getName(): string
    {
        return 'RDAP Registry';
    }

    public function isEnabled(): bool
    {
        return config('expiry.enabled', true) && 
               config('expiry.domain.rdap.enabled', true);
    }
}
