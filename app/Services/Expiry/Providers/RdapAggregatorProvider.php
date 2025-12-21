<?php

namespace App\Services\Expiry\Providers;

use App\Services\Expiry\Contracts\DomainExpiryProvider;
use App\Services\Expiry\DTOs\ExpiryResult;
use Carbon\Carbon;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class RdapAggregatorProvider implements DomainExpiryProvider
{
    public function detect(string $domain): ExpiryResult
    {
        $start = microtime(true);

        try {
            $baseUrl = config('expiry.domain.rdap.aggregator_url', 'https://rdap.org/domain');
            $url = rtrim($baseUrl, '/') . '/' . $domain;

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
            Log::warning('RDAP Aggregator detection failed', [
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
        return 'RDAP Aggregator';
    }

    public function isEnabled(): bool
    {
        return config('expiry.enabled', true) && 
               config('expiry.domain.rdap.aggregator_enabled', true);
    }
}
