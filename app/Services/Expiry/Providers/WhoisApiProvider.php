<?php

namespace App\Services\Expiry\Providers;

use App\Services\Expiry\Contracts\DomainExpiryProvider;
use App\Services\Expiry\DTOs\ExpiryResult;
use Carbon\Carbon;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class WhoisApiProvider implements DomainExpiryProvider
{
    private const PROVIDERS = [
        'whoisxmlapi' => [
            'url' => 'https://www.whoisxmlapi.com/whoisserver/WhoisService',
            'method' => 'GET',
            'params' => ['domainName', 'apiKey', 'outputFormat' => 'JSON'],
            'expiry_paths' => ['registryData.expiresDate', 'WhoisRecord.expiresDate', 'expiresDate'],
        ],
        'jsonwhois' => [
            'url' => 'https://jsonwhois.com/api/v1/whois',
            'method' => 'GET',
            'params' => ['domain'],
            'headers' => ['Authorization' => 'Bearer {key}'],
            'expiry_paths' => ['expiry_date', 'expires'],
        ],
        'ip2whois' => [
            'url' => 'https://api.ip2whois.com/v2',
            'method' => 'GET',
            'params' => ['domain', 'key'],
            'expiry_paths' => ['expire_date', 'expiration_date'],
        ],
        'whoisfreaks' => [
            'url' => 'https://api.whoisfreaks.com/v1.0/whois',
            'method' => 'GET',
            'params' => ['whois', 'apiKey'],
            'expiry_paths' => ['expiry_date', 'expires'],
        ],
    ];

    public function detect(string $domain): ExpiryResult
    {
        $start = microtime(true);

        try {
            $provider = config('expiry.domain.whois_api.provider', 'whoisxmlapi');
            $apiKey = config('expiry.domain.whois_api.key');

            if (!$apiKey) {
                return ExpiryResult::failure(
                    $this->getName(),
                    'API key not configured',
                    (microtime(true) - $start) * 1000
                );
            }

            if (!isset(self::PROVIDERS[$provider])) {
                return ExpiryResult::failure(
                    $this->getName(),
                    "Unknown provider: {$provider}",
                    (microtime(true) - $start) * 1000
                );
            }

            $config = self::PROVIDERS[$provider];
            $response = $this->makeRequest($domain, $apiKey, $config);

            if (!$response) {
                return ExpiryResult::failure(
                    $this->getName(),
                    'API request failed',
                    (microtime(true) - $start) * 1000
                );
            }

            $expiryDate = $this->extractExpiryDate($response, $config['expiry_paths']);

            if (!$expiryDate) {
                return ExpiryResult::failure(
                    $this->getName(),
                    'No expiry date found in API response',
                    (microtime(true) - $start) * 1000
                );
            }

            return ExpiryResult::success(
                $expiryDate,
                $this->getName(),
                (microtime(true) - $start) * 1000
            );

        } catch (\Exception $e) {
            Log::warning('WHOIS API detection failed', [
                'domain' => $domain,
                'provider' => config('expiry.domain.whois_api.provider'),
                'error' => $e->getMessage(),
            ]);

            return ExpiryResult::failure(
                $this->getName(),
                $e->getMessage(),
                (microtime(true) - $start) * 1000
            );
        }
    }

    private function makeRequest(string $domain, string $apiKey, array $config): ?array
    {
        try {
            $http = Http::timeout(config('expiry.http_timeout', 8))
                ->withHeaders([
                    'User-Agent' => 'MXScan/1.0 (+https://mxscan.me)',
                ]);

            // Add custom headers if defined
            if (isset($config['headers'])) {
                foreach ($config['headers'] as $header => $value) {
                    $value = str_replace('{key}', $apiKey, $value);
                    $http = $http->withHeaders([$header => $value]);
                }
            }

            // Build query parameters
            $params = [];
            foreach ($config['params'] as $key => $value) {
                if (is_numeric($key)) {
                    // Dynamic param name
                    if ($value === 'domain' || $value === 'domainName' || $value === 'whois') {
                        $params[$value] = $domain;
                    } elseif ($value === 'apiKey' || $value === 'key') {
                        $params[$value] = $apiKey;
                    }
                } else {
                    // Static param
                    $params[$key] = $value;
                }
            }

            $response = $http->get($config['url'], $params);

            if (!$response->successful()) {
                Log::warning('WHOIS API request failed', [
                    'status' => $response->status(),
                    'body' => $response->body(),
                ]);
                return null;
            }

            return $response->json();

        } catch (\Exception $e) {
            Log::warning('WHOIS API request exception', [
                'error' => $e->getMessage(),
            ]);
            return null;
        }
    }

    private function extractExpiryDate(array $data, array $paths): ?Carbon
    {
        foreach ($paths as $path) {
            $value = $this->getNestedValue($data, $path);
            
            if ($value) {
                try {
                    $date = Carbon::parse($value);
                    
                    // Only accept future dates
                    if ($date->isFuture()) {
                        return $date;
                    }
                } catch (\Exception $e) {
                    Log::debug('Failed to parse WHOIS API date', [
                        'path' => $path,
                        'value' => $value,
                        'error' => $e->getMessage(),
                    ]);
                }
            }
        }

        return null;
    }

    private function getNestedValue(array $data, string $path): ?string
    {
        $keys = explode('.', $path);
        $value = $data;

        foreach ($keys as $key) {
            if (!isset($value[$key])) {
                return null;
            }
            $value = $value[$key];
        }

        return is_string($value) ? $value : null;
    }

    public function getName(): string
    {
        $provider = config('expiry.domain.whois_api.provider', 'whoisxmlapi');
        return 'WHOIS API (' . ucfirst($provider) . ')';
    }

    public function isEnabled(): bool
    {
        return config('expiry.enabled', true) && 
               config('expiry.domain.whois_api.enabled', false) &&
               !empty(config('expiry.domain.whois_api.key'));
    }
}
