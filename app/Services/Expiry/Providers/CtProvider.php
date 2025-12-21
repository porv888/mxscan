<?php

namespace App\Services\Expiry\Providers;

use App\Services\Expiry\Contracts\SslExpiryProvider;
use App\Services\Expiry\DTOs\ExpiryResult;
use Carbon\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class CtProvider implements SslExpiryProvider
{
    private const CERTSPOTTER_URL = 'https://api.certspotter.com/v1/issuances';
    private const CRTSH_URL = 'https://crt.sh/';
    private const CRTSH_CACHE_TTL = 86400; // 24 hours

    public function detect(string $domain): ExpiryResult
    {
        $start = microtime(true);

        try {
            $token = config('expiry.ssl.ct.certspotter_token');
            $crtshEnabled = config('expiry.ssl.ct.crtsh_enabled', false);

            // Try Cert Spotter first if token is available
            if ($token) {
                $result = $this->checkCertSpotter($domain, $token);
                if ($result->isValid()) {
                    return $result;
                }
            }

            // Fallback to crt.sh if enabled
            if ($crtshEnabled) {
                return $this->checkCrtSh($domain);
            }

            return ExpiryResult::failure(
                $this->getName(),
                'No CT provider configured or available',
                (microtime(true) - $start) * 1000
            );

        } catch (\Exception $e) {
            Log::warning('CT detection failed', [
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

    private function checkCertSpotter(string $domain, string $token): ExpiryResult
    {
        $start = microtime(true);

        try {
            $response = Http::timeout(config('expiry.http_timeout', 8))
                ->withHeaders([
                    'Authorization' => "Bearer {$token}",
                    'User-Agent' => 'MXScan/1.0 (+https://mxscan.me)',
                ])
                ->get(self::CERTSPOTTER_URL, [
                    'domain' => $domain,
                    'include_subdomains' => 'true',
                    'expand' => 'dns_names,cert',
                    'match_wildcards' => 'true',
                ]);

            if (!$response->successful()) {
                return ExpiryResult::failure(
                    'Cert Spotter',
                    "HTTP {$response->status()}",
                    (microtime(true) - $start) * 1000
                );
            }

            $issuances = $response->json();
            
            if (empty($issuances)) {
                return ExpiryResult::failure(
                    'Cert Spotter',
                    'No certificates found',
                    (microtime(true) - $start) * 1000
                );
            }

            // Find the latest valid certificate
            $latestExpiry = null;
            
            foreach ($issuances as $issuance) {
                if (isset($issuance['cert']['not_after'])) {
                    try {
                        $notAfter = Carbon::parse($issuance['cert']['not_after']);
                        
                        // Only consider currently valid certs
                        if ($notAfter->isFuture()) {
                            if (!$latestExpiry || $notAfter->gt($latestExpiry)) {
                                $latestExpiry = $notAfter;
                            }
                        }
                    } catch (\Exception $e) {
                        Log::debug('Failed to parse CT date', [
                            'date' => $issuance['cert']['not_after'],
                            'error' => $e->getMessage(),
                        ]);
                    }
                }
            }

            if (!$latestExpiry) {
                return ExpiryResult::failure(
                    'Cert Spotter',
                    'No valid certificates found',
                    (microtime(true) - $start) * 1000
                );
            }

            return ExpiryResult::success(
                $latestExpiry,
                'Cert Spotter',
                (microtime(true) - $start) * 1000
            );

        } catch (\Exception $e) {
            return ExpiryResult::failure(
                'Cert Spotter',
                $e->getMessage(),
                (microtime(true) - $start) * 1000
            );
        }
    }

    private function checkCrtSh(string $domain): ExpiryResult
    {
        $start = microtime(true);

        try {
            // Cache crt.sh results to avoid rate limiting
            $cacheKey = "expiry:crtsh:{$domain}";
            
            $data = Cache::remember($cacheKey, self::CRTSH_CACHE_TTL, function () use ($domain) {
                $response = Http::timeout(config('expiry.http_timeout', 8))
                    ->withHeaders([
                        'User-Agent' => 'MXScan/1.0 (+https://mxscan.me)',
                    ])
                    ->get(self::CRTSH_URL, [
                        'q' => $domain,
                        'output' => 'json',
                    ]);

                if (!$response->successful()) {
                    return null;
                }

                return $response->json();
            });

            if (!$data || empty($data)) {
                return ExpiryResult::failure(
                    'crt.sh',
                    'No certificates found',
                    (microtime(true) - $start) * 1000
                );
            }

            // Find the latest valid certificate
            $latestExpiry = null;
            
            foreach ($data as $cert) {
                if (isset($cert['not_after'])) {
                    try {
                        $notAfter = Carbon::parse($cert['not_after']);
                        
                        // Only consider currently valid certs
                        if ($notAfter->isFuture()) {
                            if (!$latestExpiry || $notAfter->gt($latestExpiry)) {
                                $latestExpiry = $notAfter;
                            }
                        }
                    } catch (\Exception $e) {
                        Log::debug('Failed to parse crt.sh date', [
                            'date' => $cert['not_after'],
                            'error' => $e->getMessage(),
                        ]);
                    }
                }
            }

            if (!$latestExpiry) {
                return ExpiryResult::failure(
                    'crt.sh',
                    'No valid certificates found',
                    (microtime(true) - $start) * 1000
                );
            }

            return ExpiryResult::success(
                $latestExpiry,
                'crt.sh',
                (microtime(true) - $start) * 1000
            );

        } catch (\Exception $e) {
            return ExpiryResult::failure(
                'crt.sh',
                $e->getMessage(),
                (microtime(true) - $start) * 1000
            );
        }
    }

    public function getName(): string
    {
        return 'Certificate Transparency';
    }

    public function isEnabled(): bool
    {
        return config('expiry.enabled', true) && 
               config('expiry.ssl.ct.enabled', false) &&
               (!empty(config('expiry.ssl.ct.certspotter_token')) || 
                config('expiry.ssl.ct.crtsh_enabled', false));
    }
}
