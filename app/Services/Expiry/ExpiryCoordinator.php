<?php

namespace App\Services\Expiry;

use App\Models\Domain;
use App\Models\Incident;
use App\Services\Expiry\Contracts\DomainExpiryProvider;
use App\Services\Expiry\Contracts\SslExpiryProvider;
use App\Services\Expiry\DTOs\ExpiryResult;
use App\Services\Expiry\Providers\CtProvider;
use App\Services\Expiry\Providers\LiveTlsProvider;
use App\Services\Expiry\Providers\LocalWhoisProvider;
use App\Services\Expiry\Providers\RdapAggregatorProvider;
use App\Services\Expiry\Providers\RdapRegistryProvider;
use App\Services\Expiry\Providers\TcpWhoisProvider;
use App\Services\Expiry\Providers\WhoisApiProvider;
use Carbon\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

class ExpiryCoordinator
{
    private array $domainProviders;
    private array $sslProviders;

    public function __construct()
    {
        // Initialize domain providers in priority order
        $this->domainProviders = [
            new RdapRegistryProvider(),
            new RdapAggregatorProvider(),
            new WhoisApiProvider(),
            new TcpWhoisProvider(),  // Open source TCP WHOIS (free, no API key)
            new LocalWhoisProvider(),
        ];

        // Initialize SSL providers in priority order
        $this->sslProviders = [
            new LiveTlsProvider(),
            new CtProvider(),
        ];
    }

    /**
     * Detect domain expiry date using available providers.
     *
     * @param Domain $domain
     * @param bool $fastPath Use only the best provider (for scan-time checks)
     * @return ExpiryResult|null
     */
    public function detectDomainExpiry(Domain $domain, bool $fastPath = false): ?ExpiryResult
    {
        if (!config('expiry.enabled', true)) {
            Log::debug('Expiry detection disabled', ['domain' => $domain->domain]);
            return null;
        }

        $providers = $fastPath 
            ? array_slice($this->domainProviders, 0, 4) // Try RDAP Registry, RDAP Aggregator, WHOIS API, and TCP WHOIS for fast path
            : $this->domainProviders;

        foreach ($providers as $provider) {
            if (!$provider->isEnabled()) {
                Log::debug('Provider disabled', [
                    'domain' => $domain->domain,
                    'provider' => $provider->getName(),
                ]);
                continue;
            }

            // Check backoff
            if ($this->isBackedOff($domain, $provider->getName(), 'domain')) {
                Log::debug('Provider backed off', [
                    'domain' => $domain->domain,
                    'provider' => $provider->getName(),
                ]);
                continue;
            }

            $result = $provider->detect($domain->domain);

            $this->logResult($domain, $result, 'domain');

            if ($result->isValid()) {
                $this->clearBackoff($domain, $provider->getName(), 'domain');
                return $result;
            }

            // Apply backoff on failure
            $this->applyBackoff($domain, $provider->getName(), 'domain');
            
            // Continue to next provider (fast path will try all configured providers)
        }

        Log::info('All domain expiry providers failed', [
            'domain' => $domain->domain,
            'fast_path' => $fastPath,
        ]);

        return null;
    }

    /**
     * Detect SSL expiry date using available providers.
     *
     * @param Domain $domain
     * @param bool $fastPath Use only the best provider (for scan-time checks)
     * @return ExpiryResult|null
     */
    public function detectSslExpiry(Domain $domain, bool $fastPath = false): ?ExpiryResult
    {
        if (!config('expiry.enabled', true)) {
            Log::debug('Expiry detection disabled', ['domain' => $domain->domain]);
            return null;
        }

        $providers = $fastPath 
            ? array_slice($this->sslProviders, 0, 1) // Only use Live TLS for fast path
            : $this->sslProviders;

        foreach ($providers as $provider) {
            if (!$provider->isEnabled()) {
                Log::debug('Provider disabled', [
                    'domain' => $domain->domain,
                    'provider' => $provider->getName(),
                ]);
                continue;
            }

            // Check backoff
            if ($this->isBackedOff($domain, $provider->getName(), 'ssl')) {
                Log::debug('Provider backed off', [
                    'domain' => $domain->domain,
                    'provider' => $provider->getName(),
                ]);
                continue;
            }

            $result = $provider->detect($domain->domain);

            $this->logResult($domain, $result, 'ssl');

            if ($result->isValid()) {
                $this->clearBackoff($domain, $provider->getName(), 'ssl');
                return $result;
            }

            // Apply backoff on failure
            $this->applyBackoff($domain, $provider->getName(), 'ssl');
            
            // Continue to next provider (fast path will try all configured providers)
        }

        Log::info('All SSL expiry providers failed', [
            'domain' => $domain->domain,
            'fast_path' => $fastPath,
        ]);

        return null;
    }

    /**
     * Update domain with detected expiry dates and manage incidents.
     *
     * @param Domain $domain
     * @param ExpiryResult|null $domainResult
     * @param ExpiryResult|null $sslResult
     * @return void
     */
    public function updateDomain(Domain $domain, ?ExpiryResult $domainResult, ?ExpiryResult $sslResult): void
    {
        $allowOverwrite = config('expiry.allow_overwrite', true);
        $updated = false;

        // Update domain expiry
        if ($domainResult && $domainResult->isValid()) {
            $newDate = $domainResult->expiryDate;
            $currentDate = $domain->domain_expires_at;

            $shouldUpdate = !$currentDate || 
                           ($allowOverwrite && $newDate->ne($currentDate)) ||
                           (!$allowOverwrite && $newDate->gt($currentDate));

            if ($shouldUpdate) {
                $domain->domain_expires_at = $newDate;
                $domain->domain_expiry_source = $domainResult->source;
                $domain->domain_expiry_detected_at = now();
                $updated = true;

                Log::info('Updated domain expiry', [
                    'domain' => $domain->domain,
                    'date' => $newDate->toIso8601String(),
                    'source' => $domainResult->source,
                    'previous' => $currentDate?->toIso8601String(),
                ]);

                // Close incidents if expiry is now > 30 days away
                if ($newDate->diffInDays(now()) > 30) {
                    $this->closeExpiryIncidents($domain, 'domain');
                }
            }
        }

        // Update SSL expiry
        if ($sslResult && $sslResult->isValid()) {
            $newDate = $sslResult->expiryDate;
            $currentDate = $domain->ssl_expires_at;

            $shouldUpdate = !$currentDate || 
                           ($allowOverwrite && $newDate->ne($currentDate)) ||
                           (!$allowOverwrite && $newDate->gt($currentDate));

            if ($shouldUpdate) {
                $domain->ssl_expires_at = $newDate;
                $domain->ssl_expiry_source = $sslResult->source;
                $domain->ssl_expiry_detected_at = now();
                $updated = true;

                Log::info('Updated SSL expiry', [
                    'domain' => $domain->domain,
                    'date' => $newDate->toIso8601String(),
                    'source' => $sslResult->source,
                    'previous' => $currentDate?->toIso8601String(),
                ]);

                // Close incidents if expiry is now > 30 days away
                if ($newDate->diffInDays(now()) > 30) {
                    $this->closeExpiryIncidents($domain, 'ssl');
                }
            }
        }

        if ($updated) {
            $domain->save();
        }
    }

    /**
     * Check if a provider is currently backed off for a domain.
     */
    private function isBackedOff(Domain $domain, string $provider, string $type): bool
    {
        $key = $this->getBackoffKey($domain, $provider, $type);
        return Cache::has($key);
    }

    /**
     * Apply backoff to a provider for a domain.
     */
    private function applyBackoff(Domain $domain, string $provider, string $type): void
    {
        $key = $this->getBackoffKey($domain, $provider, $type);
        $ttl = config('expiry.retry_backoff', 300); // seconds
        
        Cache::put($key, true, $ttl);
        
        Log::debug('Applied backoff', [
            'domain' => $domain->domain,
            'provider' => $provider,
            'type' => $type,
            'ttl' => $ttl,
        ]);
    }

    /**
     * Clear backoff for a provider.
     */
    private function clearBackoff(Domain $domain, string $provider, string $type): void
    {
        $key = $this->getBackoffKey($domain, $provider, $type);
        Cache::forget($key);
    }

    /**
     * Get backoff cache key.
     */
    private function getBackoffKey(Domain $domain, string $provider, string $type): string
    {
        $providerSlug = str_replace(' ', '_', strtolower($provider));
        return "expiry:backoff:{$type}:{$domain->id}:{$providerSlug}";
    }

    /**
     * Log detection result.
     */
    private function logResult(Domain $domain, ExpiryResult $result, string $type): void
    {
        $level = $result->success ? 'info' : 'warning';
        
        Log::log($level, "Expiry detection result", [
            'domain' => $domain->domain,
            'type' => $type,
            'provider' => $result->source,
            'success' => $result->success,
            'date' => $result->expiryDate?->toIso8601String(),
            'error' => $result->error,
            'latency_ms' => round($result->latencyMs ?? 0, 2),
        ]);
    }

    /**
     * Close expiry-related incidents.
     */
    private function closeExpiryIncidents(Domain $domain, string $type): void
    {
        $titlePattern = $type === 'domain' ? 'Domain expiring soon' : 'SSL certificate expiring soon';
        
        Incident::where('domain_id', $domain->id)
            ->where('title', 'like', "%{$titlePattern}%")
            ->whereNull('resolved_at')
            ->update(['resolved_at' => now()]);
    }
}
