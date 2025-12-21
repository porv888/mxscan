<?php

namespace App\Services\Expiry\Providers;

use App\Services\Expiry\Contracts\SslExpiryProvider;
use App\Services\Expiry\DTOs\ExpiryResult;
use Carbon\Carbon;
use Illuminate\Support\Facades\Log;

class LiveTlsProvider implements SslExpiryProvider
{
    public function detect(string $domain): ExpiryResult
    {
        $start = microtime(true);

        try {
            $hostnames = $this->getHostnamesToCheck($domain);
            $earliestExpiry = null;
            $successfulHost = null;

            foreach ($hostnames as $hostname) {
                $expiryDate = $this->checkHostname($hostname);
                
                if ($expiryDate && $expiryDate->isFuture()) {
                    if (!$earliestExpiry || $expiryDate->lt($earliestExpiry)) {
                        $earliestExpiry = $expiryDate;
                        $successfulHost = $hostname;
                    }
                }
            }

            if (!$earliestExpiry) {
                return ExpiryResult::failure(
                    $this->getName(),
                    'No valid SSL certificate found on any hostname',
                    (microtime(true) - $start) * 1000
                );
            }

            return ExpiryResult::success(
                $earliestExpiry,
                $this->getName() . " ({$successfulHost})",
                (microtime(true) - $start) * 1000
            );

        } catch (\Exception $e) {
            Log::warning('Live TLS detection failed', [
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

    private function getHostnamesToCheck(string $domain): array
    {
        $templates = config('expiry.ssl.live_tls.hostnames', ['%domain%', 'www.%domain%']);
        
        return array_map(
            fn($template) => str_replace('%domain%', $domain, $template),
            $templates
        );
    }

    private function checkHostname(string $hostname): ?Carbon
    {
        try {
            $timeout = config('expiry.connect_timeout', 8);
            
            $context = stream_context_create([
                'ssl' => [
                    'capture_peer_cert' => true,
                    'verify_peer' => false,
                    'verify_peer_name' => false,
                    'SNI_enabled' => true,
                    'peer_name' => $hostname,
                ],
            ]);

            $errno = 0;
            $errstr = '';
            
            $client = @stream_socket_client(
                "ssl://{$hostname}:443",
                $errno,
                $errstr,
                $timeout,
                STREAM_CLIENT_CONNECT,
                $context
            );

            if (!$client) {
                Log::debug('TLS connection failed', [
                    'hostname' => $hostname,
                    'error' => $errstr,
                    'errno' => $errno,
                ]);
                return null;
            }

            $params = stream_context_get_params($client);
            fclose($client);

            if (!isset($params['options']['ssl']['peer_certificate'])) {
                return null;
            }

            $cert = openssl_x509_parse($params['options']['ssl']['peer_certificate']);

            if (!isset($cert['validTo_time_t'])) {
                return null;
            }

            return Carbon::createFromTimestamp($cert['validTo_time_t']);

        } catch (\Exception $e) {
            Log::debug('TLS certificate check failed', [
                'hostname' => $hostname,
                'error' => $e->getMessage(),
            ]);
            return null;
        }
    }

    public function getName(): string
    {
        return 'Live TLS';
    }

    public function isEnabled(): bool
    {
        return config('expiry.enabled', true) && 
               config('expiry.ssl.live_tls.enabled', true);
    }
}
