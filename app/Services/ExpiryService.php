<?php

namespace App\Services;

use App\Models\Domain;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Http;
use Carbon\Carbon;

class ExpiryService
{
    /**
     * Refresh expiry dates for a domain
     */
    public function refresh(Domain $domain): void
    {
        try {
            // Update domain expiry
            $domainExpiry = $this->getDomainExpiry($domain->domain);
            if ($domainExpiry) {
                $domain->update(['domain_expires_at' => $domainExpiry]);
                Log::info('Updated domain expiry', [
                    'domain' => $domain->domain,
                    'expires_at' => $domainExpiry->toDateTimeString(),
                ]);
            }

            // Update SSL expiry
            $sslExpiry = $this->getSslExpiry($domain->domain);
            if ($sslExpiry) {
                $domain->update(['ssl_expires_at' => $sslExpiry]);
                Log::info('Updated SSL expiry', [
                    'domain' => $domain->domain,
                    'ssl_expires_at' => $sslExpiry->toDateTimeString(),
                ]);
            }
        } catch (\Exception $e) {
            Log::error('Failed to refresh expiry dates', [
                'domain' => $domain->domain,
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Get domain expiry date using WHOIS lookup
     */
    protected function getDomainExpiry(string $domain): ?Carbon
    {
        try {
            // Use a simple WHOIS API or command
            $whoisData = $this->getWhoisData($domain);
            
            if ($whoisData && isset($whoisData['expiry'])) {
                return Carbon::parse($whoisData['expiry']);
            }

            // Fallback: try parsing whois command output (if shell_exec is available)
            if (\function_exists('shell_exec')) {
                $whoisOutput = @\shell_exec("whois " . \escapeshellarg($domain) . " 2>/dev/null");
                if ($whoisOutput) {
                    return $this->parseWhoisExpiry($whoisOutput);
                }
            }

        } catch (\Exception $e) {
            Log::warning('Failed to get domain expiry', [
                'domain' => $domain,
                'error' => $e->getMessage(),
            ]);
        }

        return null;
    }

    /**
     * Get SSL certificate expiry date
     */
    protected function getSslExpiry(string $domain): ?Carbon
    {
        try {
            // Use openssl to check certificate (if shell_exec is available)
            if (\function_exists('shell_exec')) {
                $command = "echo | timeout 10 openssl s_client -servername " . \escapeshellarg($domain) . 
                          " -connect " . \escapeshellarg($domain) . ":443 2>/dev/null | " .
                          "openssl x509 -noout -dates 2>/dev/null";
                
                $output = @\shell_exec($command);
                
                if ($output && \preg_match('/notAfter=(.+)/', $output, $matches)) {
                    return Carbon::parse($matches[1]);
                }
            }

            // Alternative: use PHP's stream context to get SSL certificate info
            try {
                $context = \stream_context_create([
                    'ssl' => [
                        'capture_peer_cert' => true,
                        'verify_peer' => false,
                        'verify_peer_name' => false,
                    ]
                ]);
                
                $stream = @\stream_socket_client(
                    "ssl://{$domain}:443",
                    $errno,
                    $errstr,
                    10,
                    STREAM_CLIENT_CONNECT,
                    $context
                );
                
                if ($stream) {
                    $params = \stream_context_get_params($stream);
                    $cert = \openssl_x509_parse($params['options']['ssl']['peer_certificate']);
                    \fclose($stream);
                    
                    if (isset($cert['validTo_time_t'])) {
                        return Carbon::createFromTimestamp($cert['validTo_time_t']);
                    }
                }
            } catch (\Exception $e) {
                Log::debug('Stream SSL check failed', [
                    'domain' => $domain,
                    'error' => $e->getMessage()
                ]);
            }

        } catch (\Exception $e) {
            Log::warning('Failed to get SSL expiry', [
                'domain' => $domain,
                'error' => $e->getMessage(),
            ]);
        }

        return null;
    }

    /**
     * Get WHOIS data using external API (placeholder implementation)
     */
    protected function getWhoisData(string $domain): ?array
    {
        try {
            // You could integrate with a WHOIS API service here
            // For now, this is a placeholder that returns null
            // to fall back to the command line whois tool
            
            // Example with a hypothetical WHOIS API:
            // $response = Http::timeout(10)->get("https://api.whoisapi.com/v1/{$domain}");
            // return $response->json();
            
            return null;
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Parse expiry date from WHOIS command output
     */
    protected function parseWhoisExpiry(string $whoisOutput): ?Carbon
    {
        // Common WHOIS expiry patterns
        $patterns = [
            '/Registry Expiry Date:\s*(.+)/i',
            '/Expiration Date:\s*(.+)/i',
            '/Expires:\s*(.+)/i',
            '/Expiry Date:\s*(.+)/i',
            '/Domain expires:\s*(.+)/i',
            '/paid-till:\s*(.+)/i',
        ];

        foreach ($patterns as $pattern) {
            if (\preg_match($pattern, $whoisOutput, $matches)) {
                try {
                    $dateString = \trim($matches[1]);
                    // Remove any trailing timezone info that might cause issues
                    $dateString = \preg_replace('/\s+[A-Z]{3,4}$/', '', $dateString);
                    return Carbon::parse($dateString);
                } catch (\Exception $e) {
                    continue;
                }
            }
        }

        return null;
    }

    /**
     * Check if domain needs expiry update (hasn't been checked recently)
     */
    public function needsExpiryUpdate(Domain $domain): bool
    {
        // Update if we don't have expiry data or it's older than 24 hours
        $lastUpdate = $domain->updated_at;
        
        return !$domain->domain_expires_at || 
               !$domain->ssl_expires_at || 
               $lastUpdate->lt(now()->subDay());
    }

    /**
     * Get domains that are expiring soon
     */
    public function getExpiringDomains(int $days = 30): array
    {
        $domains = Domain::where(function ($query) use ($days) {
            $query->where('domain_expires_at', '<=', now()->addDays($days))
                  ->orWhere('ssl_expires_at', '<=', now()->addDays($days));
        })->with('user')->get();

        $expiring = [];
        
        foreach ($domains as $domain) {
            if ($domain->isDomainExpiringSoon($days)) {
                $expiring[] = [
                    'domain' => $domain,
                    'type' => 'domain',
                    'days' => $domain->getDaysUntilDomainExpiry(),
                ];
            }
            
            if ($domain->isSslExpiringSoon($days)) {
                $expiring[] = [
                    'domain' => $domain,
                    'type' => 'ssl',
                    'days' => $domain->getDaysUntilSslExpiry(),
                ];
            }
        }

        return $expiring;
    }
}
