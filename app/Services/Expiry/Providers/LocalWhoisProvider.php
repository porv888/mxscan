<?php

namespace App\Services\Expiry\Providers;

use App\Services\Expiry\Contracts\DomainExpiryProvider;
use App\Services\Expiry\DTOs\ExpiryResult;
use Carbon\Carbon;
use Illuminate\Support\Facades\Log;
use Symfony\Component\Process\Process;

class LocalWhoisProvider implements DomainExpiryProvider
{
    private const EXPIRY_PATTERNS = [
        '/Registry Expiry Date:\s*(.+)/i',
        '/Registrar Registration Expiration Date:\s*(.+)/i',
        '/Expiration Date:\s*(.+)/i',
        '/Expiry Date:\s*(.+)/i',
        '/Expires:\s*(.+)/i',
        '/expire:\s*(.+)/i',
        '/paid-till:\s*(.+)/i',
    ];

    public function detect(string $domain): ExpiryResult
    {
        $start = microtime(true);

        try {
            // Check if whois binary exists
            if (!$this->whoisExists()) {
                return ExpiryResult::failure(
                    $this->getName(),
                    'whois binary not found',
                    (microtime(true) - $start) * 1000
                );
            }

            // Execute whois command
            $process = new Process(['whois', $domain]);
            $process->setTimeout(config('expiry.http_timeout', 8));
            $process->run();

            if (!$process->isSuccessful()) {
                return ExpiryResult::failure(
                    $this->getName(),
                    'whois command failed: ' . $process->getErrorOutput(),
                    (microtime(true) - $start) * 1000
                );
            }

            $output = $process->getOutput();
            
            // Extract expiry date using patterns
            $expiryDate = $this->extractExpiryDate($output);

            if (!$expiryDate) {
                return ExpiryResult::failure(
                    $this->getName(),
                    'No expiry date found in whois output',
                    (microtime(true) - $start) * 1000
                );
            }

            return ExpiryResult::success(
                $expiryDate,
                $this->getName(),
                (microtime(true) - $start) * 1000
            );

        } catch (\Exception $e) {
            Log::warning('Local WHOIS detection failed', [
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

    private function whoisExists(): bool
    {
        $process = new Process(['which', 'whois']);
        $process->run();
        return $process->isSuccessful();
    }

    private function extractExpiryDate(string $output): ?Carbon
    {
        foreach (self::EXPIRY_PATTERNS as $pattern) {
            if (preg_match($pattern, $output, $matches)) {
                $dateString = trim($matches[1]);
                
                try {
                    $date = Carbon::parse($dateString);
                    
                    // Only accept future dates
                    if ($date->isFuture()) {
                        return $date;
                    }
                } catch (\Exception $e) {
                    Log::debug('Failed to parse local whois date', [
                        'pattern' => $pattern,
                        'value' => $dateString,
                        'error' => $e->getMessage(),
                    ]);
                }
            }
        }

        return null;
    }

    public function getName(): string
    {
        return 'Local WHOIS';
    }

    public function isEnabled(): bool
    {
        return config('expiry.enabled', true) && 
               config('expiry.domain.whois_binary.enabled', false);
    }
}
