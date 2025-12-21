<?php

namespace App\Services\Expiry\Providers;

use App\Services\Expiry\Contracts\DomainExpiryProvider;
use App\Services\Expiry\DTOs\ExpiryResult;
use Carbon\Carbon;
use Illuminate\Support\Facades\Log;

/**
 * TCP WHOIS Provider - Queries WHOIS servers directly via TCP port 43
 * This is the open-source method used by big companies
 * No API key required, completely free
 */
class TcpWhoisProvider implements DomainExpiryProvider
{
    private array $whoisServers = [
        'com' => 'whois.verisign-grs.com',
        'net' => 'whois.verisign-grs.com',
        'org' => 'whois.pir.org',
        'info' => 'whois.afilias.net',
        'biz' => 'whois.biz',
        'me' => 'whois.nic.me',
        'io' => 'whois.nic.io',
        'co' => 'whois.nic.co',
        'uk' => 'whois.nic.uk',
        'de' => 'whois.denic.de',
        'fr' => 'whois.nic.fr',
        'nl' => 'whois.domain-registry.nl',
        'ca' => 'whois.cira.ca',
        'au' => 'whois.auda.org.au',
        'nz' => 'whois.srs.net.nz',
        'in' => 'whois.registry.in',
        'cn' => 'whois.cnnic.cn',
        'jp' => 'whois.jprs.jp',
        'br' => 'whois.registro.br',
        'ru' => 'whois.tcinet.ru',
        'pl' => 'whois.dns.pl',
        'it' => 'whois.nic.it',
        'es' => 'whois.nic.es',
        'se' => 'whois.iis.se',
        'no' => 'whois.norid.no',
        'ch' => 'whois.nic.ch',
        'at' => 'whois.nic.at',
        'be' => 'whois.dns.be',
        'dk' => 'whois.dk-hostmaster.dk',
        'fi' => 'whois.fi',
        'cz' => 'whois.nic.cz',
        'pt' => 'whois.dns.pt',
        'gr' => 'whois.nic.gr',
        'ie' => 'whois.iedr.ie',
        'sg' => 'whois.sgnic.sg',
        'hk' => 'whois.hkirc.hk',
        'tw' => 'whois.twnic.net.tw',
        'kr' => 'whois.kr',
        'za' => 'whois.registry.net.za',
        'mx' => 'whois.mx',
        'ar' => 'whois.nic.ar',
        'cl' => 'whois.nic.cl',
        'pe' => 'kero.yachay.pe',
        'tr' => 'whois.nic.tr',
        'il' => 'whois.isoc.org.il',
        'ae' => 'whois.aeda.net.ae',
        'sa' => 'whois.nic.net.sa',
    ];

    private array $expiryPatterns = [
        '/Registry Expiry Date:\s*(.+)/i',
        '/Registrar Registration Expiration Date:\s*(.+)/i',
        '/Expiration Date:\s*(.+)/i',
        '/Expiry Date:\s*(.+)/i',
        '/Expires:\s*(.+)/i',
        '/Expiry date:\s*(.+)/i',
        '/Expire Date:\s*(.+)/i',
        '/Renewal date:\s*(.+)/i',
        '/paid-till:\s*(.+)/i',
        '/expire:\s*(.+)/i',
        '/expiration_date:\s*(.+)/i',
        '/domain_datebilleduntil:\s*(.+)/i',
        '/renewal:\s*(.+)/i',
        '/expires\.+:\s*(.+)/i',  // .fi format: expires............: DD.MM.YYYY
    ];

    public function getName(): string
    {
        return 'TCP WHOIS';
    }

    public function isEnabled(): bool
    {
        return config('expiry.domain.tcp_whois.enabled', false);
    }

    public function detect(string $domain): ExpiryResult
    {
        $startTime = microtime(true);
        
        try {
            // Extract TLD
            $parts = explode('.', $domain);
            $tld = strtolower(end($parts));
            
            // Get WHOIS server for this TLD
            $whoisServer = $this->whoisServers[$tld] ?? null;
            
            if (!$whoisServer) {
                return new ExpiryResult(
                    success: false,
                    expiryDate: null,
                    source: 'TCP WHOIS',
                    error: "No WHOIS server configured for .{$tld} TLD",
                    latencyMs: (microtime(true) - $startTime) * 1000
                );
            }
            
            // Query WHOIS server via TCP
            $whoisData = $this->queryWhoisServer($whoisServer, $domain);
            
            if (!$whoisData) {
                return new ExpiryResult(
                    success: false,
                    expiryDate: null,
                    source: 'TCP WHOIS',
                    error: "Failed to connect to WHOIS server: {$whoisServer}",
                    latencyMs: (microtime(true) - $startTime) * 1000
                );
            }
            
            // Parse expiry date from WHOIS response
            $expiryDate = $this->parseExpiryDate($whoisData);
            
            if (!$expiryDate) {
                Log::debug('TCP WHOIS: Could not parse expiry date', [
                    'domain' => $domain,
                    'server' => $whoisServer,
                    'response_length' => strlen($whoisData),
                ]);
                
                return new ExpiryResult(
                    success: false,
                    expiryDate: null,
                    source: 'TCP WHOIS',
                    error: 'Could not parse expiry date from WHOIS response',
                    latencyMs: (microtime(true) - $startTime) * 1000
                );
            }
            
            return new ExpiryResult(
                success: true,
                expiryDate: $expiryDate,
                source: "TCP WHOIS ({$whoisServer})",
                error: null,
                latencyMs: (microtime(true) - $startTime) * 1000
            );
            
        } catch (\Exception $e) {
            Log::warning('TCP WHOIS provider error', [
                'domain' => $domain,
                'error' => $e->getMessage(),
            ]);
            
            return new ExpiryResult(
                success: false,
                expiryDate: null,
                source: 'TCP WHOIS',
                error: $e->getMessage(),
                latencyMs: (microtime(true) - $startTime) * 1000
            );
        }
    }
    
    /**
     * Query WHOIS server via TCP socket connection
     */
    private function queryWhoisServer(string $server, string $domain): ?string
    {
        $timeout = config('expiry.connect_timeout', 8);
        $port = 43; // Standard WHOIS port
        
        // Open socket connection
        $socket = @fsockopen($server, $port, $errno, $errstr, $timeout);
        
        if (!$socket) {
            Log::debug("TCP WHOIS: Failed to connect to {$server}:{$port}", [
                'errno' => $errno,
                'errstr' => $errstr,
            ]);
            return null;
        }
        
        // Set timeout for read operations
        stream_set_timeout($socket, $timeout);
        
        // Send domain query
        fwrite($socket, $domain . "\r\n");
        
        // Read response
        $response = '';
        while (!feof($socket)) {
            $line = fgets($socket, 4096);
            if ($line === false) {
                break;
            }
            $response .= $line;
        }
        
        fclose($socket);
        
        return $response ?: null;
    }
    
    /**
     * Parse expiry date from WHOIS response using multiple patterns
     */
    private function parseExpiryDate(string $whoisData): ?Carbon
    {
        foreach ($this->expiryPatterns as $pattern) {
            if (preg_match($pattern, $whoisData, $matches)) {
                $dateString = trim($matches[1]);
                
                // Remove timezone abbreviations and extra text
                $dateString = preg_replace('/\s+\([^)]+\)/', '', $dateString);
                $dateString = preg_replace('/\s+(UTC|GMT|EST|PST|CET).*$/i', '', $dateString);
                
                try {
                    // Try to parse the date
                    $date = Carbon::parse($dateString);
                    
                    // Sanity check: expiry should be in the future and within 20 years
                    if ($date->isFuture() && $date->diffInYears(now()) <= 20) {
                        return $date;
                    }
                } catch (\Exception $e) {
                    // Try next pattern
                    continue;
                }
            }
        }
        
        return null;
    }
}
