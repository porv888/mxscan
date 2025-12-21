<?php

namespace App\Services\Spf;

use App\Services\Dns\DnsClient;
use App\Services\Spf\DTOs\SpfResultDTO;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

class SpfResolver
{
    private int $lookupCount = 0;
    private array $resolvedIps = [];
    private array $warnings = [];
    private array $processedDomains = [];
    private array $redirectChain = [];
    private DnsClient $dnsClient;
    private float $startTime;

    // Warning constants
    public const WARNING_PTR_USED = 'PTR_USED';
    public const WARNING_PLUS_ALL = 'PLUS_ALL';
    public const WARNING_INCLUDE_NXDOMAIN = 'INCLUDE_NXDOMAIN';
    public const WARNING_LOOP_DETECTED = 'LOOP_DETECTED';
    public const WARNING_TIMEOUT = 'TIMEOUT';
    public const WARNING_REDIRECT_CHAIN_LONG = 'REDIRECT_CHAIN_LONG';
    public const WARNING_UNKNOWN_MECH = 'UNKNOWN_MECH';
    public const WARNING_LOOKUP_LIMIT = 'LOOKUP_LIMIT';
    public const WARNING_NO_SPF = 'NO_SPF';
    public const WARNING_MULTIPLE_SPF = 'MULTIPLE_SPF';

    public function __construct(DnsClient $dnsClient = null)
    {
        $this->dnsClient = $dnsClient ?? new DnsClient();
        $this->startTime = microtime(true);
    }

    public function resolve(string $domain): SpfResultDTO
    {
        // Reset state for new resolution
        $this->lookupCount = 0;
        $this->resolvedIps = [];
        $this->warnings = [];
        $this->processedDomains = [];
        $this->redirectChain = [];
        $this->startTime = microtime(true);

        $domain = strtolower(trim($domain));
        
        // Get SPF record
        $spfRecord = $this->resolveCurrent($domain);
        
        if (!$spfRecord) {
            return new SpfResultDTO(
                currentRecord: null,
                lookupsUsed: 0,
                flattenedSpf: null,
                warnings: [self::WARNING_NO_SPF],
                resolvedIps: []
            );
        }

        // Parse and expand SPF record
        $this->expand($spfRecord, $domain);

        // Generate flattened SPF
        $flattenedSpf = $this->generateFlattenedSpf($spfRecord);

        // Log performance
        $elapsedMs = round((microtime(true) - $this->startTime) * 1000, 2);
        Log::info("SPF resolution completed", [
            'domain' => $domain,
            'lookupCount' => $this->lookupCount,
            'warnings' => $this->warnings,
            'elapsedMs' => $elapsedMs
        ]);

        return new SpfResultDTO(
            currentRecord: $spfRecord,
            lookupsUsed: $this->lookupCount,
            flattenedSpf: $flattenedSpf,
            warnings: $this->warnings,
            resolvedIps: array_values(array_unique($this->resolvedIps))
        );
    }

    /**
     * Resolve the current SPF record for a domain.
     */
    public function resolveCurrent(string $domain): ?string
    {
        $domain = strtolower(trim($domain));
        
        // Check cache first for performance optimization
        $cacheKey = "spf_current_{$domain}";
        $cachedResult = Cache::get($cacheKey);
        
        if ($cachedResult !== null) {
            return $cachedResult ?: null;
        }

        $spfRecord = $this->getSpfRecord($domain);
        
        // Cache for 5 minutes
        Cache::put($cacheKey, $spfRecord ?: '', 300);
        
        return $spfRecord;
    }

    /**
     * Parse an SPF record into its components.
     */
    public function parse(string $record): array
    {
        $tokens = explode(' ', trim($record));
        $mechanisms = [];
        $modifiers = [];
        
        foreach ($tokens as $token) {
            $token = trim($token);
            
            if (empty($token) || $token === 'v=spf1') {
                continue;
            }
            
            // Check if it's a modifier (contains =)
            if (str_contains($token, '=') && !str_starts_with($token, 'redirect=')) {
                $modifiers[] = $token;
            } else {
                $mechanisms[] = $token;
            }
        }
        
        return [
            'mechanisms' => $mechanisms,
            'modifiers' => $modifiers
        ];
    }

    /**
     * Expand an SPF record by resolving all includes and DNS lookups.
     */
    public function expand(string $record, string $baseDomain): void
    {
        $this->parseSpfRecord($record, $baseDomain);
    }

    private function getSpfRecord(string $domain): ?string
    {
        try {
            $txtRecords = $this->dnsClient->getTxt($domain);
            
            if (empty($txtRecords)) {
                return null;
            }

            $spfRecords = [];
            foreach ($txtRecords as $record) {
                if (str_starts_with(strtolower($record), 'v=spf1')) {
                    $spfRecords[] = $record;
                }
            }

            if (empty($spfRecords)) {
                return null;
            }

            // RFC 7208: Multiple SPF records are not allowed
            if (count($spfRecords) > 1) {
                $this->warnings[] = self::WARNING_MULTIPLE_SPF;
                // Return the first one but warn about multiple
                return $spfRecords[0];
            }

            return $spfRecords[0];
        } catch (\Exception $e) {
            Log::warning("SPF record lookup failed for {$domain}: " . $e->getMessage());
            $this->warnings[] = self::WARNING_TIMEOUT;
            return null;
        }
    }

    private function parseSpfRecord(string $spfRecord, string $baseDomain): void
    {
        // Prevent infinite loops
        if (in_array($baseDomain, $this->processedDomains)) {
            $this->warnings[] = self::WARNING_LOOP_DETECTED;
            return;
        }
        
        $this->processedDomains[] = $baseDomain;

        $tokens = explode(' ', trim($spfRecord));
        
        foreach ($tokens as $token) {
            $token = trim($token);
            
            if (empty($token) || $token === 'v=spf1') {
                continue;
            }

            $this->processSpfToken($token, $baseDomain);
        }
    }

    private function processSpfToken(string $token, string $baseDomain): void
    {
        // Check lookup limit before processing mechanisms that require DNS lookups
        $requiresLookup = $this->tokenRequiresLookup($token);
        
        if ($requiresLookup && $this->lookupCount >= 10) {
            $this->warnings[] = self::WARNING_LOOKUP_LIMIT;
            return;
        }

        // Handle different SPF mechanisms
        if (str_starts_with($token, 'include:')) {
            $this->processInclude($token, $baseDomain);
        } elseif (str_starts_with($token, 'redirect=')) {
            $this->processRedirect($token);
        } elseif (preg_match('/^[+\-~?]?a(?::|\/|$)/', $token)) {
            $this->processA($token, $baseDomain);
        } elseif (preg_match('/^[+\-~?]?mx(?::|\/|$)/', $token)) {
            $this->processMx($token, $baseDomain);
        } elseif (str_starts_with($token, 'ip4:') || preg_match('/^[+\-~?]?ip4:/', $token)) {
            $this->processIp4($token);
        } elseif (str_starts_with($token, 'ip6:') || preg_match('/^[+\-~?]?ip6:/', $token)) {
            $this->processIp6($token);
        } elseif (preg_match('/^[+\-~?]?ptr(?::|$)/', $token)) {
            $this->warnings[] = self::WARNING_PTR_USED;
            if ($this->lookupCount < 10) {
                $this->lookupCount++; // PTR requires DNS lookup
            }
        } elseif (str_starts_with($token, 'exists:')) {
            if ($this->lookupCount < 10) {
                $this->lookupCount++; // Count as lookup but don't resolve
            }
        } elseif (in_array($token, ['+all', '-all', '~all', '?all'])) {
            if ($token === '+all') {
                $this->warnings[] = self::WARNING_PLUS_ALL;
            }
            // All mechanisms - no further action needed
        } else {
            // Unknown mechanism
            $this->warnings[] = self::WARNING_UNKNOWN_MECH;
        }
    }

    /**
     * Check if a token requires a DNS lookup according to RFC 7208.
     */
    private function tokenRequiresLookup(string $token): bool
    {
        return str_starts_with($token, 'include:') ||
               str_starts_with($token, 'redirect=') ||
               preg_match('/^[+\-~?]?a(?::|\/|$)/', $token) ||
               preg_match('/^[+\-~?]?mx(?::|\/|$)/', $token) ||
               preg_match('/^[+\-~?]?ptr(?::|$)/', $token) ||
               str_starts_with($token, 'exists:');
    }

    private function processInclude(string $token, string $baseDomain): void
    {
        // Extract domain from include: mechanism, handling qualifiers
        $includeDomain = preg_replace('/^[+\-~?]?include:/', '', $token);
        $includeDomain = $this->expandMacros($includeDomain, $baseDomain);
        
        $this->lookupCount++;
        
        $includeSpf = $this->getSpfRecord($includeDomain);
        if ($includeSpf) {
            $this->parseSpfRecord($includeSpf, $includeDomain);
        } else {
            $this->warnings[] = self::WARNING_INCLUDE_NXDOMAIN;
        }
    }

    private function processRedirect(string $token): void
    {
        $redirectDomain = substr($token, 9); // Remove 'redirect='
        $redirectDomain = $this->expandMacros($redirectDomain, $this->processedDomains[0] ?? '');
        
        // Track redirect chain length
        $this->redirectChain[] = $redirectDomain;
        if (count($this->redirectChain) > 3) {
            $this->warnings[] = self::WARNING_REDIRECT_CHAIN_LONG;
            return;
        }
        
        $this->lookupCount++;
        
        $redirectSpf = $this->getSpfRecord($redirectDomain);
        if ($redirectSpf) {
            // Reset and process redirect (replaces current SPF)
            $this->parseSpfRecord($redirectSpf, $redirectDomain);
        } else {
            $this->warnings[] = self::WARNING_INCLUDE_NXDOMAIN;
        }
    }

    private function processA(string $token, string $baseDomain): void
    {
        $domain = $baseDomain;
        
        // Extract domain from a: mechanism, handling qualifiers and CIDR
        if (preg_match('/^[+\-~?]?a(?::([^\/]+))?/', $token, $matches)) {
            if (isset($matches[1])) {
                $domain = $this->expandMacros($matches[1], $baseDomain);
            }
        }
        
        $this->lookupCount++;
        $this->resolveARecord($domain);
    }

    private function processMx(string $token, string $baseDomain): void
    {
        $domain = $baseDomain;
        
        // Extract domain from mx: mechanism, handling qualifiers and CIDR
        if (preg_match('/^[+\-~?]?mx(?::([^\/]+))?/', $token, $matches)) {
            if (isset($matches[1])) {
                $domain = $this->expandMacros($matches[1], $baseDomain);
            }
        }
        
        $this->lookupCount++;
        $this->resolveMxRecord($domain);
    }

    private function processIp4(string $token): void
    {
        // Extract IP from ip4: mechanism, handling qualifiers
        $ip = preg_replace('/^[+\-~?]?ip4:/', '', $token);
        
        // Validate IP format
        if (filter_var(explode('/', $ip)[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $this->resolvedIps[] = $ip;
        }
    }

    private function processIp6(string $token): void
    {
        // Extract IP from ip6: mechanism, handling qualifiers
        $ip = preg_replace('/^[+\-~?]?ip6:/', '', $token);
        
        // Validate IP format
        if (filter_var(explode('/', $ip)[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $this->resolvedIps[] = $ip;
        }
    }

    private function resolveARecord(string $domain): void
    {
        try {
            // IPv4 A records
            $aRecords = $this->dnsClient->getA($domain);
            foreach ($aRecords as $ip) {
                $this->resolvedIps[] = $ip;
            }

            // IPv6 AAAA records
            $aaaaRecords = $this->dnsClient->getAAAA($domain);
            foreach ($aaaaRecords as $ip) {
                $this->resolvedIps[] = $ip;
            }
        } catch (\Exception $e) {
            Log::warning("A/AAAA record lookup failed for {$domain}: " . $e->getMessage());
        }
    }

    private function resolveMxRecord(string $domain): void
    {
        try {
            $mxHosts = $this->dnsClient->getMx($domain);
            
            // Resolve A/AAAA records for each MX host
            foreach ($mxHosts as $mxHost) {
                // Don't count MX host resolution as additional lookups
                // The MX lookup itself already counted
                $this->resolveARecord($mxHost);
            }
        } catch (\Exception $e) {
            Log::warning("MX record lookup failed for {$domain}: " . $e->getMessage());
        }
    }

    private function expandMacros(string $value, string $baseDomain): string
    {
        // Basic macro expansion - for v1, we'll keep it simple
        // In production, you might want more comprehensive macro support
        return str_replace('%{d}', $baseDomain, $value);
    }

    private function generateFlattenedSpf(string $originalSpf): string
    {
        $uniqueIps = array_unique($this->resolvedIps);
        
        if (empty($uniqueIps)) {
            // Determine the final qualifier from original SPF
            $qualifier = $this->extractAllQualifier($originalSpf);
            return "v=spf1 {$qualifier}";
        }

        $ipv4s = [];
        $ipv6s = [];

        foreach ($uniqueIps as $ip) {
            // Handle CIDR notation
            $ipPart = explode('/', $ip)[0];
            
            if (filter_var($ipPart, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $ipv4s[] = "ip4:{$ip}";
            } elseif (filter_var($ipPart, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                $ipv6s[] = "ip6:{$ip}";
            }
        }

        // Sort IPs for consistent output
        sort($ipv4s);
        sort($ipv6s);
        
        $mechanisms = array_merge($ipv4s, $ipv6s);
        
        // Determine the final qualifier from original SPF
        $qualifier = $this->extractAllQualifier($originalSpf);

        return 'v=spf1 ' . implode(' ', $mechanisms) . ' ' . $qualifier;
    }

    /**
     * Extract the 'all' qualifier from the original SPF record.
     */
    private function extractAllQualifier(string $spfRecord): string
    {
        // Look for all mechanisms in order of precedence
        if (preg_match('/\s([+\-~?]?all)\s*$/', $spfRecord, $matches)) {
            return $matches[1];
        }
        
        // Default to hard fail if no all mechanism found
        return '-all';
    }
}
