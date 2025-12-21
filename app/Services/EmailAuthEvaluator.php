<?php

namespace App\Services;

use App\Support\DomainAlign;
use Illuminate\Support\Facades\Log;
use SPFLib\Check\Environment as SPFEnvironment;
use SPFLib\Checker as SPFChecker;
use Spatie\Dns\Dns;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Contracts\Cache\ItemInterface;

class EmailAuthEvaluator
{
    protected DkimVerifier $dkimVerifier;
    protected FilesystemAdapter $cache;
    protected Dns $dns;

    public function __construct(DkimVerifier $dkimVerifier)
    {
        $this->dkimVerifier = $dkimVerifier;
        $this->cache = new FilesystemAdapter('email_auth', 900); // 15 minutes TTL
        $this->dns = new Dns();
    }

    /**
     * Evaluate SPF, DKIM, and DMARC for an email message
     *
     * @param array|string $input Either raw headers string (legacy) or array with keys: raw_headers, raw_body, header_from, envelope_from
     * @param string|null $rawBody Raw email body (optional, for legacy signature)
     * @return array
     */
    public function evaluate($input, ?string $rawBody = null): array
    {
        // Handle both array and legacy string signatures
        if (is_array($input)) {
            $rawHeaders = $input['raw_headers'] ?? '';
            $rawBody = $input['raw_body'] ?? null;
            $providedHeaderFrom = $input['header_from'] ?? null;
            $providedEnvelopeFrom = $input['envelope_from'] ?? null;
        } else {
            // Legacy signature: evaluate($rawHeaders, $rawBody)
            $rawHeaders = $input;
            $providedHeaderFrom = null;
            $providedEnvelopeFrom = null;
        }
        
        $notes = [];
        
        // Parse headers
        $headers = $this->parseHeaders($rawHeaders);
        
        // Extract key information (use provided values if available)
        $headerFrom = $providedHeaderFrom ?? $this->extractHeaderFrom($headers);
        $headerFromDomain = DomainAlign::extractDomain($headerFrom);
        $envelopeFrom = $providedEnvelopeFrom ?? $this->extractEnvelopeFrom($headers);
        $envelopeFromDomain = DomainAlign::extractDomain($envelopeFrom) ?? $headerFromDomain;
        $connectingIp = $this->extractConnectingIp($headers);
        
        // Extract MX host from first Received header
        $mxHost = $this->extractMxHost($headers);
        
        // Calculate TTI from Received headers
        $ttiMs = $this->calculateTti($headers);

        // Initialize results
        $spfResult = null;  // null = none
        $dkimResult = null; // null = none
        $dmarcResult = null; // null = none
        
        $details = [
            'ip' => $connectingIp,
            'mailfrom' => $envelopeFrom,
            'header_from' => $headerFrom,
            'mailfrom_domain' => $envelopeFromDomain,
            'header_from_domain' => $headerFromDomain,
            'mx_host' => $mxHost,
            'dkim' => [],
            'dmarc' => [],
            'notes' => [],
        ];

        // SPF Check - always attempt if we have IP and domain
        if ($connectingIp && $envelopeFromDomain) {
            $spfCheck = $this->checkSpf($connectingIp, $envelopeFromDomain, $headers);
            $spfResult = $spfCheck['pass'];  // true/false/null
            $details['spf_details'] = $spfCheck['details'];
            $notes = array_merge($notes, $spfCheck['notes']);
        } else {
            $notes[] = 'SPF: Unable to determine connecting IP or envelope-from domain';
        }

        // DKIM Check - check if DKIM-Signature exists
        $hasDkimSignature = preg_match('/^DKIM-Signature:/mi', $rawHeaders);
        if ($hasDkimSignature && $rawBody !== null) {
            $rawMessage = $rawHeaders . "\r\n\r\n" . $rawBody;
            $dkimCheck = $this->dkimVerifier->verify($rawMessage, $headerFromDomain);
            
            // Map result to boolean
            if ($dkimCheck['result'] === 'pass') {
                $dkimResult = true;
            } elseif ($dkimCheck['result'] === 'fail') {
                $dkimResult = false;
            } else {
                $dkimResult = null;
            }
            
            $details['dkim'] = $dkimCheck['signatures'];
            $notes = array_merge($notes, $dkimCheck['notes']);
        } else {
            if (!$hasDkimSignature) {
                $notes[] = 'DKIM: No DKIM-Signature header found';
            } elseif ($rawBody === null) {
                $notes[] = 'DKIM: Body not provided, cannot verify signatures';
            }
            $dkimResult = null; // None
        }

        // DMARC Check
        if ($headerFromDomain) {
            $dmarcCheck = $this->checkDmarc(
                $headerFromDomain,
                $spfResult,
                $envelopeFromDomain,
                $dkimResult,
                $details['dkim']
            );
            $dmarcResult = $dmarcCheck['pass'];  // true/false/null
            $details['dmarc'] = $dmarcCheck['details'];
            $details['dmarc']['aligned'] = $dmarcCheck['aligned'] ?? null;
            $details['dmarc']['domain'] = $headerFromDomain;
            $notes = array_merge($notes, $dmarcCheck['notes']);
        } else {
            $notes[] = 'DMARC: Unable to determine header From domain';
        }

        $details['notes'] = $notes;
        
        // Determine verdict
        $verdict = 'ok';
        if ($spfResult === false || $dkimResult === false || $dmarcResult === false) {
            $verdict = 'incident';
        } elseif ($ttiMs !== null && $ttiMs > 900000) { // 15 minutes
            $verdict = 'warning';
        }

        // Deep logging for debugging
        Log::info('auth-eval', [
            'ip'           => $connectingIp,
            'mail_from'    => $envelopeFromDomain,
            'header_from'  => $headerFromDomain,
            'spf_result'   => $spfResult === true ? 'pass' : ($spfResult === false ? 'fail' : 'none'),
            'spf_pass'     => $spfResult,
            'dkim_count'   => count($details['dkim']),
            'dkim_pass'    => $dkimResult,
            'dkim_domains' => array_column($details['dkim'], 'd'),
            'dmarc_pass'   => $dmarcResult,
            'dmarc_align'  => $details['dmarc']['aligned'] ?? null,
            'verdict'      => $verdict,
            'tti_ms'       => $ttiMs,
        ]);

        return [
            'spf'   => ['pass' => $spfResult, 'ip' => $connectingIp, 'domain' => $envelopeFromDomain],
            'dkim'  => ['pass' => $dkimResult, 'count' => count($details['dkim']), 'domains' => array_column($details['dkim'], 'd')],
            'dmarc' => ['pass' => $dmarcResult, 'aligned' => $details['dmarc']['aligned'] ?? null, 'domain' => $headerFromDomain],
            'metrics' => ['tti_ms' => $ttiMs],
            'analysis' => ['mx_host' => $mxHost, 'mx_ip' => $connectingIp, 'verdict' => $verdict],
            // Keep legacy format for backward compatibility
            'details' => $details,
        ];
    }

    /**
     * Parse email headers into associative array
     *
     * @param string $rawHeaders
     * @return array
     */
    protected function parseHeaders(string $rawHeaders): array
    {
        $headers = [];
        
        // Split by lines that don't start with whitespace (handle folded headers)
        $lines = preg_split('/\r?\n(?=[^ \t])/', $rawHeaders);

        foreach ($lines as $line) {
            if (preg_match('/^([^:]+):\s*(.*)$/s', $line, $matches)) {
                $name = strtolower(trim($matches[1]));
                $value = trim(preg_replace('/\r?\n[ \t]+/', ' ', $matches[2]));
                
                if (!isset($headers[$name])) {
                    $headers[$name] = [];
                }
                $headers[$name][] = $value;
            }
        }

        return $headers;
    }

    /**
     * Extract From header email address
     *
     * @param array $headers
     * @return string
     */
    protected function extractHeaderFrom(array $headers): string
    {
        if (isset($headers['from'][0])) {
            $from = $headers['from'][0];
            
            // Extract email from "Name" <email@domain.com> format
            if (preg_match('/<([^>]+)>/', $from, $matches)) {
                return $matches[1];
            }
            
            // Or just return as-is if it's already an email
            return $from;
        }

        return '';
    }

    /**
     * Extract envelope-from (Return-Path or fallback to From)
     *
     * @param array $headers
     * @return string
     */
    protected function extractEnvelopeFrom(array $headers): string
    {
        // Try Return-Path first
        if (isset($headers['return-path'][0])) {
            $returnPath = $headers['return-path'][0];
            // Remove angle brackets
            $returnPath = trim($returnPath, '<>');
            if (!empty($returnPath)) {
                return $returnPath;
            }
        }

        // Fallback to From header
        return $this->extractHeaderFrom($headers);
    }

    /**
     * Extract connecting IP from Received headers (skip local/LMTP hops)
     *
     * @param array $headers
     * @return string|null
     */
    protected function extractConnectingIp(array $headers): ?string
    {
        if (!isset($headers['received']) || empty($headers['received'])) {
            return null;
        }

        // Iterate through Received headers from top to bottom
        foreach ($headers['received'] as $received) {
            $line = is_array($received) ? implode(' ', $received) : $received;
            
            // DON'T skip LMTP headers entirely - they may contain the external IP!
            // Just try to extract IPs from all headers
            
            // Try to extract ALL public IPs from this Received header
            // Pattern 1: ([1.2.3.4]:port) - Gmail/Google format
            if (preg_match_all('/\(\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]:\d+\)/', $line, $matches)) {
                foreach ($matches[1] as $ip) {
                    if (!$this->isPrivateIp($ip)) {
                        return $ip;
                    }
                }
            }
            
            // Pattern 2: [1.2.3.4] - standard format
            if (preg_match_all('/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/', $line, $matches)) {
                foreach ($matches[1] as $ip) {
                    if (!$this->isPrivateIp($ip)) {
                        return $ip;
                    }
                }
            }

            // Pattern 3: [IPv6:...]
            if (preg_match_all('/\[IPv6:([0-9a-fA-F:]+)\]/', $line, $matches)) {
                foreach ($matches[1] as $ip) {
                    // Skip IPv6 localhost
                    if ($ip !== '::1' && !str_starts_with($ip, 'fe80:')) {
                        return $ip;
                    }
                }
            }

            // Pattern 4: plain IP without brackets (last resort)
            if (preg_match_all('/(?<!\d)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?!\d)/', $line, $matches)) {
                foreach ($matches[1] as $ip) {
                    if (!$this->isPrivateIp($ip)) {
                        return $ip;
                    }
                }
            }
        }

        return null;
    }

    /**
     * Check if IP is private/local
     *
     * @param string $ip
     * @return bool
     */
    protected function isPrivateIp(string $ip): bool
    {
        $parts = explode('.', $ip);
        if (count($parts) !== 4) {
            return false;
        }
        
        $first = (int)$parts[0];
        $second = (int)$parts[1];
        
        // 127.0.0.0/8
        if ($first === 127) {
            return true;
        }
        
        // 10.0.0.0/8
        if ($first === 10) {
            return true;
        }
        
        // 172.16.0.0/12
        if ($first === 172 && $second >= 16 && $second <= 31) {
            return true;
        }
        
        // 192.168.0.0/16
        if ($first === 192 && $second === 168) {
            return true;
        }
        
        return false;
    }

    /**
     * Extract MX host from first public Received header
     *
     * @param array $headers
     * @return string|null
     */
    protected function extractMxHost(array $headers): ?string
    {
        if (!isset($headers['received']) || empty($headers['received'])) {
            return null;
        }

        foreach ($headers['received'] as $received) {
            $line = is_array($received) ? implode(' ', $received) : $received;
            
            // Skip LMTP and local hops
            if (stripos($line, 'with lmtp') !== false || 
                stripos($line, '127.') !== false ||
                stripos($line, 'localhost') !== false) {
                continue;
            }
            
            // Extract hostname from "from hostname.com"
            if (preg_match('/^from\s+([^\s\(]+)/i', $line, $matches)) {
                $host = $matches[1];
                // Skip if it's an IP address
                if (!preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/', $host)) {
                    return $host;
                }
            }
        }

        return null;
    }

    /**
     * Calculate Time-To-Inbox from Received headers
     *
     * @param array $headers
     * @return int|null TTI in milliseconds
     */
    protected function calculateTti(array $headers): ?int
    {
        if (!isset($headers['received']) || empty($headers['received'])) {
            return null;
        }

        $timestamps = [];
        
        foreach ($headers['received'] as $received) {
            $line = is_array($received) ? implode(' ', $received) : $received;
            
            // Extract timestamp from Received header
            // Format: "... ; Thu, 1 Oct 2025 09:00:00 +0000"
            if (preg_match('/;\s*(.+)$/i', $line, $matches)) {
                try {
                    $timestamp = \Carbon\Carbon::parse($matches[1]);
                    $timestamps[] = $timestamp;
                } catch (\Exception $e) {
                    // Skip invalid timestamps
                    continue;
                }
            }
        }

        if (count($timestamps) < 2) {
            return null;
        }

        // TTI is the difference between first (oldest) and last (newest) Received header
        $oldest = end($timestamps);
        $newest = reset($timestamps);
        
        return max(0, $newest->diffInMilliseconds($oldest));
    }

    /**
     * Check SPF using mlocati/spf-lib
     *
     * @param string $ip
     * @param string $domain
     * @param array $headers
     * @return array
     */
    protected function checkSpf(string $ip, string $domain, array $headers): array
    {
        $notes = [];
        
        try {
            // Get HELO domain from Received header if available
            $helo = $domain;
            if (isset($headers['received'][0])) {
                if (preg_match('/\(HELO\s+([^\)]+)\)/i', $headers['received'][0], $matches)) {
                    $helo = trim($matches[1]);
                } elseif (preg_match('/\(EHLO\s+([^\)]+)\)/i', $headers['received'][0], $matches)) {
                    $helo = trim($matches[1]);
                }
            }

            // Create SPF environment
            $environment = new SPFEnvironment($ip, $domain, $helo);
            
            // Check SPF
            $checker = new SPFChecker();
            $result = $checker->check($environment);

            // Map result to pass/fail/none (boolean or null)
            $resultCode = $result->getCode();
            
            if ($resultCode === \SPFLib\Check\Result::CODE_PASS) {
                $spfPass = true;
            } elseif (in_array($resultCode, [
                \SPFLib\Check\Result::CODE_FAIL,
                \SPFLib\Check\Result::CODE_SOFTFAIL,
            ])) {
                $spfPass = false;
                $notes[] = 'SPF failed: ' . $resultCode;
            } else {
                $spfPass = null;
                $notes[] = 'SPF result: ' . $resultCode;
            }

            return [
                'pass' => $spfPass,
                'result' => $spfPass === true ? 'pass' : ($spfPass === false ? 'fail' : 'none'), // legacy
                'details' => [
                    'code' => $resultCode,
                    'ip' => $ip,
                    'domain' => $domain,
                    'helo' => $helo,
                ],
                'notes' => $notes,
            ];
        } catch (\Exception $e) {
            Log::warning('SPF check error', [
                'ip' => $ip,
                'domain' => $domain,
                'error' => $e->getMessage(),
            ]);

            return [
                'pass' => null,
                'result' => 'none', // legacy
                'details' => ['error' => $e->getMessage()],
                'notes' => ['SPF check error: ' . $e->getMessage()],
            ];
        }
    }

    /**
     * Check DMARC policy and alignment
     *
     * @param string $headerFromDomain
     * @param string $spfResult
     * @param string $envelopeFromDomain
     * @param string $dkimResult
     * @param array $dkimSignatures
     * @return array
     */
    protected function checkDmarc(
        string $headerFromDomain,
        ?bool $spfResult,
        string $envelopeFromDomain,
        ?bool $dkimResult,
        array $dkimSignatures
    ): array {
        $notes = [];

        try {
            // Fetch DMARC record
            $dmarcRecord = $this->fetchDmarcRecord($headerFromDomain);

            if (!$dmarcRecord) {
                return [
                    'pass' => null,
                    'result' => 'none', // legacy
                    'aligned' => null,
                    'details' => ['policy' => 'none'],
                    'notes' => ['No DMARC record found for ' . $headerFromDomain],
                ];
            }

            // Parse DMARC policy
            $policy = $dmarcRecord['p'] ?? 'none';
            $aspf = $dmarcRecord['aspf'] ?? 'r'; // SPF alignment mode
            $adkim = $dmarcRecord['adkim'] ?? 'r'; // DKIM alignment mode

            // Check SPF alignment
            $spfAligned = false;
            if ($spfResult === true) {
                $spfAligned = DomainAlign::aligned($envelopeFromDomain, $headerFromDomain, $aspf);
                if ($spfAligned) {
                    $notes[] = 'SPF aligned (mode: ' . $aspf . ')';
                } else {
                    $notes[] = 'SPF passed but not aligned';
                }
            }

            // Check DKIM alignment
            $dkimAligned = false;
            if ($dkimResult === true) {
                foreach ($dkimSignatures as $sig) {
                    if ($sig['pass'] && isset($sig['d'])) {
                        if (DomainAlign::aligned($sig['d'], $headerFromDomain, $adkim)) {
                            $dkimAligned = true;
                            $notes[] = 'DKIM aligned: d=' . $sig['d'] . ' (mode: ' . $adkim . ')';
                            break;
                        }
                    }
                }
                if (!$dkimAligned) {
                    $notes[] = 'DKIM passed but not aligned';
                }
            }

            // DMARC passes if either SPF or DKIM is aligned
            $dmarcPass = ($spfAligned || $dkimAligned) ? true : false;

            if ($dmarcPass === false) {
                $notes[] = 'DMARC failed: neither SPF nor DKIM aligned';
            }

            return [
                'pass' => $dmarcPass,
                'result' => $dmarcPass ? 'pass' : 'fail', // legacy
                'aligned' => $spfAligned || $dkimAligned,
                'details' => [
                    'policy' => $policy,
                    'aspf' => $aspf,
                    'adkim' => $adkim,
                    'aligned' => [
                        'spf' => $spfAligned,
                        'dkim' => $dkimAligned,
                    ],
                ],
                'notes' => $notes,
            ];
        } catch (\Exception $e) {
            Log::warning('DMARC check error', [
                'domain' => $headerFromDomain,
                'error' => $e->getMessage(),
            ]);

            return [
                'pass' => null,
                'result' => 'none', // legacy
                'aligned' => null,
                'details' => ['error' => $e->getMessage()],
                'notes' => ['DMARC check error: ' . $e->getMessage()],
            ];
        }
    }

    /**
     * Fetch and parse DMARC record from DNS
     *
     * @param string $domain
     * @return array|null
     */
    protected function fetchDmarcRecord(string $domain): ?array
    {
        $dnsName = "_dmarc.{$domain}";

        try {
            return $this->cache->get(
                'dmarc_' . md5($dnsName),
                function (ItemInterface $item) use ($dnsName) {
                    $item->expiresAfter(900); // 15 minutes

                    $records = $this->dns->getRecords($dnsName, 'TXT');

                    foreach ($records as $record) {
                        // Spatie DNS returns objects, not arrays
                        $txt = is_object($record) ? $record->txt() : ($record['txt'] ?? '');
                        if ($txt && str_starts_with($txt, 'v=DMARC1')) {
                            return $this->parseDmarcRecord($txt);
                        }
                    }

                    return null;
                }
            );
        } catch (\Exception $e) {
            Log::warning('Failed to fetch DMARC record', [
                'domain' => $domain,
                'error' => $e->getMessage(),
            ]);
            return null;
        }
    }

    /**
     * Parse DMARC record into tags
     *
     * @param string $record
     * @return array
     */
    protected function parseDmarcRecord(string $record): array
    {
        $tags = [];
        
        // Split by semicolon
        $parts = explode(';', $record);
        
        foreach ($parts as $part) {
            $part = trim($part);
            if (strpos($part, '=') !== false) {
                [$key, $value] = explode('=', $part, 2);
                $tags[trim($key)] = trim($value);
            }
        }

        return $tags;
    }
}
