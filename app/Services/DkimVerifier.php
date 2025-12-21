<?php

namespace App\Services;

use Illuminate\Support\Facades\Log;
use Spatie\Dns\Dns;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Contracts\Cache\ItemInterface;

class DkimVerifier
{
    protected FilesystemAdapter $cache;
    protected Dns $dns;

    public function __construct()
    {
        $this->cache = new FilesystemAdapter('dkim', 900); // 15 minutes TTL
        $this->dns = new Dns();
    }

    /**
     * Verify all DKIM signatures in the message
     *
     * @param string $rawMessage Full raw message (headers + body)
     * @param string $headerFromDomain Domain from the From header
     * @return array ['result' => 'pass|fail|none', 'signatures' => [...], 'aligned' => bool]
     */
    public function verify(string $rawMessage, string $headerFromDomain): array
    {
        $signatures = $this->extractDkimSignatures($rawMessage);

        if (empty($signatures)) {
            return [
                'result' => 'none',
                'signatures' => [],
                'aligned' => false,
                'notes' => ['No DKIM signatures found'],
            ];
        }

        $verifiedSignatures = [];
        $hasPassingAligned = false;

        foreach ($signatures as $sig) {
            $verified = $this->verifySignature($rawMessage, $sig);
            $aligned = $verified['pass'] && $this->isAligned($sig['d'], $headerFromDomain);

            $verifiedSignatures[] = [
                'd' => $sig['d'],
                's' => $sig['s'],
                'pass' => $verified['pass'],
                'aligned' => $aligned,
                'reason' => $verified['reason'] ?? null,
            ];

            if ($verified['pass'] && $aligned) {
                $hasPassingAligned = true;
            }
        }

        $result = $hasPassingAligned ? 'pass' : 'fail';

        return [
            'result' => $result,
            'signatures' => $verifiedSignatures,
            'aligned' => $hasPassingAligned,
            'notes' => $this->generateNotes($verifiedSignatures),
        ];
    }

    /**
     * Extract DKIM-Signature headers from message (preserving folding)
     *
     * @param string $rawMessage
     * @return array
     */
    protected function extractDkimSignatures(string $rawMessage): array
    {
        $signatures = [];

        // Match DKIM-Signature headers with folded continuation lines
        // This regex captures the header and all continuation lines (starting with space/tab)
        if (preg_match_all('/^DKIM-Signature:\s*(.+?(?:\r?\n[ \t].+?)*)\r?$/mi', $rawMessage, $matches)) {
            foreach ($matches[1] as $sigHeader) {
                $sig = $this->parseDkimSignature($sigHeader);
                if ($sig) {
                    $signatures[] = $sig;
                }
            }
        }

        return $signatures;
    }

    /**
     * Parse DKIM-Signature header into components
     *
     * @param string $header
     * @return array|null
     */
    protected function parseDkimSignature(string $header): ?array
    {
        // Remove whitespace and newlines
        $header = preg_replace('/\s+/', ' ', $header);

        $tags = [];
        if (preg_match_all('/([a-z]+)=([^;]+)/i', $header, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                $tags[trim($match[1])] = trim($match[2]);
            }
        }

        // Required tags: v, a, d, s, b, bh, h
        if (!isset($tags['d'], $tags['s'], $tags['b'], $tags['bh'])) {
            return null;
        }

        return [
            'v' => $tags['v'] ?? '1',
            'a' => $tags['a'] ?? 'rsa-sha256',
            'd' => $tags['d'],
            's' => $tags['s'],
            'b' => $tags['b'],
            'bh' => $tags['bh'],
            'h' => $tags['h'] ?? '',
            'c' => $tags['c'] ?? 'simple/simple',
            'raw' => $header,
        ];
    }

    /**
     * Verify a single DKIM signature
     *
     * @param string $rawMessage
     * @param array $sig
     * @return array ['pass' => bool, 'reason' => string]
     */
    protected function verifySignature(string $rawMessage, array $sig): array
    {
        try {
            // Fetch public key
            $publicKey = $this->fetchPublicKey($sig['s'], $sig['d']);
            if (!$publicKey) {
                return ['pass' => false, 'reason' => 'Public key not found'];
            }

            // Parse canonicalization
            [$headerCanon, $bodyCanon] = explode('/', $sig['c'] . '/simple');

            // Verify body hash
            $body = $this->extractBody($rawMessage);
            $canonicalBody = $this->canonicalizeBody($body, $bodyCanon);
            $computedBh = base64_encode(hash('sha256', $canonicalBody, true));

            if ($computedBh !== $sig['bh']) {
                return ['pass' => false, 'reason' => 'Body hash mismatch'];
            }

            // Verify signature
            $headers = $this->extractHeaders($rawMessage);
            $signedHeaders = explode(':', $sig['h']);
            $canonicalHeaders = $this->canonicalizeHeaders($headers, $signedHeaders, $headerCanon);

            // Add DKIM-Signature header (with b= empty)
            $dkimHeader = preg_replace('/b=[^;]+/', 'b=', $sig['raw']);
            $canonicalHeaders .= "dkim-signature:" . $this->canonicalizeHeaderValue($dkimHeader, $headerCanon);

            // Verify with public key
            $signature = base64_decode($sig['b']);
            $verified = openssl_verify(
                $canonicalHeaders,
                $signature,
                $publicKey,
                OPENSSL_ALGO_SHA256
            );

            if ($verified === 1) {
                return ['pass' => true];
            } elseif ($verified === 0) {
                return ['pass' => false, 'reason' => 'Signature verification failed'];
            } else {
                return ['pass' => false, 'reason' => 'OpenSSL error: ' . openssl_error_string()];
            }
        } catch (\Exception $e) {
            Log::warning('DKIM verification error', [
                'domain' => $sig['d'],
                'selector' => $sig['s'],
                'error' => $e->getMessage(),
            ]);

            return ['pass' => false, 'reason' => 'Verification error: ' . $e->getMessage()];
        }
    }

    /**
     * Fetch DKIM public key from DNS
     *
     * @param string $selector
     * @param string $domain
     * @return string|null
     */
    protected function fetchPublicKey(string $selector, string $domain): ?string
    {
        $dnsName = "{$selector}._domainkey.{$domain}";

        try {
            return $this->cache->get(
                'dkim_' . md5($dnsName),
                function (ItemInterface $item) use ($dnsName) {
                    $item->expiresAfter(900); // 15 minutes

                    $records = $this->dns->getRecords($dnsName, 'TXT');

                    foreach ($records as $record) {
                        // Spatie DNS returns objects, not arrays
                        $txt = is_object($record) ? $record->txt() : ($record['txt'] ?? '');
                        if ($txt && str_contains($txt, 'p=')) {
                            // Extract public key
                            if (preg_match('/p=([A-Za-z0-9+\/=]+)/', $txt, $matches)) {
                                $key = $matches[1];
                                if (empty($key)) {
                                    return null; // Revoked key
                                }
                                // Format as PEM
                                return "-----BEGIN PUBLIC KEY-----\n" .
                                    chunk_split($key, 64) .
                                    "-----END PUBLIC KEY-----";
                            }
                        }
                    }

                    return null;
                }
            );
        } catch (\Exception $e) {
            Log::warning('Failed to fetch DKIM public key', [
                'selector' => $selector,
                'domain' => $domain,
                'error' => $e->getMessage(),
            ]);
            return null;
        }
    }

    /**
     * Extract body from raw message
     *
     * @param string $rawMessage
     * @return string
     */
    protected function extractBody(string $rawMessage): string
    {
        // Body starts after first blank line
        if (preg_match('/\r?\n\r?\n(.*)$/s', $rawMessage, $matches)) {
            return $matches[1];
        }
        return '';
    }

    /**
     * Extract headers from raw message
     *
     * @param string $rawMessage
     * @return array
     */
    protected function extractHeaders(string $rawMessage): array
    {
        $headers = [];
        $headerSection = preg_split('/\r?\n\r?\n/', $rawMessage, 2)[0];

        // Parse headers (handle folded headers)
        $lines = preg_split('/\r?\n(?=[^ \t])/', $headerSection);

        foreach ($lines as $line) {
            if (preg_match('/^([^:]+):\s*(.*)$/s', $line, $matches)) {
                $name = strtolower(trim($matches[1]));
                $value = trim($matches[2]);
                
                if (!isset($headers[$name])) {
                    $headers[$name] = [];
                }
                $headers[$name][] = $value;
            }
        }

        return $headers;
    }

    /**
     * Canonicalize body according to DKIM rules
     *
     * @param string $body
     * @param string $canon
     * @return string
     */
    protected function canonicalizeBody(string $body, string $canon): string
    {
        if ($canon === 'relaxed') {
            // Reduce all sequences of WSP to single SP
            $body = preg_replace('/[ \t]+/', ' ', $body);
            // Remove trailing WSP from each line
            $body = preg_replace('/[ \t]+(\r?\n)/', '$1', $body);
        }

        // Remove trailing empty lines
        $body = rtrim($body, "\r\n") . "\r\n";

        return $body;
    }

    /**
     * Canonicalize headers according to DKIM rules
     *
     * @param array $headers
     * @param array $signedHeaders
     * @param string $canon
     * @return string
     */
    protected function canonicalizeHeaders(array $headers, array $signedHeaders, string $canon): string
    {
        $result = '';

        foreach ($signedHeaders as $headerName) {
            $headerName = strtolower(trim($headerName));
            
            if (isset($headers[$headerName])) {
                // Use the first occurrence (most recent)
                $value = $headers[$headerName][0];
                $result .= $headerName . ':' . $this->canonicalizeHeaderValue($value, $canon);
            }
        }

        return $result;
    }

    /**
     * Canonicalize header value
     *
     * @param string $value
     * @param string $canon
     * @return string
     */
    protected function canonicalizeHeaderValue(string $value, string $canon): string
    {
        if ($canon === 'relaxed') {
            // Unfold and reduce WSP
            $value = preg_replace('/\r?\n[ \t]+/', ' ', $value);
            $value = preg_replace('/[ \t]+/', ' ', $value);
            $value = trim($value);
        }

        return $value . "\r\n";
    }

    /**
     * Check if DKIM domain is aligned with header From domain
     *
     * @param string $dkimDomain
     * @param string $headerFromDomain
     * @return bool
     */
    protected function isAligned(string $dkimDomain, string $headerFromDomain): bool
    {
        return \App\Support\DomainAlign::aligned($dkimDomain, $headerFromDomain, 'r');
    }

    /**
     * Generate human-readable notes from verification results
     *
     * @param array $signatures
     * @return array
     */
    protected function generateNotes(array $signatures): array
    {
        $notes = [];

        foreach ($signatures as $sig) {
            if ($sig['pass'] && $sig['aligned']) {
                $notes[] = "DKIM passed and aligned: d={$sig['d']}";
            } elseif ($sig['pass'] && !$sig['aligned']) {
                $notes[] = "DKIM passed but not aligned: d={$sig['d']}";
            } else {
                $reason = $sig['reason'] ?? 'unknown';
                $notes[] = "DKIM failed: d={$sig['d']}, reason: {$reason}";
            }
        }

        return $notes;
    }
}
