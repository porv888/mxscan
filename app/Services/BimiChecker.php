<?php

namespace App\Services;

use App\Services\Dns\DnsClient;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class BimiChecker
{
    private DnsClient $dnsClient;

    public function __construct(DnsClient $dnsClient)
    {
        $this->dnsClient = $dnsClient;
    }

    /**
     * Check BIMI record and validate logo for a domain.
     */
    public function check(string $domain): array
    {
        $result = [
            'domain' => $domain,
            'record_found' => false,
            'raw_record' => null,
            'version' => null,
            'logo_url' => null,
            'authority_url' => null,
            'logo_valid' => false,
            'logo_content_type' => null,
            'logo_size_bytes' => null,
            'logo_errors' => [],
            'checked_at' => now()->toISOString(),
        ];

        // Query BIMI TXT record at default._bimi.{domain}
        $bimiDomain = "default._bimi.{$domain}";
        $txtRecords = $this->dnsClient->getTxt($bimiDomain);

        if (empty($txtRecords)) {
            $result['logo_errors'][] = "No BIMI record found at {$bimiDomain}";
            return $result;
        }

        // Find the BIMI record
        $bimiRecord = null;
        foreach ($txtRecords as $record) {
            if (str_starts_with(strtolower(trim($record)), 'v=bimi1')) {
                $bimiRecord = $record;
                break;
            }
        }

        if (!$bimiRecord) {
            $result['logo_errors'][] = 'TXT records found but none contain a valid BIMI record (v=BIMI1)';
            return $result;
        }

        $result['record_found'] = true;
        $result['raw_record'] = $bimiRecord;

        // Parse the BIMI record
        $parsed = $this->parseBimiRecord($bimiRecord);
        $result['version'] = $parsed['v'] ?? null;
        $result['logo_url'] = $parsed['l'] ?? null;
        $result['authority_url'] = $parsed['a'] ?? null;

        // Validate logo URL
        if (empty($result['logo_url'])) {
            $result['logo_errors'][] = 'BIMI record is missing the l= (logo) tag';
            return $result;
        }

        if (!str_starts_with($result['logo_url'], 'https://')) {
            $result['logo_errors'][] = 'Logo URL must use HTTPS';
            return $result;
        }

        if (!str_ends_with(strtolower($result['logo_url']), '.svg')) {
            $result['logo_errors'][] = 'Logo URL must point to an SVG file';
        }

        // Fetch and validate the SVG logo
        try {
            $response = Http::timeout(10)->get($result['logo_url']);

            if (!$response->successful()) {
                $result['logo_errors'][] = "Failed to fetch logo: HTTP {$response->status()}";
                return $result;
            }

            $contentType = $response->header('Content-Type');
            $result['logo_content_type'] = $contentType;
            $result['logo_size_bytes'] = strlen($response->body());

            // Validate content type
            if (!str_contains($contentType, 'svg') && !str_contains($contentType, 'xml')) {
                $result['logo_errors'][] = "Invalid Content-Type: {$contentType} (expected image/svg+xml)";
            }

            // Basic SVG Tiny PS validation
            $svgContent = $response->body();
            if (!str_contains($svgContent, '<svg')) {
                $result['logo_errors'][] = 'Response does not contain valid SVG markup';
            } else {
                // Check for SVG Tiny PS profile
                if (str_contains($svgContent, 'baseProfile="tiny-ps"') || str_contains($svgContent, "baseProfile='tiny-ps'")) {
                    $result['logo_valid'] = empty($result['logo_errors']);
                } else {
                    $result['logo_errors'][] = 'SVG is missing baseProfile="tiny-ps" (required for BIMI)';
                }

                // Check for forbidden elements
                $forbidden = ['<script', '<foreignObject', '<use', 'xlink:href'];
                foreach ($forbidden as $tag) {
                    if (stripos($svgContent, $tag) !== false) {
                        $result['logo_errors'][] = "SVG contains forbidden element: {$tag}";
                        $result['logo_valid'] = false;
                    }
                }
            }

            if (empty($result['logo_errors'])) {
                $result['logo_valid'] = true;
            }

        } catch (\Exception $e) {
            $result['logo_errors'][] = 'Failed to fetch logo: ' . $e->getMessage();
            Log::warning("BIMI logo fetch failed for {$domain}: " . $e->getMessage());
        }

        return $result;
    }

    /**
     * Parse a BIMI record into its tags.
     */
    private function parseBimiRecord(string $record): array
    {
        $tags = [];
        $parts = explode(';', $record);

        foreach ($parts as $part) {
            $part = trim($part);
            if (empty($part)) continue;

            $eqPos = strpos($part, '=');
            if ($eqPos !== false) {
                $key = strtolower(trim(substr($part, 0, $eqPos)));
                $value = trim(substr($part, $eqPos + 1));
                $tags[$key] = $value;
            }
        }

        return $tags;
    }
}
