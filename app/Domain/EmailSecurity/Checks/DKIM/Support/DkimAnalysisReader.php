<?php

namespace App\Domain\EmailSecurity\Checks\DKIM\Support;

use App\Domain\EmailSecurity\Checks\DKIM\DkimProtocolStatus;
use App\Domain\EmailSecurity\Checks\DKIM\DkimRiskStatus;
use App\Domain\EmailSecurity\Checks\DKIM\DkimStates;

final class DkimAnalysisReader
{
    /**
     * @param array<string, mixed>|null $dkim
     */
    public static function analysis(?array $dkim): ?array
    {
        if ($dkim === null) {
            return null;
        }

        $analysis = $dkim['analysis'] ?? null;
        if (is_array($analysis) && ($analysis['version'] ?? null) !== null) {
            return $analysis;
        }

        return null;
    }

    /**
     * @param array<string, mixed>|null $dkim
     */
    public static function protocolStatus(?array $dkim): ?string
    {
        return self::stringFromAnalysis($dkim, 'protocol_status')
            ?? self::string($dkim, 'protocol_status');
    }

    /**
     * @param array<string, mixed>|null $dkim
     */
    public static function state(?array $dkim): ?string
    {
        $analysis = self::analysis($dkim);
        if (is_array($analysis) && is_string($analysis['state'] ?? null)) {
            return $analysis['state'];
        }

        return is_string($dkim['ui_state'] ?? null) ? $dkim['ui_state'] : null;
    }

    /**
     * @param array<string, mixed>|null $dnsRecord
     * @param array<string, mixed>|null $dkimInfo
     * @return array<string, mixed>
     */
    public static function fromLegacyDnsRecord(?array $dnsRecord, ?array $dkimInfo = null): array
    {
        $analysis = self::analysis($dkimInfo);
        if ($analysis !== null) {
            return $analysis;
        }

        $found = ($dnsRecord['status'] ?? '') === 'found' && !empty($dnsRecord['data']);

        if (!$found) {
            return [
                'version' => 'legacy-shim-v0',
                'protocol_status' => DkimProtocolStatus::NONE,
                'risk_status' => DkimRiskStatus::CRITICAL,
                'state' => DkimStates::MISSING,
                'summary' => 'No DKIM key was found for the tested selectors (historical scan).',
                'signing_verified' => false,
                'selector_coverage' => [
                    'selectors_available' => true,
                    'selectors_tested' => count($dnsRecord['data'] ?? []),
                    'coverage_type' => 'catalog_only',
                ],
                'selectors' => [],
                'errors' => [],
                'warnings' => [],
                'resolver_diagnostics' => [],
            ];
        }

        $selectors = [];
        if (is_array($dnsRecord['data'] ?? null)) {
            foreach ($dnsRecord['data'] as $row) {
                if (!is_array($row)) {
                    continue;
                }
                $selectors[] = [
                    'selector' => $row['selector'] ?? 'unknown',
                    'source' => 'catalog',
                    'confidence' => 'low',
                    'hostname' => ($row['selector'] ?? 'unknown') . '._domainkey.',
                    'dns_status' => 'answer',
                    'record_status' => 'valid',
                    'key_type' => null,
                    'key_bits' => null,
                    'testing' => false,
                    'revoked' => false,
                    'errors' => [],
                    'warnings' => [[
                        'code' => 'HISTORICAL_SCAN',
                        'message' => 'Historical scan confirmed DNS key presence only.',
                    ]],
                ];
            }
        }

        return [
            'version' => 'legacy-shim-v0',
            'protocol_status' => DkimProtocolStatus::VALID,
            'risk_status' => DkimRiskStatus::HEALTHY,
            'state' => DkimStates::PASS,
            'summary' => 'A valid DKIM key is published for a tested selector (historical scan).',
            'signing_verified' => false,
            'selector_coverage' => [
                'selectors_available' => true,
                'selectors_tested' => count($selectors),
                'coverage_type' => 'catalog_only',
            ],
            'selectors' => $selectors,
            'errors' => [],
            'warnings' => [[
                'code' => 'HISTORICAL_SCAN',
                'message' => 'Historical scan confirmed DNS key presence only — live signing was not verified.',
            ]],
            'resolver_diagnostics' => [],
        ];
    }

    /**
     * @param array<string, mixed>|null $payload
     */
    private static function string(?array $payload, string $key): ?string
    {
        if ($payload === null) {
            return null;
        }

        $value = $payload[$key] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @param array<string, mixed>|null $dkim
     */
    private static function stringFromAnalysis(?array $dkim, string $key): ?string
    {
        $analysis = self::analysis($dkim);

        if ($analysis === null) {
            return null;
        }

        $value = $analysis[$key] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }
}
