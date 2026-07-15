<?php

namespace App\Domain\EmailSecurity\Checks\TlsRpt\Support;

use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptProtocolStatus;
use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptStates;

final class TlsRptAnalysisReader
{
    /**
     * @param array<string, mixed>|null $tlsRpt
     */
    public static function analysis(?array $tlsRpt): ?array
    {
        if ($tlsRpt === null) {
            return null;
        }

        $analysis = $tlsRpt['analysis'] ?? null;
        if (is_array($analysis) && ($analysis['version'] ?? null) !== null) {
            return $analysis;
        }

        return null;
    }

    /**
     * @param array<string, mixed>|null $tlsRpt
     */
    public static function protocolStatus(?array $tlsRpt): ?string
    {
        return self::stringFromAnalysis($tlsRpt, 'protocol_status')
            ?? self::string($tlsRpt, 'protocol_status');
    }

    /**
     * @param array<string, mixed>|null $tlsRpt
     */
    public static function riskStatus(?array $tlsRpt): ?string
    {
        return self::stringFromAnalysis($tlsRpt, 'risk_status')
            ?? self::string($tlsRpt, 'risk_status');
    }

    /**
     * @param array<string, mixed>|null $tlsRpt
     */
    public static function state(?array $tlsRpt): ?string
    {
        $analysis = self::analysis($tlsRpt);
        if (is_array($analysis) && is_string($analysis['state'] ?? null)) {
            return $analysis['state'];
        }

        return is_string($tlsRpt['ui_state'] ?? null) ? $tlsRpt['ui_state'] : null;
    }

    /**
     * @param array<string, mixed>|null $tlsRpt
     */
    public static function summary(?array $tlsRpt): ?string
    {
        $analysis = self::analysis($tlsRpt);

        return is_string($analysis['summary'] ?? null)
            ? $analysis['summary']
            : (is_string($tlsRpt['summary'] ?? null) ? $tlsRpt['summary'] : null);
    }

    /**
     * @param array<string, mixed>|null $dnsRecord
     * @param array<string, mixed>|null $tlsRptInfo
     * @return array<string, mixed>
     */
    public static function fromLegacyDnsRecord(?array $dnsRecord, ?array $tlsRptInfo = null): array
    {
        $analysis = self::analysis($tlsRptInfo);
        if ($analysis !== null) {
            return $analysis;
        }

        $found = ($dnsRecord['status'] ?? '') === 'found';
        $raw = is_string($dnsRecord['data'] ?? null) ? $dnsRecord['data'] : null;

        if (!$found) {
            return [
                'version' => 'legacy-readonly',
                'protocol_status' => TlsRptProtocolStatus::NONE,
                'risk_status' => 'warning',
                'state' => TlsRptStates::MISSING,
                'summary' => 'No TLS-RPT policy was found.',
                'record' => [
                    'raw' => null,
                    'normalized' => null,
                    'ttl' => null,
                    'alias_path' => [],
                ],
                'reporting' => ['configured' => false],
                'evaluation_completeness' => 'legacy',
            ];
        }

        return [
            'version' => 'legacy-readonly',
            'protocol_status' => TlsRptProtocolStatus::VALID,
            'risk_status' => 'warning',
            'state' => TlsRptStates::WARNING,
            'summary' => 'Historical scan found a TLS-RPT record snapshot.',
            'record' => [
                'raw' => $raw,
                'normalized' => $raw,
                'ttl' => null,
                'alias_path' => [],
            ],
            'reporting' => ['configured' => true],
            'evaluation_completeness' => 'legacy',
        ];
    }

    /**
     * @param array<string, mixed>|null $tlsRpt
     */
    private static function stringFromAnalysis(?array $tlsRpt, string $key): ?string
    {
        $analysis = self::analysis($tlsRpt);

        return is_array($analysis) && is_string($analysis[$key] ?? null) ? $analysis[$key] : null;
    }

    /**
     * @param array<string, mixed>|null $tlsRpt
     */
    private static function string(?array $tlsRpt, string $key): ?string
    {
        return is_array($tlsRpt) && is_string($tlsRpt[$key] ?? null) ? $tlsRpt[$key] : null;
    }
}
