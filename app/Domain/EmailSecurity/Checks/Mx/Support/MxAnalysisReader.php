<?php

namespace App\Domain\EmailSecurity\Checks\Mx\Support;

use App\Domain\EmailSecurity\Checks\Mx\MxProtocolStatus;
use App\Domain\EmailSecurity\Checks\Mx\MxRiskStatus;
use App\Domain\EmailSecurity\Checks\Mx\MxServiceMode;
use App\Domain\EmailSecurity\Checks\Mx\MxStates;

final class MxAnalysisReader
{
    /**
     * @param array<string, mixed>|null $mx
     */
    public static function analysis(?array $mx): ?array
    {
        if ($mx === null) {
            return null;
        }

        $analysis = $mx['analysis'] ?? null;
        if (is_array($analysis) && ($analysis['version'] ?? null) !== null) {
            return $analysis;
        }

        return null;
    }

    /**
     * @param array<string, mixed>|null $mx
     */
    public static function protocolStatus(?array $mx): ?string
    {
        return self::stringFromAnalysis($mx, 'protocol_status')
            ?? self::string($mx, 'protocol_status');
    }

    /**
     * @param array<string, mixed>|null $mx
     */
    public static function riskStatus(?array $mx): ?string
    {
        return self::stringFromAnalysis($mx, 'risk_status')
            ?? self::string($mx, 'risk_status');
    }

    /**
     * @param array<string, mixed>|null $mx
     */
    public static function state(?array $mx): ?string
    {
        $analysis = self::analysis($mx);
        if (is_array($analysis) && is_string($analysis['state'] ?? null)) {
            return $analysis['state'];
        }

        return is_string($mx['ui_state'] ?? null) ? $mx['ui_state'] : null;
    }

    /**
     * @param array<string, mixed>|null $mx
     */
    public static function summary(?array $mx): ?string
    {
        $analysis = self::analysis($mx);

        return is_string($analysis['summary'] ?? null)
            ? $analysis['summary']
            : (is_string($mx['summary'] ?? null) ? $mx['summary'] : null);
    }

    /**
     * @param array<string, mixed>|null $mx
     */
    public static function serviceMode(?array $mx): ?string
    {
        return self::stringFromAnalysis($mx, 'service_mode');
    }

    /**
     * @param array<string, mixed>|null $dnsRecord
     * @param array<string, mixed>|null $mxInfo
     * @return array<string, mixed>
     */
    public static function fromLegacyDnsRecord(?array $dnsRecord, ?array $mxInfo = null): array
    {
        $analysis = self::analysis($mxInfo);
        if ($analysis !== null) {
            return $analysis;
        }

        $status = is_array($dnsRecord) ? (string) ($dnsRecord['status'] ?? 'missing') : 'missing';

        if ($status === 'found') {
            return [
                'version' => 'mx-legacy-readonly-v1',
                'protocol_status' => MxProtocolStatus::VALID,
                'risk_status' => MxRiskStatus::HEALTHY,
                'state' => MxStates::PASS,
                'summary' => 'MX records were present in this historical scan.',
                'service_mode' => MxServiceMode::ACCEPTS_MAIL,
                'targets' => [],
                'null_mx' => ['published' => false, 'valid' => false],
                'implicit_fallback' => ['evaluated' => false, 'active' => false],
            ];
        }

        return [
            'version' => 'mx-legacy-readonly-v1',
            'protocol_status' => MxProtocolStatus::NONE,
            'risk_status' => MxRiskStatus::CRITICAL,
            'state' => MxStates::MISSING,
            'summary' => 'No MX records were found in this historical scan.',
            'service_mode' => MxServiceMode::UNKNOWN,
            'targets' => [],
            'null_mx' => ['published' => false, 'valid' => false],
            'implicit_fallback' => ['evaluated' => false, 'active' => false],
        ];
    }

    /**
     * @param array<string, mixed>|null $mx
     */
    private static function stringFromAnalysis(?array $mx, string $key): ?string
    {
        $analysis = self::analysis($mx);

        return is_array($analysis) && is_string($analysis[$key] ?? null) ? $analysis[$key] : null;
    }

    /**
     * @param array<string, mixed>|null $mx
     */
    private static function string(?array $mx, string $key): ?string
    {
        return is_array($mx) && is_string($mx[$key] ?? null) ? $mx[$key] : null;
    }
}
