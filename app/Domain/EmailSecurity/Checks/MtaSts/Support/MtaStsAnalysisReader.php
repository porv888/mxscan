<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts\Support;

use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsProtocolStatus;
use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsStates;

final class MtaStsAnalysisReader
{
    /**
     * @param array<string, mixed>|null $mtaSts
     */
    public static function analysis(?array $mtaSts): ?array
    {
        if ($mtaSts === null) {
            return null;
        }

        $analysis = $mtaSts['analysis'] ?? null;
        if (is_array($analysis) && ($analysis['version'] ?? null) !== null) {
            return $analysis;
        }

        return null;
    }

    /**
     * @param array<string, mixed>|null $mtaSts
     */
    public static function protocolStatus(?array $mtaSts): ?string
    {
        return self::stringFromAnalysis($mtaSts, 'protocol_status')
            ?? self::string($mtaSts, 'protocol_status');
    }

    /**
     * @param array<string, mixed>|null $mtaSts
     */
    public static function state(?array $mtaSts): ?string
    {
        $analysis = self::analysis($mtaSts);
        if (is_array($analysis) && is_string($analysis['state'] ?? null)) {
            return $analysis['state'];
        }

        return is_string($mtaSts['ui_state'] ?? null) ? $mtaSts['ui_state'] : null;
    }

    /**
     * @param array<string, mixed>|null $mtaSts
     */
    public static function summary(?array $mtaSts): ?string
    {
        $analysis = self::analysis($mtaSts);

        return is_string($analysis['summary'] ?? null)
            ? $analysis['summary']
            : (is_string($mtaSts['summary'] ?? null) ? $mtaSts['summary'] : null);
    }

    /**
     * @param array<string, mixed>|null $dnsRecord
     * @param array<string, mixed>|null $mtaStsInfo
     * @return array<string, mixed>
     */
    public static function fromLegacyDnsRecord(?array $dnsRecord, ?array $mtaStsInfo = null): array
    {
        $analysis = self::analysis($mtaStsInfo);
        if ($analysis !== null) {
            return $analysis;
        }

        $found = ($dnsRecord['status'] ?? '') === 'found';
        $hasPolicy = !empty($dnsRecord['policy']);

        if (!$found) {
            return [
                'version' => 'legacy-readonly',
                'protocol_status' => MtaStsProtocolStatus::NONE,
                'risk_status' => 'warning',
                'state' => MtaStsStates::MISSING,
                'summary' => 'No MTA-STS DNS indicator was found.',
                'dns_indicator' => [
                    'status' => 'missing',
                    'raw_record' => null,
                ],
                'policy_fetch' => ['status' => 'not_evaluated'],
                'policy' => [],
                'mx_validation' => [],
                'evaluation_completeness' => 'legacy',
            ];
        }

        return [
            'version' => 'legacy-readonly',
            'protocol_status' => $hasPolicy ? MtaStsProtocolStatus::VALID : MtaStsProtocolStatus::PERMERROR,
            'risk_status' => $hasPolicy ? 'warning' : 'critical',
            'state' => $hasPolicy ? MtaStsStates::WARNING : MtaStsStates::FAIL,
            'summary' => $hasPolicy
                ? 'Historical scan found an MTA-STS indicator and policy snapshot.'
                : 'Historical scan found an MTA-STS indicator without a stored policy.',
            'dns_indicator' => [
                'status' => 'valid',
                'raw_record' => is_string($dnsRecord['data'] ?? null) ? $dnsRecord['data'] : null,
            ],
            'policy_fetch' => ['status' => $hasPolicy ? 'success' : 'not_evaluated'],
            'policy' => $hasPolicy ? ['mode' => 'unknown'] : [],
            'mx_validation' => [],
            'evaluation_completeness' => 'legacy',
        ];
    }

    /**
     * @param array<string, mixed>|null $payload
     */
    private static function stringFromAnalysis(?array $payload, string $key): ?string
    {
        $analysis = self::analysis($payload);

        return is_string($analysis[$key] ?? null) ? $analysis[$key] : null;
    }

    /**
     * @param array<string, mixed>|null $payload
     */
    private static function string(?array $payload, string $key): ?string
    {
        return is_string($payload[$key] ?? null) ? $payload[$key] : null;
    }
}
