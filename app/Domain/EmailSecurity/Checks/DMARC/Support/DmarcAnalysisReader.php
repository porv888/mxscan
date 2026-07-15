<?php

namespace App\Domain\EmailSecurity\Checks\DMARC\Support;

use App\Domain\EmailSecurity\Checks\DMARC\Evaluation\DmarcReportingEvaluator;
use App\Domain\EmailSecurity\Checks\DMARC\Parsing\DmarcParser;
use App\Domain\EmailSecurity\Checks\DMARC\Reporting\DmarcMxscanRuaExpectations;

final class DmarcAnalysisReader
{
    /**
     * @param array<string, mixed>|null $dmarc
     */
    public static function analysis(?array $dmarc): ?array
    {
        if ($dmarc === null) {
            return null;
        }

        $analysis = $dmarc['analysis'] ?? null;
        if (is_array($analysis) && ($analysis['version'] ?? null) !== null) {
            return $analysis;
        }

        return null;
    }

    /**
     * @param array<string, mixed>|null $dmarc
     */
    public static function protocolStatus(?array $dmarc): ?string
    {
        return self::stringFromAnalysis($dmarc, 'protocol_status')
            ?? self::string($dmarc, 'protocol_status');
    }

    /**
     * @param array<string, mixed>|null $dmarc
     */
    public static function riskStatus(?array $dmarc): ?string
    {
        return self::stringFromAnalysis($dmarc, 'risk_status')
            ?? self::string($dmarc, 'risk_status');
    }

    /**
     * @param array<string, mixed>|null $dmarc
     */
    public static function state(?array $dmarc): ?string
    {
        $analysis = self::analysis($dmarc);
        if (is_array($analysis) && is_string($analysis['state'] ?? null)) {
            return $analysis['state'];
        }

        return is_string($dmarc['ui_state'] ?? null) ? $dmarc['ui_state'] : null;
    }

    /**
     * @param array<string, mixed>|null $dmarc
     */
    public static function effectivePolicy(?array $dmarc): ?string
    {
        $analysis = self::analysis($dmarc);

        return is_array($analysis['policy'] ?? null)
            ? ($analysis['policy']['effective_policy'] ?? null)
            : null;
    }

    /**
     * @param array<string, mixed>|null $dnsRecord
     * @param array<string, mixed>|null $dmarcInfo
     * @return array<string, mixed>
     */
    public static function fromLegacyDnsRecord(?array $dnsRecord, ?array $dmarcInfo = null): array
    {
        $analysis = self::analysis($dmarcInfo);
        if ($analysis !== null) {
            return $analysis;
        }

        $record = null;
        if (($dnsRecord['status'] ?? '') === 'found' && is_string($dnsRecord['data'] ?? null)) {
            $record = $dnsRecord['data'];
        }

        if ($record === null) {
            return [
                'version' => 'legacy-shim-v0',
                'protocol_status' => 'none',
                'risk_status' => 'critical',
                'state' => 'missing',
                'summary' => 'No DMARC record found.',
                'record' => null,
                'policy' => [],
                'aggregate_reporting' => [
                    'configured' => false,
                    'destinations' => [],
                    'mxscan_expectation' => [
                        'expected_address' => null,
                        'present' => false,
                        'other_valid_destination_exists' => false,
                    ],
                ],
            ];
        }

        return self::enrichLegacyShim($record, [
            'version' => 'legacy-shim-v0',
            'protocol_status' => 'valid',
            'risk_status' => 'healthy',
            'state' => 'pass',
            'summary' => 'DMARC record present (historical scan).',
            'record' => $record,
            'policy' => [],
        ]);
    }

    /**
     * @param array<string, mixed> $shim
     * @return array<string, mixed>
     */
    private static function enrichLegacyShim(string $record, array $shim): array
    {
        $parser = new DmarcParser();
        $reportingEvaluator = new DmarcReportingEvaluator();
        $parsed = $parser->parse($record);
        $aggregate = $reportingEvaluator->evaluateAggregate($parsed);

        foreach ($aggregate['destinations'] as $index => $destination) {
            $destinationDomain = strtolower((string) ($destination['destination_domain'] ?? ''));
            if ($destinationDomain === DmarcMxscanRuaExpectations::MXSCAN_DOMAIN) {
                $aggregate['destinations'][$index]['internal'] = true;
            }
        }

        $policy = $parsed->tag('p');
        $state = $policy === 'none' ? 'warning' : ($policy !== null ? 'pass' : 'warning');

        $shim['protocol_status'] = 'valid';
        $shim['risk_status'] = $state === 'pass' ? 'healthy' : 'warning';
        $shim['state'] = $state;
        $shim['policy'] = [
            'effective_policy' => $policy,
            'published_p' => $policy,
        ];
        $shim['aggregate_reporting'] = [
            'configured' => $aggregate['configured'],
            'destinations' => $aggregate['destinations'],
            'mxscan_expectation' => [
                'expected_address' => null,
                'present' => false,
                'other_valid_destination_exists' => $aggregate['configured'],
            ],
        ];

        return $shim;
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
     * @param array<string, mixed>|null $dmarc
     */
    private static function stringFromAnalysis(?array $dmarc, string $key): ?string
    {
        $analysis = self::analysis($dmarc);

        if ($analysis === null) {
            return null;
        }

        $value = $analysis[$key] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }
}
