<?php

namespace Tests\Support\EmailSecurity;

use App\Domain\EmailSecurity\Checks\DMARC\Evaluation\DmarcReportingEvaluator;
use App\Domain\EmailSecurity\Checks\DMARC\Parsing\DmarcParser;
use App\Domain\EmailSecurity\Checks\DMARC\Reporting\DmarcMxscanRuaExpectations;

final class DmarcFixtureBuilder
{
    /**
     * @return list<array{host: string, txt: string, ttl: int, rr_index: int}>
     */
    public static function txtEvidence(string $domain, string $record, int $ttl = 3600): array
    {
        return [[
            'host' => '_dmarc.' . $domain,
            'txt' => $record,
            'ttl' => $ttl,
            'rr_index' => 0,
        ]];
    }

    /**
     * @return array<string, mixed>
     */
    public static function dnsPayloadWithDmarc(string $domain, ?string $record): array
    {
        $payload = FixtureLoader::input('dns-bundled-full');
        $hostname = '_dmarc.' . $domain;

        if ($record === null) {
            $payload['records']['DMARC'] = ['status' => 'missing'];
            $payload['dmarc_txt_records'] = [];

            return $payload;
        }

        $payload['records']['DMARC'] = ['status' => 'found', 'data' => $record];
        $payload['dmarc_txt_records'] = self::txtEvidence($domain, $record);

        return $payload;
    }

    /**
     * @param array<string, mixed> $policy
     * @return array<string, mixed>
     */
    public static function nativeAnalysis(array $policy = [], ?string $record = null): array
    {
        return [
            'version' => 'dmarc-native-v1',
            'protocol_status' => $policy['protocol_status'] ?? 'valid',
            'risk_status' => $policy['risk_status'] ?? 'healthy',
            'state' => $policy['state'] ?? 'pass',
            'summary' => $policy['summary'] ?? 'DMARC configured.',
            'record' => $record ?? ($policy['record'] ?? 'v=DMARC1; p=quarantine'),
            'policy' => $policy['policy'] ?? [
                'published_p' => 'quarantine',
                'effective_policy' => 'quarantine',
                'pct' => 100,
                'testing_mode' => false,
                'enforcement' => 'quarantine',
            ],
            'alignment' => $policy['alignment'] ?? ['dkim' => 'relaxed', 'spf' => 'relaxed'],
            'aggregate_reporting' => $policy['aggregate_reporting'] ?? [
                'configured' => true,
                'destinations' => [],
                'mxscan_expectation' => [
                    'expected_address' => 'dmarc+token@mxscan.me',
                    'present' => false,
                    'other_valid_destination_exists' => false,
                ],
            ],
            'failure_reporting' => $policy['failure_reporting'] ?? ['configured' => false, 'destinations' => []],
            'external_authorization' => $policy['external_authorization'] ?? [
                'destinations_checked' => 0,
                'unauthorized_count' => 0,
            ],
            'errors' => [],
            'warnings' => [],
        ];
    }

    /**
     * @param array<string, mixed> $analysisOverrides
     * @return array<string, mixed>
     */
    public static function scanResultJsonWithNativeDmarc(
        string $dmarcRecord,
        ?string $canonicalMxscanEmail = null,
        array $analysisOverrides = [],
    ): array {
        $parser = new DmarcParser();
        $reportingEvaluator = new DmarcReportingEvaluator();
        $parsed = $parser->parse($dmarcRecord);
        $aggregate = $reportingEvaluator->evaluateAggregate($parsed);

        foreach ($aggregate['destinations'] as $index => $destination) {
            $destinationDomain = strtolower((string) ($destination['destination_domain'] ?? ''));
            if ($destinationDomain === DmarcMxscanRuaExpectations::MXSCAN_DOMAIN) {
                $aggregate['destinations'][$index]['internal'] = true;
            }
        }

        $mxscanExpectation = [
            'expected_address' => $canonicalMxscanEmail !== null ? strtolower(trim($canonicalMxscanEmail)) : null,
            'present' => false,
            'other_valid_destination_exists' => false,
        ];

        foreach ($aggregate['destinations'] as $destination) {
            $email = strtolower((string) ($destination['normalized_destination'] ?? ''));
            if ($mxscanExpectation['expected_address'] !== null && $email === $mxscanExpectation['expected_address']) {
                $mxscanExpectation['present'] = true;
            } elseif ($email !== '') {
                $mxscanExpectation['other_valid_destination_exists'] = true;
            }
        }

        $publishedPolicy = $parsed->tag('p');
        $analysis = array_replace_recursive(
            self::nativeAnalysis([
                'record' => $dmarcRecord,
                'policy' => [
                    'published_p' => $publishedPolicy,
                    'effective_policy' => $publishedPolicy,
                    'pct' => 100,
                    'testing_mode' => false,
                    'enforcement' => $publishedPolicy === 'none' ? 'monitoring' : $publishedPolicy,
                ],
                'aggregate_reporting' => [
                    'configured' => $aggregate['configured'],
                    'destinations' => $aggregate['destinations'],
                    'mxscan_expectation' => $mxscanExpectation,
                ],
            ], $dmarcRecord),
            $analysisOverrides,
        );

        return [
            'dmarc' => [
                'analysis' => $analysis,
                'ui_state' => $analysis['state'],
                'record' => $dmarcRecord,
            ],
            'dns' => [
                'records' => [
                    'DMARC' => [
                        'status' => 'found',
                        'data' => $dmarcRecord,
                    ],
                ],
            ],
        ];
    }
}
