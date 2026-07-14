<?php

namespace App\Domain\EmailSecurity\Reporting;

use App\Domain\EmailSecurity\Contracts\ScanResultNormalizerInterface;
use App\Domain\EmailSecurity\DTO\CheckResultDTO;
use App\Domain\EmailSecurity\DTO\NormalizedScanResultDTO;
use App\Domain\EmailSecurity\DTO\ScanResultDTO;
use App\Domain\EmailSecurity\Support\ScanRecordKeys;

final class ScanResultNormalizer implements ScanResultNormalizerInterface
{
    public function normalize(ScanResultDTO $result): NormalizedScanResultDTO
    {
        $sections = $result->toArray();
        $dns = is_array($sections['dns'] ?? null) ? $sections['dns'] : [];
        $records = is_array($dns['records'] ?? null) ? $dns['records'] : [];
        $checkResults = [];

        $bundledMap = [
            ScanRecordKeys::MX => 'mx',
            ScanRecordKeys::DKIM => 'dkim',
            ScanRecordKeys::DMARC => 'dmarc',
            ScanRecordKeys::TLS_RPT => 'tlsrpt',
            ScanRecordKeys::MTA_STS => 'mtasts',
            ScanRecordKeys::BIMI => 'bimi',
        ];

        foreach ($bundledMap as $recordKey => $checkKey) {
            if (!isset($records[$recordKey]) || !is_array($records[$recordKey])) {
                continue;
            }

            $record = $records[$recordKey];
            $checkResults[$checkKey] = new CheckResultDTO(
                key: $checkKey,
                status: (string) ($record['status'] ?? 'missing'),
                data: $record,
            );
        }

        if (isset($sections['spf']) && is_array($sections['spf'])) {
            $checkResults['spf'] = new CheckResultDTO(
                key: 'spf',
                status: (string) ($sections['spf']['status'] ?? 'safe'),
                data: $sections['spf'],
                messages: $sections['spf']['warnings'] ?? [],
            );
        }

        if (isset($sections['blacklist']) && is_array($sections['blacklist'])) {
            $summary = $sections['blacklist'];
            $checkResults['blacklist'] = new CheckResultDTO(
                key: 'blacklist',
                status: !empty($summary['is_clean']) ? 'clean' : 'listed',
                data: $summary,
            );
        }

        return new NormalizedScanResultDTO(
            domain: (string) ($sections['domain'] ?? ''),
            collectedAt: now()->toIso8601String(),
            checkResults: $checkResults,
            legacyDnsMetadata: [
                'score' => $dns['score'] ?? null,
                'score_breakdown' => $dns['score_breakdown'] ?? [],
                'records' => $records,
                'legacy_payload' => $dns,
            ],
        );
    }
}
