<?php

namespace App\Domain\EmailSecurity\Reporting;

use App\Domain\EmailSecurity\Contracts\ScanResultNormalizerInterface;
use App\Domain\EmailSecurity\DTO\CheckResultDTO;
use App\Domain\EmailSecurity\DTO\NormalizedScanResultDTO;
use App\Domain\EmailSecurity\DTO\ScanResultDTO;

final class ScanResultNormalizer implements ScanResultNormalizerInterface
{
    public function normalize(ScanResultDTO $result): NormalizedScanResultDTO
    {
        $sections = $result->toArray();
        $dns = is_array($sections['dns'] ?? null) ? $sections['dns'] : [];
        $records = is_array($dns['records'] ?? null) ? $dns['records'] : [];
        $checkResults = [];

        if (isset($sections['bimi']) && is_array($sections['bimi'])) {
            $checkResults['bimi'] = new CheckResultDTO(
                key: 'bimi',
                status: (string) ($sections['bimi']['ui_state'] ?? $sections['bimi']['status'] ?? 'unknown'),
                data: $sections['bimi'],
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

        if (isset($sections['dmarc']) && is_array($sections['dmarc'])) {
            $checkResults['dmarc'] = new CheckResultDTO(
                key: 'dmarc',
                status: (string) ($sections['dmarc']['ui_state'] ?? $sections['dmarc']['status'] ?? 'unknown'),
                data: $sections['dmarc'],
            );
        }

        if (isset($sections['dkim']) && is_array($sections['dkim'])) {
            $checkResults['dkim'] = new CheckResultDTO(
                key: 'dkim',
                status: (string) ($sections['dkim']['ui_state'] ?? $sections['dkim']['status'] ?? 'unknown'),
                data: $sections['dkim'],
            );
        }

        if (isset($sections['mta_sts']) && is_array($sections['mta_sts'])) {
            $checkResults['mtasts'] = new CheckResultDTO(
                key: 'mtasts',
                status: (string) ($sections['mta_sts']['ui_state'] ?? $sections['mta_sts']['status'] ?? 'unknown'),
                data: $sections['mta_sts'],
            );
        }

        if (isset($sections['tls_rpt']) && is_array($sections['tls_rpt'])) {
            $checkResults['tlsrpt'] = new CheckResultDTO(
                key: 'tlsrpt',
                status: (string) ($sections['tls_rpt']['ui_state'] ?? $sections['tls_rpt']['status'] ?? 'unknown'),
                data: $sections['tls_rpt'],
            );
        }

        if (isset($sections['mx']) && is_array($sections['mx'])) {
            $checkResults['mx'] = new CheckResultDTO(
                key: 'mx',
                status: (string) ($sections['mx']['ui_state'] ?? $sections['mx']['status'] ?? 'unknown'),
                data: $sections['mx'],
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
