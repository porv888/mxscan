<?php

namespace App\Domain\EmailSecurity\Checks\TlsRpt\Recommendations;

use App\Domain\EmailSecurity\Checks\TlsRpt\Support\TlsRptAnalysisReader;
use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptNativeResult;
use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptProtocolStatus;
use App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper;

final class TlsRptRecommendationEvaluator
{
    /**
     * @param array<string, mixed>|null $tlsRptInfo
     * @param array<string, mixed>|null $tlsRptCard
     * @return list<array{semantic_key: string, legacy_key: string, severity: string, title: string, body: string, suggested: ?string, card_state: string}>
     */
    public function evaluate(
        string $domain,
        ?array $tlsRptInfo,
        ?array $tlsRptCard = null,
        ?TlsRptNativeResult $native = null,
    ): array {
        $analysis = TlsRptAnalysisReader::analysis($tlsRptInfo);
        $protocolStatus = $native?->protocolStatus ?? TlsRptAnalysisReader::protocolStatus($tlsRptInfo);
        $cardState = $tlsRptCard['state'] ?? TlsRptAnalysisReader::state($tlsRptInfo) ?? ScanReportStatusMapper::UNKNOWN;
        $domain = strtolower(rtrim(trim($domain), '.'));
        $items = [];

        if ($protocolStatus === TlsRptProtocolStatus::NONE || $cardState === ScanReportStatusMapper::MISSING) {
            return [[
                'semantic_key' => 'add_tls_rpt',
                'legacy_key' => 'tlsrpt',
                'severity' => 'low',
                'title' => 'Add TLS-RPT Record',
                'body' => 'Publish a TLS-RPT policy to receive reports about TLS connection failures.',
                'suggested' => 'v=TLSRPTv1; rua=mailto:tlsrpt@' . $domain,
                'card_state' => ScanReportStatusMapper::MISSING,
            ]];
        }

        if ($protocolStatus === TlsRptProtocolStatus::TEMPERROR) {
            return [[
                'semantic_key' => 'review_tls_rpt_reporting_configuration',
                'legacy_key' => 'tlsrpt',
                'severity' => 'low',
                'title' => 'Review TLS-RPT configuration',
                'body' => TlsRptAnalysisReader::summary($tlsRptInfo) ?? 'TLS-RPT could not be evaluated reliably.',
                'suggested' => null,
                'card_state' => ScanReportStatusMapper::UNKNOWN,
            ]];
        }

        $errorCode = $analysis['errors'][0]['code'] ?? ($native?->errors[0]['code'] ?? '');

        if ($protocolStatus === TlsRptProtocolStatus::PERMERROR) {
            $semantic = match ($errorCode) {
                'MULTIPLE_TLS_RPT_RECORDS' => 'fix_multiple_tls_rpt_records',
                'MISSING_RUA', 'NO_VALID_DESTINATIONS' => 'add_tls_rpt_destination',
                default => 'fix_invalid_tls_rpt_record',
            };

            return [[
                'semantic_key' => $semantic,
                'legacy_key' => 'tlsrpt',
                'severity' => 'medium',
                'title' => $this->titleForSemantic($semantic),
                'body' => $analysis['summary'] ?? ($native?->summary ?? 'The TLS-RPT configuration needs attention.'),
                'suggested' => $analysis['record']['raw'] ?? $native?->rawRecord,
                'card_state' => ScanReportStatusMapper::FAIL,
            ]];
        }

        $destinations = is_array($analysis['reporting']['destinations'] ?? null)
            ? $analysis['reporting']['destinations']
            : ($native?->reporting['destinations'] ?? []);

        foreach ($destinations as $destination) {
            if (($destination['duplicate'] ?? false) === true) {
                $items[] = $this->item(
                    'remove_duplicate_tls_rpt_destination',
                    'Remove duplicate TLS-RPT destination',
                    'One published reporting destination appears more than once.',
                    $destination['normalized_uri'] ?? null,
                    ScanReportStatusMapper::WARNING,
                );
                break;
            }
        }

        foreach ($destinations as $destination) {
            if (($destination['status'] ?? '') === 'unsupported_scheme') {
                $items[] = $this->item(
                    'replace_unsupported_tls_rpt_scheme',
                    'Replace unsupported TLS-RPT URI scheme',
                    'TLS-RPT supports mailto and https reporting destinations only.',
                    'mailto:tlsrpt@' . $domain,
                    ScanReportStatusMapper::WARNING,
                );
                break;
            }
        }

        foreach ($destinations as $destination) {
            if (in_array($destination['status'] ?? '', ['invalid', 'empty'], true)) {
                $items[] = $this->item(
                    'fix_tls_rpt_destination',
                    'Fix TLS-RPT reporting destination',
                    'One published reporting destination is malformed.',
                    $destination['raw_uri'] ?? null,
                    ScanReportStatusMapper::WARNING,
                );
                break;
            }
        }

        $expected = is_array($analysis['reporting']['expected_destination'] ?? null)
            ? $analysis['reporting']['expected_destination']
            : ($native?->reporting['expected_destination'] ?? []);

        if (
            ($expected['expected_address'] ?? null) !== null
            && ($expected['present'] ?? false) === false
            && ($expected['other_valid_destination_exists'] ?? false) === true
        ) {
            $items[] = $this->item(
                'add_mxscan_tls_rpt_destination',
                'Add MXScan TLS-RPT destination',
                'A valid TLS-RPT policy is published, but the expected MXScan reporting destination is missing.',
                $expected['expected_address'],
                ScanReportStatusMapper::WARNING,
            );
        }

        if ($items === [] && $cardState === ScanReportStatusMapper::WARNING) {
            $items[] = $this->item(
                'review_tls_rpt_reporting_configuration',
                'Review TLS-RPT reporting configuration',
                $analysis['summary'] ?? ($native?->summary ?? 'Review the published TLS-RPT destinations.'),
                null,
                ScanReportStatusMapper::WARNING,
            );
        }

        return $items;
    }

    /**
     * @return array{semantic_key: string, legacy_key: string, severity: string, title: string, body: string, suggested: ?string, card_state: string}
     */
    private function item(
        string $semanticKey,
        string $title,
        string $body,
        ?string $suggested,
        string $cardState,
    ): array {
        return [
            'semantic_key' => $semanticKey,
            'legacy_key' => 'tlsrpt',
            'severity' => 'low',
            'title' => $title,
            'body' => $body,
            'suggested' => $suggested,
            'card_state' => $cardState,
        ];
    }

    private function titleForSemantic(string $semantic): string
    {
        return match ($semantic) {
            'fix_multiple_tls_rpt_records' => 'Fix multiple TLS-RPT records',
            'add_tls_rpt_destination' => 'Add TLS-RPT reporting destination',
            default => 'Fix TLS-RPT record',
        };
    }
}
