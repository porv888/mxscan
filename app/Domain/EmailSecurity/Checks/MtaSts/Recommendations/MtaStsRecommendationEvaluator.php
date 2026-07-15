<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts\Recommendations;

use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsNativeResult;
use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsProtocolStatus;
use App\Domain\EmailSecurity\Checks\MtaSts\Support\MtaStsAnalysisReader;
use App\Domain\EmailSecurity\Checks\MtaSts\Validation\MtaStsPolicyValidationResult;
use App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper;

final class MtaStsRecommendationEvaluator
{
    /**
     * @param array<string, mixed>|null $mtaStsInfo
     * @param array<string, mixed>|null $mtaStsCard
     * @return list<array{semantic_key: string, legacy_key: string, severity: string, title: string, body: string, suggested: ?string, card_state: string}>
     */
    public function evaluate(
        string $domain,
        ?array $mtaStsInfo,
        ?array $mtaStsCard = null,
        ?MtaStsNativeResult $native = null,
    ): array {
        $analysis = MtaStsAnalysisReader::analysis($mtaStsInfo);
        $protocolStatus = $native?->protocolStatus ?? MtaStsAnalysisReader::protocolStatus($mtaStsInfo);
        $cardState = $mtaStsCard['state'] ?? MtaStsAnalysisReader::state($mtaStsInfo) ?? ScanReportStatusMapper::UNKNOWN;
        $domain = strtolower(rtrim(trim($domain), '.'));

        if ($protocolStatus === MtaStsProtocolStatus::NONE || $cardState === ScanReportStatusMapper::MISSING) {
            return [[
                'semantic_key' => 'add_mta_sts',
                'legacy_key' => 'mtasts',
                'severity' => 'low',
                'title' => 'Add MTA-STS Policy',
                'body' => 'Publish an MTA-STS DNS indicator and HTTPS policy to enforce secure mail delivery.',
                'suggested' => 'v=STSv1; id=' . date('Ymd') . '01',
                'card_state' => ScanReportStatusMapper::MISSING,
            ]];
        }

        if ($protocolStatus === MtaStsProtocolStatus::PERMERROR) {
            $code = $analysis['errors'][0]['code'] ?? '';
            $semantic = match ($code) {
                'MULTIPLE_MTA_STS_INDICATORS' => 'fix_multiple_mta_sts_records',
                'MALFORMED_INDICATOR', 'INVALID_INDICATOR_VERSION', 'MISSING_OR_INVALID_ID' => 'fix_mta_sts_dns_record',
                default => $this->policySemanticKey($analysis),
            };

            return [[
                'semantic_key' => $semantic,
                'legacy_key' => 'mtasts',
                'severity' => 'medium',
                'title' => $this->titleForSemantic($semantic),
                'body' => $analysis['summary'] ?? ($native?->summary ?? 'The MTA-STS configuration needs attention.'),
                'suggested' => $analysis['dns_indicator']['raw_record'] ?? $native?->rawIndicator,
                'card_state' => ScanReportStatusMapper::FAIL,
            ]];
        }

        $items = [];
        $mode = $analysis['policy']['mode'] ?? $native?->policy['mode'] ?? null;

        if ($mode === 'none') {
            $items[] = $this->item(
                'enable_mta_sts_testing',
                'Move MTA-STS to testing mode',
                'MTA-STS is currently disabled via mode: none. Publish a testing policy after validation.',
                'mode: testing',
                ScanReportStatusMapper::WARNING,
            );
        }

        if ($mode === 'testing') {
            $items[] = $this->item(
                'enable_mta_sts_enforcement',
                'Enable MTA-STS enforcement',
                'After validating MX coverage and TLS, move from testing to enforcement mode.',
                'mode: enforce',
                ScanReportStatusMapper::WARNING,
            );
        }

        $maxAge = $analysis['policy']['max_age'] ?? $native?->policy['max_age'] ?? null;
        if (is_int($maxAge) && $maxAge < MtaStsPolicyValidationResult::OPERATIONAL_SHORT_MAX_AGE) {
            $items[] = $this->item(
                'increase_mta_sts_max_age',
                'Increase MTA-STS max_age',
                'The published max_age is operationally short and may cause frequent policy refreshes.',
                'max_age: 604800',
                ScanReportStatusMapper::WARNING,
            );
        }

        $mxValidation = is_array($analysis['mx_validation'] ?? null)
            ? $analysis['mx_validation']
            : ($native?->mxValidation ?? []);

        foreach ($mxValidation as $mx) {
            if (($mx['matches_policy'] ?? false) === false) {
                $items[] = $this->item(
                    'add_missing_mx_to_mta_sts_policy',
                    'Add missing MX to MTA-STS policy',
                    'Current MX host ' . ($mx['hostname'] ?? 'unknown') . ' is not covered by the published policy.',
                    'mx: ' . ($mx['hostname'] ?? ''),
                    ScanReportStatusMapper::FAIL,
                );
                break;
            }
        }

        foreach ($mxValidation as $mx) {
            if (($mx['starttls'] ?? null) === false) {
                $items[] = $this->item(
                    'fix_mx_starttls',
                    'Enable STARTTLS on MX host',
                    'MX host ' . ($mx['hostname'] ?? 'unknown') . ' did not advertise STARTTLS during testing.',
                    null,
                    ScanReportStatusMapper::WARNING,
                );
                break;
            }
        }

        $patterns = is_array($analysis['policy']['mx_patterns'] ?? null)
            ? $analysis['policy']['mx_patterns']
            : ($native?->policy['mx_patterns'] ?? []);

        foreach ($patterns as $pattern) {
            if ($pattern === '*.' . $domain) {
                $items[] = $this->item(
                    'review_overbroad_mta_sts_wildcard',
                    'Review broad MTA-STS wildcard',
                    'The wildcard pattern *.' . $domain . ' may be broader than necessary.',
                    null,
                    ScanReportStatusMapper::WARNING,
                );
                break;
            }
        }

        if (($analysis['policy_fetch']['status'] ?? null) !== null
            && ($analysis['policy_fetch']['status'] ?? '') !== 'success'
            && ($analysis['dns_indicator']['status'] ?? '') === 'valid') {
            $items[] = $this->item(
                'publish_mta_sts_policy',
                'Publish MTA-STS policy file',
                'The DNS indicator is valid but the HTTPS policy file is unavailable.',
                'https://mta-sts.' . $domain . '/.well-known/mta-sts.txt',
                ScanReportStatusMapper::FAIL,
            );
        }

        return $items;
    }

    /**
     * @param array<string, mixed>|null $analysis
     */
    private function policySemanticKey(?array $analysis): string
    {
        $fetchStatus = $analysis['policy_fetch']['status'] ?? null;
        if ($fetchStatus !== null && $fetchStatus !== 'success') {
            return str_contains((string) $fetchStatus, 'certificate')
                ? 'fix_mta_sts_policy_certificate'
                : 'fix_mta_sts_policy_https';
        }

        return 'fix_invalid_mta_sts_policy';
    }

    private function titleForSemantic(string $semantic): string
    {
        return match ($semantic) {
            'fix_multiple_mta_sts_records' => 'Fix multiple MTA-STS records',
            'fix_mta_sts_dns_record' => 'Fix MTA-STS DNS record',
            'fix_mta_sts_policy_https' => 'Fix MTA-STS policy HTTPS endpoint',
            'fix_mta_sts_policy_certificate' => 'Fix MTA-STS policy certificate',
            'publish_mta_sts_policy' => 'Publish MTA-STS policy file',
            default => 'Fix MTA-STS configuration',
        };
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
            'legacy_key' => 'mtasts',
            'severity' => 'low',
            'title' => $title,
            'body' => $body,
            'suggested' => $suggested,
            'card_state' => $cardState,
        ];
    }
}
