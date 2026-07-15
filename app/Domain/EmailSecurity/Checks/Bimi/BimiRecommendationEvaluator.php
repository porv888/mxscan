<?php

namespace App\Domain\EmailSecurity\Checks\Bimi;

use App\Domain\EmailSecurity\Checks\Bimi\BimiAnalysisReader;
use App\Domain\EmailSecurity\Checks\Bimi\BimiNativeResult;
use App\Domain\EmailSecurity\Checks\Bimi\BimiProtocolStatus;
use App\Domain\EmailSecurity\Checks\Bimi\BimiReadinessStatus;
use App\Domain\EmailSecurity\Checks\Bimi\BimiEvidenceStatus;
use App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper;

final class BimiRecommendationEvaluator
{
    /**
     * @param array<string, mixed>|null $bimiInfo
     * @param array<string, mixed>|null $bimiCard
     * @return list<array{semantic_key: string, legacy_key: string, severity: string, title: string, body: string, suggested: ?string, card_state: string}>
     */
    public function evaluate(
        string $domain,
        ?array $bimiInfo,
        ?array $bimiCard = null,
        ?BimiNativeResult $native = null,
    ): array {
        $analysis = BimiAnalysisReader::analysis($bimiInfo) ?? [];
        $protocolStatus = $native?->protocolStatus ?? BimiAnalysisReader::protocolStatus($bimiInfo);
        $cardState = $bimiCard['state'] ?? BimiAnalysisReader::state($bimiInfo) ?? ScanReportStatusMapper::UNKNOWN;
        $domain = strtolower(rtrim(trim($domain), '.'));
        $items = [];

        if ($protocolStatus === BimiProtocolStatus::DECLINED) {
            return [];
        }

        if ($protocolStatus === BimiProtocolStatus::NONE || $cardState === ScanReportStatusMapper::MISSING) {
            return [[
                'semantic_key' => 'add_bimi_record',
                'legacy_key' => 'bimi',
                'severity' => 'low',
                'title' => 'Add BIMI Record',
                'body' => 'Publish a BIMI TXT record to declare brand indicator configuration.',
                'suggested' => 'v=BIMI1; l=https://' . $domain . '/logo.svg',
                'card_state' => ScanReportStatusMapper::MISSING,
            ]];
        }

        if ($protocolStatus === BimiProtocolStatus::TEMPERROR) {
            return [[
                'semantic_key' => 'review_bimi_configuration',
                'legacy_key' => 'bimi',
                'severity' => 'low',
                'title' => 'Review BIMI configuration',
                'body' => BimiAnalysisReader::summary($bimiInfo) ?? 'BIMI could not be evaluated reliably.',
                'suggested' => null,
                'card_state' => ScanReportStatusMapper::UNKNOWN,
            ]];
        }

        $errorCode = $analysis['errors'][0]['code'] ?? ($native?->errors[0]['code'] ?? '');

        if ($protocolStatus === BimiProtocolStatus::PERMERROR) {
            $semantic = match ($errorCode) {
                'MULTIPLE_BIMI_RECORDS' => 'fix_multiple_bimi_records',
                'MISSING_L_TAG', 'EMPTY_LOGO_URI' => 'publish_bimi_logo',
                'INVALID_LOGO_URI' => 'fix_bimi_logo_uri',
                'NON_HTTPS_SCHEME' => 'fix_bimi_logo_https',
                'INDICATOR_MISMATCH' => 'align_bimi_logo_with_certificate',
                default => 'fix_invalid_bimi_record',
            };

            return [[
                'semantic_key' => $semantic,
                'legacy_key' => 'bimi',
                'severity' => 'medium',
                'title' => $this->titleForSemantic($semantic),
                'body' => $analysis['summary'] ?? ($native?->summary ?? 'The BIMI configuration needs attention.'),
                'suggested' => $analysis['record']['raw'] ?? $native?->rawRecord,
                'card_state' => ScanReportStatusMapper::FAIL,
            ]];
        }

        if (!($analysis['dmarc_eligibility']['core_eligible'] ?? $native?->dmarcEligibility['core_eligible'] ?? true)) {
            $items[] = $this->item(
                'fix_bimi_dmarc_eligibility',
                'Fix DMARC eligibility for BIMI',
                'DMARC must meet BIMI core eligibility requirements at the organizational domain.',
                null,
                ScanReportStatusMapper::FAIL,
                'high',
            );
        }

        $indicator = is_array($analysis['indicator'] ?? null) ? $analysis['indicator'] : ($native?->indicator ?? []);
        if (($indicator['status'] ?? '') === 'unavailable') {
            $items[] = $this->item(
                'fix_bimi_logo_fetch',
                'Fix BIMI logo fetch',
                'The published logo URL could not be retrieved.',
                $indicator['fetch']['source_uri'] ?? null,
                ScanReportStatusMapper::FAIL,
                'medium',
            );
        }

        if (($indicator['status'] ?? '') === 'invalid') {
            foreach ($indicator['validation']['validation_errors'] ?? [] as $validationError) {
                $code = $validationError['code'] ?? '';
                $semantic = match ($code) {
                    'SVG_TOO_LARGE' => 'reduce_bimi_logo_size',
                    'FORBIDDEN_ELEMENT', 'EVENT_HANDLER', 'JAVASCRIPT_URI', 'EXTERNAL_REFERENCE' => 'remove_unsafe_svg_content',
                    'INVALID_BASE_PROFILE', 'INVALID_SVG_VERSION' => 'convert_logo_to_svg_tiny_ps',
                    default => 'convert_logo_to_svg_tiny_ps',
                };
                $items[] = $this->item(
                    $semantic,
                    $this->titleForSemantic($semantic),
                    $validationError['message'] ?? 'SVG validation failed.',
                    null,
                    ScanReportStatusMapper::FAIL,
                    $semantic === 'remove_unsafe_svg_content' ? 'high' : 'medium',
                );
                break;
            }
        }

        $authority = is_array($analysis['authority_evidence'] ?? null)
            ? $analysis['authority_evidence']
            : ($native?->authorityEvidence ?? []);

        if (($authority['status'] ?? '') === BimiEvidenceStatus::SELF_ASSERTED) {
            $items[] = $this->item(
                'add_bimi_mark_certificate',
                'Add BIMI Mark Certificate',
                'A Mark Certificate may be required for some provider readiness profiles.',
                null,
                ScanReportStatusMapper::WARNING,
                'low',
            );
        }

        if (($authority['status'] ?? '') === BimiEvidenceStatus::INVALID) {
            $items[] = $this->item(
                'fix_bimi_mark_certificate',
                'Fix BIMI Mark Certificate',
                'The published Mark Certificate is invalid.',
                null,
                ScanReportStatusMapper::FAIL,
                'high',
            );
        }

        if (isset($authority['days_until_expiry']) && is_int($authority['days_until_expiry']) && $authority['days_until_expiry'] <= 30) {
            $items[] = $this->item(
                'renew_bimi_mark_certificate',
                'Renew BIMI Mark Certificate',
                'The Mark Certificate is expired or expiring soon.',
                null,
                ScanReportStatusMapper::FAIL,
                'high',
            );
        }

        if (($authority['domain_match'] ?? '') === 'mismatch') {
            $items[] = $this->item(
                'fix_bimi_certificate_domain',
                'Fix BIMI certificate domain',
                'Mark Certificate domain scope does not match the asserted domain.',
                null,
                ScanReportStatusMapper::FAIL,
                'high',
            );
        }

        if (($analysis['indicator_comparison']['identical'] ?? null) === false) {
            $items[] = $this->item(
                'align_bimi_logo_with_certificate',
                'Align BIMI logo with certificate',
                'Published logo bytes do not match the embedded certificate indicator.',
                null,
                ScanReportStatusMapper::FAIL,
                'high',
            );
        }

        foreach ($analysis['warnings'] ?? ($native?->warnings ?? []) as $warning) {
            $code = $warning['code'] ?? '';
            if ($code === 'LOCAL_PART_NOT_SUPPLIED') {
                $items[] = $this->item(
                    'review_bimi_local_part_selectors',
                    'Review BIMI local-part selectors',
                    $warning['message'] ?? 'Local-part selector evaluation is incomplete.',
                    null,
                    ScanReportStatusMapper::WARNING,
                    'low',
                );
                break;
            }
            if ($code === 'INVALID_AVP') {
                $items[] = $this->item(
                    'review_bimi_avatar_preference',
                    'Review BIMI avatar preference',
                    $warning['message'] ?? 'Avatar preference tag needs review.',
                    null,
                    ScanReportStatusMapper::WARNING,
                    'low',
                );
                break;
            }
        }

        if (($analysis['record']['lps_prefixes'] ?? []) !== []) {
            $items[] = $this->item(
                'review_bimi_selector_configuration',
                'Review BIMI selector configuration',
                'Local-part selector prefixes are configured.',
                null,
                ScanReportStatusMapper::WARNING,
                'low',
            );
        }

        foreach ($analysis['provider_profiles'] ?? ($native?->providerProfiles ?? []) as $profile) {
            if (!is_array($profile)) {
                continue;
            }
            if (($profile['readiness_status'] ?? '') === BimiReadinessStatus::NOT_READY) {
                $items[] = $this->item(
                    'review_bimi_provider_requirements',
                    'Review BIMI provider requirements',
                    'Configuration does not meet the ' . ($profile['label'] ?? 'provider') . ' readiness profile.',
                    null,
                    ScanReportStatusMapper::WARNING,
                    'low',
                );
                break;
            }
        }

        if ($items === [] && $cardState === ScanReportStatusMapper::WARNING) {
            $items[] = $this->item(
                'review_bimi_configuration',
                'Review BIMI configuration',
                $analysis['summary'] ?? ($native?->summary ?? 'Review the published BIMI configuration.'),
                null,
                ScanReportStatusMapper::WARNING,
                'low',
            );
        }

        return $this->dedupeBySemanticKey($items);
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
        string $severity = 'low',
    ): array {
        return [
            'semantic_key' => $semanticKey,
            'legacy_key' => 'bimi',
            'severity' => $severity,
            'title' => $title,
            'body' => $body,
            'suggested' => $suggested,
            'card_state' => $cardState,
        ];
    }

    private function titleForSemantic(string $semantic): string
    {
        return match ($semantic) {
            'fix_multiple_bimi_records' => 'Fix multiple BIMI records',
            'publish_bimi_logo' => 'Publish BIMI logo URI',
            'fix_bimi_logo_uri' => 'Fix BIMI logo URI',
            'fix_bimi_logo_https' => 'Use HTTPS for BIMI logo',
            'convert_logo_to_svg_tiny_ps' => 'Convert logo to SVG Tiny P/S',
            'reduce_bimi_logo_size' => 'Reduce BIMI logo size',
            'remove_unsafe_svg_content' => 'Remove unsafe SVG content',
            'align_bimi_logo_with_certificate' => 'Align BIMI logo with certificate',
            default => 'Fix BIMI record',
        };
    }

    /**
     * @param list<array{semantic_key: string, legacy_key: string, severity: string, title: string, body: string, suggested: ?string, card_state: string}> $items
     * @return list<array{semantic_key: string, legacy_key: string, severity: string, title: string, body: string, suggested: ?string, card_state: string}>
     */
    private function dedupeBySemanticKey(array $items): array
    {
        $seen = [];
        $deduped = [];

        foreach ($items as $item) {
            $key = $item['semantic_key'];
            if (isset($seen[$key])) {
                continue;
            }
            $seen[$key] = true;
            $deduped[] = $item;
        }

        return $deduped;
    }
}
