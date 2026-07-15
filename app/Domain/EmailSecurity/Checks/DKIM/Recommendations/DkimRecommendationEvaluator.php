<?php

namespace App\Domain\EmailSecurity\Checks\DKIM\Recommendations;

use App\Domain\EmailSecurity\Checks\DKIM\DkimNativeResult;
use App\Domain\EmailSecurity\Checks\DKIM\DkimProtocolStatus;
use App\Domain\EmailSecurity\Checks\DKIM\DkimSelectorSource;
use App\Domain\EmailSecurity\Checks\DKIM\DkimStates;
use App\Domain\EmailSecurity\Checks\DKIM\Support\DkimAnalysisReader;
use App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper;

final class DkimRecommendationEvaluator
{
    /**
     * @param array<string, mixed>|null $dkimInfo
     * @param array<string, mixed>|null $dkimCard
     * @return list<array{semantic_key: string, legacy_key: string, severity: string, title: string, body: string, suggested: ?string, card_state: string}>
     */
    public function evaluate(?array $dkimInfo, ?array $dkimCard = null, ?DkimNativeResult $native = null, ?array $dkimDnsRecord = null): array
    {
        $analysis = DkimAnalysisReader::analysis($dkimInfo)
            ?? DkimAnalysisReader::fromLegacyDnsRecord($dkimDnsRecord, $dkimInfo);
        $cardState = $dkimCard['state'] ?? DkimAnalysisReader::state($dkimInfo) ?? ScanReportStatusMapper::UNKNOWN;
        $protocolStatus = $native?->protocolStatus ?? ($analysis['protocol_status'] ?? DkimAnalysisReader::protocolStatus($dkimInfo));
        $coverage = is_array($analysis['selector_coverage'] ?? null) ? $analysis['selector_coverage'] : ($native?->selectorCoverage ?? []);
        $selectors = is_array($analysis['selectors'] ?? null) ? $analysis['selectors'] : ($native?->selectors ?? []);

        $items = [];

        if ($protocolStatus === DkimProtocolStatus::PARTIALLY_EVALUATED
            || ($coverage['selectors_available'] ?? true) === false) {
            $items[] = $this->item(
                'provide_dkim_selector',
                'dkim_selector',
                'high',
                'Provide a DKIM Selector',
                'MXScan could not evaluate DKIM without a selector. Supply your provider\'s selector or a sample DKIM-Signature header.',
                $cardState === ScanReportStatusMapper::UNKNOWN ? ScanReportStatusMapper::UNKNOWN : ScanReportStatusMapper::MISSING,
            );
            $items[] = $this->item(
                'verify_dkim_signing_with_sample_message',
                'dkim_verify',
                'medium',
                'Verify DKIM Signing With a Sample Message',
                'DKIM signing cannot be confirmed without inspecting a signed message.',
                $cardState,
            );

            return $this->dedupe($items);
        }

        $items[] = $this->item(
            'verify_dkim_signing_with_sample_message',
            'dkim_verify',
            'medium',
            'Verify DKIM Signing With a Sample Message',
            'Published DNS keys confirm configuration only. Verify live signing with a sample signed message.',
            $cardState,
        );

        foreach ($selectors as $selector) {
            if (!is_array($selector)) {
                continue;
            }

            $source = $selector['source'] ?? '';
            $recordStatus = $selector['record_status'] ?? '';
            $errors = $selector['errors'] ?? [];

            if ($recordStatus === 'none' && DkimSelectorSource::isAuthoritative($source)) {
                $items[] = $this->item(
                    'publish_dkim_key',
                    'dkim_dns',
                    'high',
                    'Publish DKIM Key',
                    "No DKIM key was found for selector {$selector['selector']}.",
                    ScanReportStatusMapper::MISSING,
                );
            }

            if ($recordStatus === 'revoked') {
                $items[] = $this->item(
                    'replace_revoked_dkim_key',
                    'dkim_revoked',
                    'critical',
                    'Replace Revoked DKIM Key',
                    "Selector {$selector['selector']} publishes an empty p= tag (revoked key).",
                    ScanReportStatusMapper::FAIL,
                );
            }

            if ($recordStatus === 'ambiguous' || $this->hasCode($errors, 'MULTIPLE_DKIM_RECORDS')) {
                $items[] = $this->item(
                    'fix_multiple_dkim_records',
                    'dkim_multiple',
                    'high',
                    'Fix Multiple DKIM Records',
                    "Selector {$selector['selector']} returned multiple DKIM key records.",
                    ScanReportStatusMapper::FAIL,
                );
            }

            if ($recordStatus === 'invalid' || $this->hasCode($errors, 'MALFORMED_PUBLIC_KEY') || $this->hasCode($errors, 'INVALID_BASE64')) {
                $items[] = $this->item(
                    'fix_invalid_dkim_record',
                    'dkim_invalid',
                    'high',
                    'Fix Invalid DKIM Record',
                    "The tested selector {$selector['selector']} contains an invalid DKIM key record.",
                    ScanReportStatusMapper::FAIL,
                );
            }

            if ($this->hasCode($errors, 'RSA_TOO_WEAK') || $this->hasCode($selector['warnings'] ?? [], 'WEAK_RSA_KEY')) {
                $items[] = $this->item(
                    'upgrade_weak_dkim_key',
                    'dkim_weak',
                    'high',
                    'Upgrade Weak DKIM Key',
                    "Selector {$selector['selector']} uses an RSA key below 2048 bits.",
                    ScanReportStatusMapper::WARNING,
                );
            }

            if ($this->hasCode($errors, 'SHA1_ONLY')) {
                $items[] = $this->item(
                    'replace_sha1_dkim_configuration',
                    'dkim_sha1',
                    'high',
                    'Replace SHA-1 DKIM Configuration',
                    "Selector {$selector['selector']} restricts hashing to SHA-1 only.",
                    ScanReportStatusMapper::FAIL,
                );
            }

            if ($this->hasCode($errors, 'NON_EMAIL_SERVICE')) {
                $items[] = $this->item(
                    'fix_dkim_service_type',
                    'dkim_service',
                    'high',
                    'Fix DKIM Service Type',
                    "Selector {$selector['selector']} does not apply to email service.",
                    ScanReportStatusMapper::FAIL,
                );
            }

            if ($recordStatus === 'unsupported' || $this->hasCode($errors, 'UNSUPPORTED_KEY_TYPE')) {
                $items[] = $this->item(
                    'review_unsupported_dkim_key_type',
                    'dkim_unsupported',
                    'medium',
                    'Review Unsupported DKIM Key Type',
                    "Selector {$selector['selector']} uses a key type that MXScan could not fully evaluate.",
                    ScanReportStatusMapper::UNKNOWN,
                );
            }

            if (($selector['testing'] ?? false) === true) {
                $items[] = $this->item(
                    'disable_dkim_testing_mode',
                    'dkim_testing',
                    'medium',
                    'Disable DKIM Testing Mode',
                    "Selector {$selector['selector']} is flagged for testing mode (t=y).",
                    ScanReportStatusMapper::WARNING,
                );
            }

            if ($recordStatus === 'none' && $source === DkimSelectorSource::CONFIRMED) {
                $items[] = $this->item(
                    'rotate_dkim_selector',
                    'dkim_rotate',
                    'medium',
                    'Rotate DKIM Selector',
                    "Previously confirmed selector {$selector['selector']} no longer publishes a key.",
                    ScanReportStatusMapper::MISSING,
                );
            }
        }

        if ($protocolStatus === DkimProtocolStatus::NONE
            && ($coverage['coverage_type'] ?? '') === 'catalog_only'
            && !$this->hasSemanticKey($items, 'publish_dkim_key')) {
            // Do not recommend publish_dkim_key for catalog-only misses.
        }

        return $this->dedupe($items);
    }

    /**
     * @param list<array{semantic_key: string, legacy_key: string, severity: string, title: string, body: string, suggested: ?string, card_state: string}> $items
     * @return list<array{semantic_key: string, legacy_key: string, severity: string, title: string, body: string, suggested: ?string, card_state: string}>
     */
    private function dedupe(array $items): array
    {
        $seen = [];
        $unique = [];

        foreach ($items as $item) {
            $key = $item['semantic_key'];
            if (isset($seen[$key])) {
                continue;
            }
            $seen[$key] = true;
            $unique[] = $item;
        }

        return $unique;
    }

    /**
     * @param list<array{code?: string}> $messages
     */
    private function hasCode(array $messages, string $code): bool
    {
        foreach ($messages as $message) {
            if (($message['code'] ?? '') === $code) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<array{semantic_key: string}> $items
     */
    private function hasSemanticKey(array $items, string $key): bool
    {
        foreach ($items as $item) {
            if (($item['semantic_key'] ?? '') === $key) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array{semantic_key: string, legacy_key: string, severity: string, title: string, body: string, suggested: ?string, card_state: string}
     */
    private function item(
        string $semanticKey,
        string $legacyKey,
        string $severity,
        string $title,
        string $body,
        string $cardState,
        ?string $suggested = null,
    ): array {
        return [
            'semantic_key' => $semanticKey,
            'legacy_key' => $legacyKey,
            'severity' => $severity,
            'title' => $title,
            'body' => $body,
            'suggested' => $suggested,
            'card_state' => $cardState,
        ];
    }
}
