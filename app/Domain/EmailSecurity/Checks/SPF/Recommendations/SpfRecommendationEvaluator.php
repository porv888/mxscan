<?php

namespace App\Domain\EmailSecurity\Checks\SPF\Recommendations;

use App\Domain\EmailSecurity\Checks\SPF\SpfNativeResult;
use App\Domain\EmailSecurity\Checks\SPF\SpfProtocolStatus;
use App\Domain\EmailSecurity\Checks\SPF\SpfStates;
use App\Domain\EmailSecurity\Checks\SPF\SpfTerminalPolicy;
use App\Domain\EmailSecurity\Checks\SPF\Support\SpfAnalysisReader;
use App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper;
use App\Services\Spf\SpfResolver;

/**
 * Native SPF recommendation evaluation. Does not parse raw SPF strings.
 */
final class SpfRecommendationEvaluator
{
    /**
     * @param array<string, mixed>|null $spfRecord dns.records.SPF
     * @param array<string, mixed>|null $spfInfo result_json.spf
     * @param array<string, mixed> $spfCard from ScanReportStatusMapper::mapSpf
     * @return list<array{semantic_key: string, legacy_key: string, severity: string, title: string, body: string, suggested: ?string, card_state: string}>
     */
    public function evaluate(?array $spfRecord, array $spfCard, ?array $spfInfo = null, ?SpfNativeResult $native = null): array
    {
        $items = [];
        $recordStatus = $spfRecord['status'] ?? null;
        $nativeMeta = $this->nativeMeta($spfInfo, $native);

        if ($recordStatus !== 'found') {
            $items[] = [
                'semantic_key' => 'add_spf',
                'legacy_key' => 'spf_missing',
                'severity' => 'high',
                'title' => 'Add SPF Record',
                'body' => 'Publish an SPF TXT record so receivers can validate which servers may send mail for your domain. Identify your legitimate sending services (mail provider, CRM, marketing platform) before publishing.',
                'suggested' => null,
                'card_state' => ScanReportStatusMapper::MISSING,
            ];

            return $items;
        }

        $invalid = ($spfInfo['valid'] ?? true) === false
            || ($nativeMeta !== null && $this->isInvalidNativeMeta($nativeMeta));

        if ($spfCard['state'] === ScanReportStatusMapper::FAIL && $invalid) {
            $semantic = $this->hasCode($nativeMeta, 'MULTIPLE_SPF_RECORDS')
                || $this->hasLegacyWarning($spfInfo, SpfResolver::WARNING_MULTIPLE_SPF)
                ? 'fix_multiple_spf_records'
                : (($nativeMeta['protocol_status'] ?? null) === SpfProtocolStatus::TEMPERROR
                    || ($nativeMeta['ui_state'] ?? null) === SpfStates::UNKNOWN
                    ? 'investigate_spf_dns_failure'
                    : 'fix_invalid_spf');

            $items[] = [
                'semantic_key' => $semantic,
                'legacy_key' => 'spf_invalid',
                'severity' => 'high',
                'title' => 'Fix Invalid SPF Record',
                'body' => $spfCard['subtext'],
                'suggested' => is_string($spfInfo['record'] ?? null) ? $spfInfo['record'] : ($native?->rawRecord),
                'card_state' => ScanReportStatusMapper::FAIL,
            ];

            return $items;
        }

        if ($this->hasLegacyWarning($spfInfo, SpfResolver::WARNING_UNSUPPORTED_MACRO)
            || ($nativeMeta['protocol_status'] ?? null) === SpfProtocolStatus::PARTIALLY_EVALUATED) {
            $items[] = [
                'semantic_key' => 'review_unsupported_spf_macro',
                'legacy_key' => 'spf_invalid',
                'severity' => 'medium',
                'title' => 'Review Unsupported SPF Macros',
                'body' => 'This SPF record contains macros that cannot be fully evaluated in a domain configuration scan.',
                'suggested' => is_string($spfInfo['record'] ?? null) ? $spfInfo['record'] : ($native?->rawRecord),
                'card_state' => ScanReportStatusMapper::WARNING,
            ];
        }

        if ($this->hasLegacyWarning($spfInfo, SpfResolver::WARNING_PTR_USED)) {
            $items[] = [
                'semantic_key' => 'replace_deprecated_ptr',
                'legacy_key' => 'spf_invalid',
                'severity' => 'medium',
                'title' => 'Replace Deprecated PTR Mechanism',
                'body' => 'The ptr mechanism is deprecated and should be removed from your SPF configuration.',
                'suggested' => is_string($spfInfo['record'] ?? null) ? $spfInfo['record'] : ($native?->rawRecord),
                'card_state' => ScanReportStatusMapper::WARNING,
            ];
        }

        if ($this->hasWeakTerminalPolicy($nativeMeta, $spfInfo)) {
            $items[] = [
                'semantic_key' => 'review_weak_terminal_policy',
                'legacy_key' => 'spf_invalid',
                'severity' => 'medium',
                'title' => 'Review Weak SPF Terminal Policy',
                'body' => 'SPF policy uses a weak terminal qualifier. Review whether a stricter terminal policy is appropriate.',
                'suggested' => is_string($spfInfo['record'] ?? null) ? $spfInfo['record'] : ($native?->rawRecord),
                'card_state' => ScanReportStatusMapper::WARNING,
            ];
        }

        if (
            $spfCard['state'] === ScanReportStatusMapper::FAIL
            || $spfCard['state'] === ScanReportStatusMapper::WARNING
        ) {
            $lookups = (int) ($spfInfo['lookups'] ?? $native?->lookupCount ?? 0);
            $items[] = [
                'semantic_key' => 'reduce_spf_lookups',
                'legacy_key' => 'spf_lookups',
                'severity' => $lookups > 10 ? 'critical' : 'medium',
                'title' => 'Flatten SPF Record',
                'body' => "Your SPF record uses {$lookups}/10 DNS lookups." . ($lookups > 10
                    ? ' This exceeds the RFC limit and can cause delivery failures.'
                    : ($lookups === 10
                        ? ' This is at the RFC lookup limit.'
                        : ' Flatten it to improve reliability.')),
                'suggested' => $spfInfo['flattened'] ?? $native?->flattenedRecord,
                'card_state' => $spfCard['state'],
            ];
        }

        return $items;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function nativeMeta(?array $spfInfo, ?SpfNativeResult $native): ?array
    {
        if ($native !== null) {
            return [
                'protocol_status' => $native->protocolStatus,
                'risk_status' => $native->riskStatus,
                'ui_state' => $native->state,
                'terminal_policy' => $native->terminalPolicy,
                'errors' => $native->errors,
                'warnings' => $native->warnings,
            ];
        }

        if ($spfInfo === null) {
            return null;
        }

        return [
            'protocol_status' => SpfAnalysisReader::protocolStatus($spfInfo),
            'risk_status' => SpfAnalysisReader::riskStatus($spfInfo),
            'ui_state' => SpfAnalysisReader::state($spfInfo),
            'terminal_policy' => SpfAnalysisReader::terminalPolicy($spfInfo),
            'errors' => SpfAnalysisReader::errors($spfInfo),
            'warnings' => SpfAnalysisReader::warnings($spfInfo),
        ];
    }

    /**
     * @param array<string, mixed>|null $nativeMeta
     */
    private function isInvalidNativeMeta(?array $nativeMeta): bool
    {
        if ($nativeMeta === null) {
            return false;
        }

        return in_array($nativeMeta['ui_state'] ?? null, [SpfStates::FAIL, SpfStates::UNKNOWN], true)
            || ($nativeMeta['protocol_status'] ?? null) === SpfProtocolStatus::PERMERROR;
    }

    /**
     * @param array<string, mixed>|null $nativeMeta
     */
    private function hasCode(?array $nativeMeta, string $code): bool
    {
        if ($nativeMeta === null) {
            return false;
        }

        foreach (array_merge($nativeMeta['errors'] ?? [], $nativeMeta['warnings'] ?? []) as $item) {
            if (($item['code'] ?? '') === $code) {
                return true;
            }
        }

        if ($code === 'UNSUPPORTED_SPF_MACRO' && ($nativeMeta['protocol_status'] ?? null) === SpfProtocolStatus::PARTIALLY_EVALUATED) {
            return true;
        }

        return false;
    }

    /**
     * @param array<string, mixed>|null $spfInfo
     */
    private function hasLegacyWarning(?array $spfInfo, string $code): bool
    {
        if ($spfInfo === null) {
            return false;
        }

        return in_array($code, $spfInfo['warnings'] ?? [], true);
    }

    /**
     * @param array<string, mixed>|null $nativeMeta
     * @param array<string, mixed>|null $spfInfo
     */
    private function hasWeakTerminalPolicy(?array $nativeMeta, ?array $spfInfo): bool
    {
        if ($this->hasCode($nativeMeta, 'WEAK_TERMINAL_POLICY')) {
            return true;
        }

        $terminalPolicy = $nativeMeta['terminal_policy'] ?? SpfAnalysisReader::terminalPolicy($spfInfo);
        if ($terminalPolicy === null) {
            return false;
        }

        return in_array($terminalPolicy, [
            SpfTerminalPolicy::SOFT_FAIL,
            SpfTerminalPolicy::NEUTRAL,
            SpfTerminalPolicy::IMPLICIT_NEUTRAL,
            SpfTerminalPolicy::PASS_ALL,
        ], true);
    }
}
