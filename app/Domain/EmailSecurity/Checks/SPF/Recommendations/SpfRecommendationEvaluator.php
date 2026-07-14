<?php

namespace App\Domain\EmailSecurity\Checks\SPF\Recommendations;

use App\Domain\EmailSecurity\Checks\SPF\SpfNativeResult;
use App\Domain\EmailSecurity\Checks\SPF\SpfStates;
use App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper;

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
            || ($native !== null && $this->isInvalidNative($native));

        if ($spfCard['state'] === ScanReportStatusMapper::FAIL && $invalid) {
            $semantic = $native !== null && $this->hasCode($native->errors, 'MULTIPLE_SPF_RECORDS')
                ? 'fix_multiple_spf_records'
                : ($native !== null && $native->state === SpfStates::UNKNOWN
                    ? 'investigate_spf_dns_failure'
                    : 'fix_invalid_spf');

            $items[] = [
                'semantic_key' => $semantic,
                'legacy_key' => 'spf_invalid',
                'severity' => 'high',
                'title' => 'Fix Invalid SPF Record',
                'body' => $spfCard['subtext'],
                'suggested' => is_string($spfInfo['record'] ?? null) ? $spfInfo['record'] : $native?->rawRecord,
                'card_state' => ScanReportStatusMapper::FAIL,
            ];

            return $items;
        }

        if (
            $spfCard['state'] === ScanReportStatusMapper::FAIL
            || $spfCard['state'] === ScanReportStatusMapper::WARNING
        ) {
            $lookups = (int) ($spfInfo['lookups'] ?? $native?->lookupCount ?? 0);
            $items[] = [
                'semantic_key' => 'reduce_spf_lookups',
                'legacy_key' => 'spf_lookups',
                'severity' => $lookups >= 10 ? 'critical' : 'medium',
                'title' => 'Flatten SPF Record',
                'body' => "Your SPF record uses {$lookups}/10 DNS lookups." . ($lookups >= 10
                    ? ' This exceeds the RFC limit and can cause delivery failures.'
                    : ' Flatten it to improve reliability.'),
                'suggested' => $spfInfo['flattened'] ?? $native?->flattenedRecord,
                'card_state' => $spfCard['state'],
            ];
        }

        return $items;
    }

    private function isInvalidNative(SpfNativeResult $native): bool
    {
        return in_array($native->state, [SpfStates::FAIL, SpfStates::UNKNOWN], true)
            || $this->hasCode($native->errors, 'PLUS_ALL')
            || $this->hasCode($native->errors, 'MULTIPLE_SPF_RECORDS');
    }

    /**
     * @param list<array{code: string}> $items
     */
    private function hasCode(array $items, string $code): bool
    {
        foreach ($items as $item) {
            if (($item['code'] ?? '') === $code) {
                return true;
            }
        }

        return false;
    }
}
