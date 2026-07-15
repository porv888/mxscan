<?php

namespace App\Domain\EmailSecurity\Checks\Blacklist\Recommendations;

use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistAnalysisStatus;
use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistReputationStatus;
use App\Domain\EmailSecurity\Checks\Blacklist\Support\BlacklistAnalysisReader;
use App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper;

final class BlacklistRecommendationEvaluator
{
    /**
     * @param array<string, mixed>|null $blacklistInfo
     * @return list<array{semantic_key: string, legacy_key: string, severity: string, title: string, body: string, suggested: ?string, card_state: string}>
     */
    public function evaluate(?array $blacklistInfo, ?array $blacklistCard = null): array
    {
        $analysis = BlacklistAnalysisReader::resolvedAnalysis($blacklistInfo);
        $reputation = (string) ($analysis['reputation_status'] ?? BlacklistReputationStatus::NOT_CHECKED);
        $cardState = $blacklistCard['state'] ?? $analysis['state'] ?? ScanReportStatusMapper::UNKNOWN;
        $listed = (int) (($analysis['counts']['listed_results'] ?? 0));
        $items = [];
        $seen = [];

        if ($reputation === BlacklistReputationStatus::LISTED) {
            $items[] = $this->once($seen, $this->item(
                'investigate_blacklist_listing',
                "Confirmed blacklist listing(s) detected across {$listed} usable check(s). Investigate the affected mail targets and outbound activity.",
                'critical',
                'Investigate blacklist listing',
                ScanReportStatusMapper::FAIL,
            ));

            $items[] = $this->once($seen, $this->item(
                'verify_mail_server_compromise',
                'Review whether any mail server or account may have been compromised or misconfigured before requesting delisting.',
                'high',
                'Verify mail server security',
                ScanReportStatusMapper::FAIL,
            ));

            $items[] = $this->once($seen, $this->item(
                'review_outbound_mail_activity',
                'Review recent outbound mail volume and authentication failures that may explain the listing.',
                'medium',
                'Review outbound mail activity',
                ScanReportStatusMapper::FAIL,
            ));

            $items[] = $this->once($seen, $this->item(
                'request_blacklist_delisting',
                'After investigating and fixing the underlying cause, use provider delisting resources to request removal.',
                'medium',
                'Request blacklist delisting',
                ScanReportStatusMapper::FAIL,
            ));
        }

        if ($reputation === BlacklistReputationStatus::PARTIAL) {
            $items[] = $this->once($seen, $this->item(
                'review_partial_blacklist_results',
                'No listings were found on successfully checked providers, but some blacklist queries could not be completed.',
                'medium',
                'Review partial blacklist results',
                ScanReportStatusMapper::WARNING,
            ));
        }

        if ($reputation === BlacklistReputationStatus::NOT_CHECKED
            && ($analysis['analysis_status'] ?? '') === BlacklistAnalysisStatus::NOT_CHECKED
            && (int) ($analysis['counts']['providers_enabled'] ?? 0) === 0) {
            $items[] = $this->once($seen, $this->item(
                'configure_blacklist_providers',
                'No blacklist providers are currently enabled for reputation checks.',
                'low',
                'Configure blacklist providers',
                ScanReportStatusMapper::NOT_CHECKED,
            ));
        }

        $ipv6Targets = (int) ($analysis['counts']['ipv6_targets'] ?? 0);
        $ipv4Targets = (int) ($analysis['counts']['ipv4_targets'] ?? 0);
        if ($ipv6Targets > 0 && $ipv4Targets === 0) {
            $items[] = $this->once($seen, $this->item(
                'review_ipv6_blacklist_coverage',
                'Mail targets include IPv6 addresses; verify provider coverage for IPv6 blacklist queries.',
                'low',
                'Review IPv6 blacklist coverage',
                $cardState,
            ));
        }

        if ($reputation === BlacklistReputationStatus::UNKNOWN) {
            $items[] = $this->once($seen, $this->item(
                'investigate_blacklist_provider_failure',
                'Blacklist providers could not be queried successfully. Re-run the check or review provider availability.',
                'medium',
                'Investigate blacklist provider failure',
                ScanReportStatusMapper::UNKNOWN,
            ));
        }

        return array_values(array_filter($items));
    }

    /**
     * @param array<string, true> $seen
     * @return array{semantic_key: string, legacy_key: string, severity: string, title: string, body: string, suggested: ?string, card_state: string}|null
     */
    private function once(array &$seen, ?array $item): ?array
    {
        if ($item === null || isset($seen[$item['semantic_key']])) {
            return null;
        }

        $seen[$item['semantic_key']] = true;

        return $item;
    }

    /**
     * @return array{semantic_key: string, legacy_key: string, severity: string, title: string, body: string, suggested: ?string, card_state: string}
     */
    private function item(
        string $semanticKey,
        string $body,
        string $severity,
        string $title,
        string $cardState,
    ): array {
        return [
            'semantic_key' => $semanticKey,
            'legacy_key' => 'blacklist_reputation',
            'severity' => $severity,
            'title' => $title,
            'body' => $body,
            'suggested' => null,
            'card_state' => $cardState,
        ];
    }
}
