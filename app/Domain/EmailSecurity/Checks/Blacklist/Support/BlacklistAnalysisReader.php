<?php

namespace App\Domain\EmailSecurity\Checks\Blacklist\Support;

use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistReputationStatus;

final class BlacklistAnalysisReader
{
    /**
     * @param array<string, mixed>|null $blacklistInfo
     * @return array<string, mixed>|null
     */
    public static function analysis(?array $blacklistInfo): ?array
    {
        if (!is_array($blacklistInfo)) {
            return null;
        }

        $analysis = $blacklistInfo['analysis'] ?? null;

        return is_array($analysis) ? $analysis : null;
    }

    /**
     * @param array<string, mixed>|null $blacklistInfo
     */
    public static function reputationStatus(?array $blacklistInfo): ?string
    {
        $analysis = self::analysis($blacklistInfo);

        return is_array($analysis) ? ($analysis['reputation_status'] ?? null) : null;
    }

    /**
     * @param array<string, mixed>|null $blacklistInfo
     */
    public static function analysisStatus(?array $blacklistInfo): ?string
    {
        $analysis = self::analysis($blacklistInfo);

        return is_array($analysis) ? ($analysis['analysis_status'] ?? null) : null;
    }

    /**
     * @param array<string, mixed>|null $blacklistInfo
     */
    public static function state(?array $blacklistInfo): ?string
    {
        $analysis = self::analysis($blacklistInfo);

        return is_array($analysis) ? ($analysis['state'] ?? null) : null;
    }

    /**
     * @param array<string, mixed>|null $blacklistInfo
     */
    public static function summary(?array $blacklistInfo): ?string
    {
        $analysis = self::analysis($blacklistInfo);

        return is_array($analysis) ? ($analysis['summary'] ?? null) : null;
    }

    /**
     * @param array<string, mixed>|null $blacklistInfo
     * @return array<string, int>
     */
    public static function counts(?array $blacklistInfo): array
    {
        $analysis = self::analysis($blacklistInfo);
        $counts = is_array($analysis) ? ($analysis['counts'] ?? []) : [];

        return is_array($counts) ? $counts : [];
    }

    /**
     * @param array<string, mixed>|null $blacklistInfo
     */
    public static function fromLegacySummary(?array $blacklistInfo): ?array
    {
        if (!is_array($blacklistInfo) || isset($blacklistInfo['analysis'])) {
            return self::analysis($blacklistInfo);
        }

        $total = (int) ($blacklistInfo['total_checks'] ?? 0);
        $listed = (int) ($blacklistInfo['listed_count'] ?? 0);
        $isClean = !empty($blacklistInfo['is_clean']);

        $reputation = match (true) {
            $total <= 0 => BlacklistReputationStatus::NOT_CHECKED,
            $listed > 0 => BlacklistReputationStatus::LISTED,
            $isClean || !array_key_exists('is_clean', $blacklistInfo) => BlacklistReputationStatus::CLEAN,
            default => BlacklistReputationStatus::UNKNOWN,
        };

        return [
            'version' => 'legacy-summary',
            'analysis_status' => $total <= 0 ? 'not_checked' : ($isClean ? 'complete' : 'partial'),
            'reputation_status' => $reputation,
            'state' => match ($reputation) {
                BlacklistReputationStatus::CLEAN => 'pass',
                BlacklistReputationStatus::LISTED => 'fail',
                BlacklistReputationStatus::NOT_CHECKED => 'not_checked',
                default => 'unknown',
            },
            'summary' => $blacklistInfo['summary'] ?? null,
            'counts' => [
                'usable_results' => $total,
                'listed_results' => $listed,
                'queries_planned' => $total,
            ],
        ];
    }

    /**
     * @param array<string, mixed>|null $blacklistInfo
     * @return array<string, mixed>
     */
    public static function resolvedAnalysis(?array $blacklistInfo): array
    {
        return self::analysis($blacklistInfo)
            ?? self::fromLegacySummary($blacklistInfo)
            ?? [
                'reputation_status' => BlacklistReputationStatus::NOT_CHECKED,
                'analysis_status' => 'not_checked',
                'state' => 'not_checked',
                'counts' => ['usable_results' => 0, 'listed_results' => 0, 'queries_planned' => 0],
            ];
    }

    /**
     * @param array<string, mixed>|null $blacklistInfo
     * @return array<string, mixed>
     */
    public static function facts(?array $blacklistInfo): array
    {
        $analysis = self::resolvedAnalysis($blacklistInfo);
        $counts = is_array($analysis['counts'] ?? null) ? $analysis['counts'] : [];

        $usable = (int) ($counts['usable_results'] ?? 0);
        $reputation = (string) ($analysis['reputation_status'] ?? BlacklistReputationStatus::NOT_CHECKED);

        return [
            'blacklist_analysis_status' => $analysis['analysis_status'] ?? null,
            'blacklist_reputation_status' => $reputation,
            'blacklist_targets_total' => (int) ($counts['targets_total'] ?? 0),
            'blacklist_ipv4_targets' => (int) ($counts['ipv4_targets'] ?? 0),
            'blacklist_ipv6_targets' => (int) ($counts['ipv6_targets'] ?? 0),
            'blacklist_providers_enabled' => (int) ($counts['providers_enabled'] ?? 0),
            'blacklist_queries_planned' => (int) ($counts['queries_planned'] ?? 0),
            'blacklist_queries_completed' => (int) ($counts['queries_completed'] ?? 0),
            'blacklist_usable_results' => $usable,
            'blacklist_clean_results' => (int) ($counts['clean_results'] ?? 0),
            'blacklist_listed_results' => (int) ($counts['listed_results'] ?? 0),
            'blacklist_unknown_results' => (int) ($counts['unknown_results'] ?? 0),
            'blacklist_blocked_results' => (int) ($counts['blocked_results'] ?? 0),
            'blacklist_timeout_results' => (int) ($counts['timeout_results'] ?? 0),
            'blacklist_is_listed' => $reputation === BlacklistReputationStatus::LISTED,
            'blacklist_is_partial' => $reputation === BlacklistReputationStatus::PARTIAL,
            'blacklist_was_checked' => $usable > 0,
            'blacklist_status' => self::compatStatusLabel($reputation),
            'blacklist_count' => (int) ($counts['listed_results'] ?? ($blacklistInfo['listed_count'] ?? 0)),
        ];
    }

    public static function compatStatusLabel(string $reputation): string
    {
        return match ($reputation) {
            BlacklistReputationStatus::CLEAN => 'clean',
            BlacklistReputationStatus::LISTED => 'listed',
            BlacklistReputationStatus::PARTIAL => 'partial',
            BlacklistReputationStatus::UNKNOWN => 'unknown',
            default => 'not-checked',
        };
    }
}
