<?php

namespace App\Domain\EmailSecurity\Checks\Blacklist\Compatibility;

use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistNativeResult;
use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistReputationStatus;

final class BlacklistLegacyPayloadAdapter
{
    public function __construct(
        private BlacklistNativeAnalysisPayload $analysisPayload = new BlacklistNativeAnalysisPayload(),
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toResultJsonBlacklist(BlacklistNativeResult $native): array
    {
        $counts = $native->counts;
        $usable = (int) ($counts['usable_results'] ?? 0);
        $listed = (int) ($counts['listed_results'] ?? 0);
        $clean = (int) ($counts['clean_results'] ?? 0);

        return [
            'analysis' => $this->analysisPayload->fromNative($native),
            'total_checks' => $usable,
            'listed_count' => $listed,
            'ok_count' => $clean,
            'unique_ips' => (int) ($counts['targets_total'] ?? 0),
            'providers_checked' => (int) ($counts['providers_enabled'] ?? 0),
            'is_clean' => $native->reputationStatus === BlacklistReputationStatus::CLEAN,
        ];
    }
}
