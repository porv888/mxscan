<?php

namespace App\Domain\EmailSecurity\Checks\Blacklist;

final class BlacklistStatusDeriver
{
    /**
     * @param array<string, int> $counts
     * @param list<array<string, mixed>> $listings
     * @return array{
     *   analysis_status: string,
     *   reputation_status: string,
     *   state: string,
     *   summary: string,
     *   evaluation_completeness: string
     * }
     */
    public function derive(array $counts, array $listings, ?string $notCheckedReason = null): array
    {
        $planned = (int) ($counts['queries_planned'] ?? 0);
        $usable = (int) ($counts['usable_results'] ?? 0);
        $listed = (int) ($counts['listed_results'] ?? 0);
        $unknown = (int) ($counts['unknown_results'] ?? 0);
        $clean = (int) ($counts['clean_results'] ?? 0);

        if ($notCheckedReason !== null || $planned === 0) {
            return [
                'analysis_status' => BlacklistAnalysisStatus::NOT_CHECKED,
                'reputation_status' => BlacklistReputationStatus::NOT_CHECKED,
                'state' => BlacklistStates::NOT_CHECKED,
                'summary' => $notCheckedReason ?? 'Blacklist check did not run.',
                'evaluation_completeness' => 'not_applicable',
            ];
        }

        if ($listed > 0) {
            return [
                'analysis_status' => $usable === $planned ? BlacklistAnalysisStatus::COMPLETE : BlacklistAnalysisStatus::PARTIAL,
                'reputation_status' => BlacklistReputationStatus::LISTED,
                'state' => BlacklistStates::FAIL,
                'summary' => $listed . ' confirmed listing(s) found across ' . $usable . ' usable check(s).',
                'evaluation_completeness' => $usable === $planned ? 'complete' : 'partial',
            ];
        }

        if ($usable === $planned && $planned > 0 && $listed === 0) {
            return [
                'analysis_status' => BlacklistAnalysisStatus::COMPLETE,
                'reputation_status' => BlacklistReputationStatus::CLEAN,
                'state' => BlacklistStates::PASS,
                'summary' => 'Checked ' . $planned . ' provider queries across mail targets; no listings found.',
                'evaluation_completeness' => 'complete',
            ];
        }

        if ($usable > 0 && $unknown > 0 && $listed === 0) {
            return [
                'analysis_status' => BlacklistAnalysisStatus::PARTIAL,
                'reputation_status' => BlacklistReputationStatus::PARTIAL,
                'state' => BlacklistStates::WARNING,
                'summary' => 'No listings were found on the successfully checked providers, but some checks could not be completed.',
                'evaluation_completeness' => 'partial',
            ];
        }

        if ($usable === 0 && $planned > 0) {
            return [
                'analysis_status' => BlacklistAnalysisStatus::UNAVAILABLE,
                'reputation_status' => BlacklistReputationStatus::UNKNOWN,
                'state' => BlacklistStates::UNKNOWN,
                'summary' => 'Blacklist providers could not be queried successfully for the available mail targets.',
                'evaluation_completeness' => 'incomplete',
            ];
        }

        return [
            'analysis_status' => BlacklistAnalysisStatus::UNAVAILABLE,
            'reputation_status' => BlacklistReputationStatus::UNKNOWN,
            'state' => BlacklistStates::UNKNOWN,
            'summary' => 'Blacklist reputation could not be determined.',
            'evaluation_completeness' => 'incomplete',
        ];
    }
}
