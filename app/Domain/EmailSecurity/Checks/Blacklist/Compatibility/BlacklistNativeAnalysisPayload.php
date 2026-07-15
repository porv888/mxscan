<?php

namespace App\Domain\EmailSecurity\Checks\Blacklist\Compatibility;

use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistNativeResult;
use App\Domain\EmailSecurity\Checks\Blacklist\BlacklistReputationStatus;

final class BlacklistNativeAnalysisPayload
{
    public const VERSION = 'blacklist-native-v1';

    /**
     * @return array<string, mixed>
     */
    public function fromNative(BlacklistNativeResult $native): array
    {
        return [
            'version' => self::VERSION,
            'analysis_status' => $native->analysisStatus,
            'reputation_status' => $native->reputationStatus,
            'state' => $native->state,
            'summary' => $native->summary,
            'targets' => $native->targets,
            'providers' => $native->providers,
            'checks' => $native->checks,
            'target_results' => $native->targetResults,
            'provider_health' => $native->providerHealth,
            'listings' => $native->listings,
            'counts' => $native->counts,
            'evaluation_completeness' => $native->evaluationCompleteness,
            'errors' => $native->errors,
            'warnings' => $native->warnings,
            'mx_evidence_version' => $native->mxEvidenceVersion,
        ];
    }
}
