<?php

namespace App\Domain\EmailSecurity\Checks\Blacklist;

use App\Domain\EmailSecurity\Checks\Mx\MxNativeResult;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\Support\ScanArtifactKeys;

final class BlacklistAnalysisService
{
    public function __construct(
        private BlacklistTargetCollector $targetCollector,
        private BlacklistEvidenceBuilder $evidenceBuilder,
        private BlacklistStatusDeriver $statusDeriver,
        private BlacklistProviderRegistry $registry,
    ) {
    }

    public function analyze(CheckContextDTO $context): BlacklistNativeResult
    {
        $mxNative = $context->priorArtifacts[ScanArtifactKeys::NATIVE_MX_RESULT] ?? null;
        $collection = $this->targetCollector->collect(
            $mxNative instanceof MxNativeResult ? $mxNative : null,
        );

        $enabledProviders = count($this->registry->enabled());

        if ($enabledProviders === 0) {
            return $this->notChecked($context->domainName, $collection['mx_evidence_version'], 'No blacklist providers configured.');
        }

        if (($collection['null_mx'] ?? false) === true) {
            return $this->notChecked($context->domainName, $collection['mx_evidence_version'], 'No inbound mail targets (valid Null MX).');
        }

        if ($collection['targets'] === []) {
            return $this->notChecked(
                $context->domainName,
                $collection['mx_evidence_version'],
                $collection['reason'] ?? 'No applicable public MX targets.',
            );
        }

        $evidence = $this->evidenceBuilder->build($collection['targets']);
        $derived = $this->statusDeriver->derive($evidence['counts'], $evidence['listings']);

        $targetRows = array_map(fn (BlacklistTarget $target) => [
            'address' => $target->address,
            'version' => $target->version,
            'source_type' => $target->sourceType,
            'source_mx_hostnames' => $target->sourceHostnames,
        ], $collection['targets']);

        return new BlacklistNativeResult(
            domain: $context->domainName,
            analysisStatus: $derived['analysis_status'],
            reputationStatus: $derived['reputation_status'],
            state: $derived['state'],
            summary: $derived['summary'],
            evaluationCompleteness: $derived['evaluation_completeness'],
            mxEvidenceVersion: $collection['mx_evidence_version'],
            targets: $targetRows,
            providers: $evidence['providers'],
            checks: $evidence['checks'],
            targetResults: $evidence['target_results'],
            providerHealth: $evidence['provider_health'],
            listings: $evidence['listings'],
            counts: $evidence['counts'],
            errors: $evidence['errors'],
            warnings: $evidence['warnings'],
        );
    }

    private function notChecked(string $domain, ?string $mxVersion, string $reason): BlacklistNativeResult
    {
        $counts = [
            'targets_total' => 0,
            'ipv4_targets' => 0,
            'ipv6_targets' => 0,
            'domain_targets' => 0,
            'providers_enabled' => 0,
            'providers_compatible' => 0,
            'queries_planned' => 0,
            'queries_completed' => 0,
            'usable_results' => 0,
            'clean_results' => 0,
            'listed_results' => 0,
            'unknown_results' => 0,
            'blocked_results' => 0,
            'timeout_results' => 0,
            'skipped_results' => 0,
        ];

        $derived = $this->statusDeriver->derive($counts, [], $reason);

        return new BlacklistNativeResult(
            domain: $domain,
            analysisStatus: $derived['analysis_status'],
            reputationStatus: $derived['reputation_status'],
            state: $derived['state'],
            summary: $derived['summary'],
            evaluationCompleteness: $derived['evaluation_completeness'],
            mxEvidenceVersion: $mxVersion,
            targets: [],
            providers: [],
            checks: [],
            targetResults: [],
            providerHealth: [],
            listings: [],
            counts: $counts,
        );
    }
}
