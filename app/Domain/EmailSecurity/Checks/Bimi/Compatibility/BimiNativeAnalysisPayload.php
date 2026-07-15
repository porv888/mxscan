<?php

namespace App\Domain\EmailSecurity\Checks\Bimi\Compatibility;

use App\Domain\EmailSecurity\Checks\Bimi\BimiNativeResult;

final class BimiNativeAnalysisPayload
{
    public const VERSION = 'bimi-native-v1';

    /**
     * @return array<string, mixed>
     */
    public function fromNative(BimiNativeResult $native): array
    {
        return [
            'version' => self::VERSION,
            'protocol_status' => $native->protocolStatus,
            'readiness_status' => $native->readinessStatus,
            'evidence_status' => $native->evidenceStatus,
            'risk_status' => $native->riskStatus,
            'state' => $native->state,
            'summary' => $native->summary,
            'domain' => $native->domain,
            'record_hostname' => $native->recordHostname,
            'evaluation_completeness' => $native->evaluationCompleteness,
            'standards_profile' => $native->standardsProfile,
            'record' => $native->record,
            'selector' => $native->selector,
            'discovery' => $native->discovery,
            'indicator' => $this->sanitizeIndicator($native->indicator),
            'authority_evidence' => $native->authorityEvidence,
            'indicator_comparison' => $native->indicatorComparison,
            'dmarc_eligibility' => $native->dmarcEligibility,
            'provider_profiles' => $native->providerProfiles,
            'local_part_evaluation' => $native->localPartEvaluation,
            'errors' => $this->sanitizeMessages($native->errors),
            'warnings' => $this->sanitizeMessages($native->warnings),
            'resolver_diagnostics' => $native->resolverDiagnostics,
        ];
    }

    /**
     * @param array<string, mixed> $indicator
     * @return array<string, mixed>
     */
    private function sanitizeIndicator(array $indicator): array
    {
        unset($indicator['_decompressed_svg']);

        return $indicator;
    }

    /**
     * @param list<array{code?: string, message?: string}> $items
     * @return list<array{code: string, message: string}>
     */
    private function sanitizeMessages(array $items): array
    {
        return array_values(array_map(
            fn (array $item) => [
                'code' => (string) ($item['code'] ?? ''),
                'message' => (string) ($item['message'] ?? ''),
            ],
            $items,
        ));
    }
}
