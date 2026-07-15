<?php

namespace App\Domain\EmailSecurity\Checks\Bimi;

use App\Domain\EmailSecurity\Checks\Bimi\DTO\BimiDiscoveryResult;

final class BimiStatusDeriver
{
    /**
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     * @param array<string, mixed> $context
     * @return array{
     *     protocol_status: string,
     *     readiness_status: string,
     *     evidence_status: string,
     *     risk_status: string,
     *     state: string,
     *     summary: string,
     *     evaluation_completeness: string
     * }
     */
    public function derive(BimiDiscoveryResult $discovery, array $context, array $errors, array $warnings): array
    {
        if ($discovery->hasDnsFailure()) {
            return $this->result(
                BimiProtocolStatus::TEMPERROR,
                BimiReadinessStatus::UNKNOWN,
                BimiEvidenceStatus::UNAVAILABLE,
                BimiRiskStatus::UNKNOWN,
                BimiStates::UNKNOWN,
                'BIMI could not be evaluated because of a temporary DNS failure.',
                'failed',
            );
        }

        if ($discovery->isMissing()) {
            return $this->result(
                BimiProtocolStatus::NONE,
                BimiReadinessStatus::NOT_PARTICIPATING,
                BimiEvidenceStatus::ABSENT,
                BimiRiskStatus::INFORMATIONAL,
                BimiStates::MISSING,
                'No BIMI record was found.',
                'complete',
            );
        }

        if ($discovery->hasMultipleRecords()) {
            return $this->result(
                BimiProtocolStatus::PERMERROR,
                BimiReadinessStatus::NOT_READY,
                BimiEvidenceStatus::INVALID,
                BimiRiskStatus::WARNING,
                BimiStates::FAIL,
                'The BIMI record is invalid or ambiguous.',
                'complete',
            );
        }

        if (($context['declined'] ?? false) === true) {
            return $this->result(
                BimiProtocolStatus::DECLINED,
                BimiReadinessStatus::NOT_PARTICIPATING,
                BimiEvidenceStatus::ABSENT,
                BimiRiskStatus::INFORMATIONAL,
                BimiStates::DECLINED,
                'BIMI participation is explicitly declined.',
                'complete',
            );
        }

        if ($errors !== []) {
            return $this->result(
                BimiProtocolStatus::PERMERROR,
                BimiReadinessStatus::NOT_READY,
                (string) ($context['evidence_status'] ?? BimiEvidenceStatus::INVALID),
                BimiRiskStatus::WARNING,
                BimiStates::FAIL,
                'The BIMI configuration needs attention.',
                (string) ($context['evaluation_completeness'] ?? 'complete'),
            );
        }

        if (($context['evaluation_completeness'] ?? 'complete') === 'partial') {
            return $this->result(
                BimiProtocolStatus::PARTIALLY_EVALUATED,
                BimiReadinessStatus::PARTIALLY_READY,
                (string) ($context['evidence_status'] ?? BimiEvidenceStatus::PARTIALLY_VALIDATED),
                BimiRiskStatus::WARNING,
                BimiStates::WARNING,
                'BIMI configuration is partially evaluated.',
                'partial',
            );
        }

        $indicatorStatus = (string) ($context['indicator']['status'] ?? '');
        $evidenceStatus = (string) ($context['authority_evidence']['status'] ?? BimiEvidenceStatus::ABSENT);
        $dmarcEligible = (bool) ($context['dmarc_eligibility']['core_eligible'] ?? false);

        $readiness = match (true) {
            !$dmarcEligible => BimiReadinessStatus::NOT_READY,
            $evidenceStatus === BimiEvidenceStatus::SELF_ASSERTED => BimiReadinessStatus::READY_SELF_ASSERTED,
            $indicatorStatus === 'valid' && in_array($evidenceStatus, [BimiEvidenceStatus::VALID, BimiEvidenceStatus::PARTIALLY_VALIDATED], true) => BimiReadinessStatus::READY,
            $indicatorStatus === 'valid' => BimiReadinessStatus::PARTIALLY_READY,
            default => BimiReadinessStatus::NOT_READY,
        };

        $risk = match (true) {
            !$dmarcEligible => BimiRiskStatus::WARNING,
            $warnings !== [] => BimiRiskStatus::WARNING,
            $readiness === BimiReadinessStatus::READY || $readiness === BimiReadinessStatus::READY_SELF_ASSERTED => BimiRiskStatus::HEALTHY,
            default => BimiRiskStatus::WARNING,
        };

        $state = match (true) {
            $warnings !== [] || $readiness === BimiReadinessStatus::PARTIALLY_READY => BimiStates::WARNING,
            $readiness === BimiReadinessStatus::READY || $readiness === BimiReadinessStatus::READY_SELF_ASSERTED => BimiStates::PASS,
            default => BimiStates::WARNING,
        };

        return $this->result(
            BimiProtocolStatus::VALID,
            $readiness,
            $evidenceStatus,
            $risk,
            $state,
            'BIMI configuration appears eligible for the evaluated profile.',
            (string) ($context['evaluation_completeness'] ?? 'complete'),
        );
    }

    /**
     * @return array{
     *     protocol_status: string,
     *     readiness_status: string,
     *     evidence_status: string,
     *     risk_status: string,
     *     state: string,
     *     summary: string,
     *     evaluation_completeness: string
     * }
     */
    private function result(
        string $protocol,
        string $readiness,
        string $evidence,
        string $risk,
        string $state,
        string $summary,
        string $completeness,
    ): array {
        return [
            'protocol_status' => $protocol,
            'readiness_status' => $readiness,
            'evidence_status' => $evidence,
            'risk_status' => $risk,
            'state' => $state,
            'summary' => $summary,
            'evaluation_completeness' => $completeness,
        ];
    }
}
