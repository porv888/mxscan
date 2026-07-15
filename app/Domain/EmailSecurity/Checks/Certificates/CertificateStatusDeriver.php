<?php

namespace App\Domain\EmailSecurity\Checks\Certificates;

use App\Domain\EmailSecurity\Checks\Certificates\DTO\CertificateEndpointEvaluation;

final class CertificateStatusDeriver
{
    public const ANALYSIS_COMPLETE = 'complete';
    public const ANALYSIS_PARTIAL = 'partial';
    public const ANALYSIS_UNAVAILABLE = 'unavailable';
    public const ANALYSIS_NOT_CHECKED = 'not_checked';

    /**
     * @param list<CertificateEndpointEvaluation> $evaluations
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     * @return array{
     *     analysis_status: string,
     *     risk_status: string,
     *     state: string,
     *     summary: string,
     *     evaluation_completeness: string
     * }
     */
    public function derive(array $evaluations, array $errors, array $warnings): array
    {
        if ($evaluations === []) {
            return $this->result(
                self::ANALYSIS_NOT_CHECKED,
                CertificateRiskStatus::UNKNOWN,
                CertificateStates::NOT_CHECKED,
                'No certificate endpoints were selected for evaluation.',
                'not_checked',
            );
        }

        $evaluated = 0;
        $unavailable = 0;
        $invalid = 0;
        $warningCount = 0;
        $valid = 0;
        $criticalFailure = false;
        $hasExpiryWarning = false;
        $hasWeakSignal = false;

        foreach ($evaluations as $evaluation) {
            if ($this->isUnavailable($evaluation)) {
                $unavailable++;
                continue;
            }

            if ($this->isEvaluated($evaluation)) {
                $evaluated++;
            }

            if ($this->isInvalid($evaluation)) {
                $invalid++;
                if ($this->isCriticalEndpoint($evaluation) || $this->isDefinitiveInvalid($evaluation)) {
                    $criticalFailure = true;
                }
                continue;
            }

            if ($evaluation->certificateStatus === CertificateEndpointEvaluation::CERTIFICATE_WARNING
                || $evaluation->uiState === CertificateEndpointEvaluation::UI_WARNING) {
                $warningCount++;
                $hasExpiryWarning = true;
            } elseif ($this->isValid($evaluation)) {
                $valid++;
            }

            if ($this->hasWeakKeyOrSignature($evaluation)) {
                $hasWeakSignal = true;
            }
        }

        $total = count($evaluations);

        if ($evaluated === 0) {
            return $this->result(
                self::ANALYSIS_UNAVAILABLE,
                CertificateRiskStatus::UNKNOWN,
                CertificateStates::UNKNOWN,
                'Certificate endpoints could not be evaluated reliably.',
                'failed',
            );
        }

        if ($criticalFailure || $invalid > 0) {
            return $this->result(
                $unavailable > 0 ? self::ANALYSIS_PARTIAL : self::ANALYSIS_COMPLETE,
                CertificateRiskStatus::CRITICAL,
                CertificateStates::FAIL,
                'One or more evaluated certificates are invalid or expired.',
                $unavailable > 0 ? 'partial' : 'complete',
            );
        }

        if ($hasExpiryWarning || $hasWeakSignal || $warningCount > 0) {
            return $this->result(
                $unavailable > 0 ? self::ANALYSIS_PARTIAL : self::ANALYSIS_COMPLETE,
                CertificateRiskStatus::WARNING,
                CertificateStates::WARNING,
                $hasExpiryWarning
                    ? 'One or more certificates are valid but approaching expiry.'
                    : 'Certificate evaluation completed with operational warnings.',
                $unavailable > 0 ? 'partial' : 'complete',
            );
        }

        if ($unavailable > 0 && $evaluated < $total) {
            return $this->result(
                self::ANALYSIS_PARTIAL,
                CertificateRiskStatus::WARNING,
                CertificateStates::WARNING,
                'Certificate monitoring was partially completed because one or more endpoints were unavailable.',
                'partial',
            );
        }

        if ($valid > 0) {
            return $this->result(
                self::ANALYSIS_COMPLETE,
                CertificateRiskStatus::HEALTHY,
                CertificateStates::PASS,
                'All evaluated certificates are currently valid.',
                'complete',
            );
        }

        return $this->result(
            self::ANALYSIS_PARTIAL,
            CertificateRiskStatus::UNKNOWN,
            CertificateStates::UNKNOWN,
            'Certificate evaluation completed with incomplete results.',
            'partial',
        );
    }

    private function isUnavailable(CertificateEndpointEvaluation $evaluation): bool
    {
        return $evaluation->protocolStatus === CertificateEndpointEvaluation::PROTOCOL_UNAVAILABLE
            || $evaluation->certificateStatus === CertificateEndpointEvaluation::CERTIFICATE_UNAVAILABLE
            || $evaluation->uiState === CertificateEndpointEvaluation::UI_UNKNOWN;
    }

    private function isEvaluated(CertificateEndpointEvaluation $evaluation): bool
    {
        return in_array($evaluation->protocolStatus, [
            CertificateEndpointEvaluation::PROTOCOL_EVALUATED,
            CertificateEndpointEvaluation::PROTOCOL_PARTIALLY_EVALUATED,
        ], true);
    }

    private function isInvalid(CertificateEndpointEvaluation $evaluation): bool
    {
        return in_array($evaluation->certificateStatus, [
            CertificateEndpointEvaluation::CERTIFICATE_INVALID,
            CertificateEndpointEvaluation::CERTIFICATE_EXPIRED,
            CertificateEndpointEvaluation::CERTIFICATE_NOT_YET_VALID,
        ], true) || $evaluation->uiState === CertificateEndpointEvaluation::UI_FAIL;
    }

    private function isValid(CertificateEndpointEvaluation $evaluation): bool
    {
        return in_array($evaluation->certificateStatus, [
            CertificateEndpointEvaluation::CERTIFICATE_VALID,
            CertificateEndpointEvaluation::CERTIFICATE_WARNING,
        ], true) && $evaluation->uiState === CertificateEndpointEvaluation::UI_PASS;
    }

    private function isDefinitiveInvalid(CertificateEndpointEvaluation $evaluation): bool
    {
        return $evaluation->parsed !== null
            && (
                !$evaluation->hostnameMatch
                || !$evaluation->trusted
                || $evaluation->certificateStatus === CertificateEndpointEvaluation::CERTIFICATE_EXPIRED
                || $evaluation->certificateStatus === CertificateEndpointEvaluation::CERTIFICATE_NOT_YET_VALID
            );
    }

    private function isCriticalEndpoint(CertificateEndpointEvaluation $evaluation): bool
    {
        return $evaluation->endpoint->kind === CertificateEndpoint::KIND_MTA_STS_HTTPS;
    }

    private function hasWeakKeyOrSignature(CertificateEndpointEvaluation $evaluation): bool
    {
        return $evaluation->keyStrengthClassification === CertificateKeyInspector::CLASSIFICATION_WEAK
            || in_array($evaluation->signatureClassification, [
                CertificateSignatureInspector::CLASSIFICATION_WEAK,
                CertificateSignatureInspector::CLASSIFICATION_OBSOLETE,
            ], true);
    }

    /**
     * @return array{
     *     analysis_status: string,
     *     risk_status: string,
     *     state: string,
     *     summary: string,
     *     evaluation_completeness: string
     * }
     */
    private function result(
        string $analysisStatus,
        string $riskStatus,
        string $state,
        string $summary,
        string $completeness,
    ): array {
        return [
            'analysis_status' => $analysisStatus,
            'risk_status' => $riskStatus,
            'state' => $state,
            'summary' => $summary,
            'evaluation_completeness' => $completeness,
        ];
    }
}
