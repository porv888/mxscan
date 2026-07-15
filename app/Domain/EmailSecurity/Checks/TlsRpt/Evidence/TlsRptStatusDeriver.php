<?php

namespace App\Domain\EmailSecurity\Checks\TlsRpt\Evidence;

use App\Domain\EmailSecurity\Checks\TlsRpt\Discovery\TlsRptDiscoveryResult;
use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptProtocolStatus;
use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptRiskStatus;
use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptStates;
use App\Domain\EmailSecurity\Checks\TlsRpt\Validation\TlsRptDestinationValidationResult;
use App\Domain\EmailSecurity\Checks\TlsRpt\Validation\TlsRptRecordValidationResult;

final class TlsRptStatusDeriver
{
    /**
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     * @return array{protocol_status: string, risk_status: string, state: string, summary: string, evaluation_completeness: string}
     */
    public function derive(
        TlsRptDiscoveryResult $discovery,
        ?TlsRptRecordValidationResult $recordValidation,
        ?TlsRptDestinationValidationResult $destinationValidation,
        array $errors,
        array $warnings,
    ): array {
        if ($discovery->hasDnsFailure()) {
            return $this->result(
                TlsRptProtocolStatus::TEMPERROR,
                TlsRptRiskStatus::UNKNOWN,
                TlsRptStates::UNKNOWN,
                'TLS reporting could not be evaluated because of a temporary DNS failure.',
                'failed',
            );
        }

        if ($discovery->isMissing()) {
            return $this->result(
                TlsRptProtocolStatus::NONE,
                TlsRptRiskStatus::WARNING,
                TlsRptStates::MISSING,
                'No TLS-RPT policy was found.',
                'complete',
            );
        }

        if ($discovery->multipleRecords || ($recordValidation !== null && !$recordValidation->valid)) {
            return $this->result(
                TlsRptProtocolStatus::PERMERROR,
                TlsRptRiskStatus::CRITICAL,
                TlsRptStates::FAIL,
                'The TLS-RPT policy is invalid or ambiguous.',
                'complete',
            );
        }

        if ($destinationValidation === null || !$destinationValidation->configured) {
            return $this->result(
                TlsRptProtocolStatus::PERMERROR,
                TlsRptRiskStatus::CRITICAL,
                TlsRptStates::FAIL,
                'The TLS-RPT policy has no valid reporting destinations.',
                'complete',
            );
        }

        if ($destinationValidation->hasMaterialWarnings) {
            return $this->result(
                TlsRptProtocolStatus::VALID,
                TlsRptRiskStatus::WARNING,
                TlsRptStates::WARNING,
                'TLS reporting is configured, but one or more published destinations need attention.',
                'complete',
            );
        }

        return $this->result(
            TlsRptProtocolStatus::VALID,
            TlsRptRiskStatus::HEALTHY,
            TlsRptStates::PASS,
            'TLS reporting is configured.',
            'complete',
        );
    }

    /**
     * @return array{protocol_status: string, risk_status: string, state: string, summary: string, evaluation_completeness: string}
     */
    private function result(
        string $protocol,
        string $risk,
        string $state,
        string $summary,
        string $completeness,
    ): array {
        return [
            'protocol_status' => $protocol,
            'risk_status' => $risk,
            'state' => $state,
            'summary' => $summary,
            'evaluation_completeness' => $completeness,
        ];
    }
}
