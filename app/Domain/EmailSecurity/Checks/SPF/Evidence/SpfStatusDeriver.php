<?php

namespace App\Domain\EmailSecurity\Checks\SPF\Evidence;

use App\Domain\EmailSecurity\Checks\SPF\Discovery\SpfDiscoveryResult;
use App\Domain\EmailSecurity\Checks\SPF\Evaluation\SpfEvaluationResult;
use App\Domain\EmailSecurity\Checks\SPF\Evaluation\SpfLookupCounter;
use App\Domain\EmailSecurity\Checks\SPF\Macros\SpfMacroAssessment;
use App\Domain\EmailSecurity\Checks\SPF\SpfLookupThresholds;
use App\Domain\EmailSecurity\Checks\SPF\SpfProtocolStatus;
use App\Domain\EmailSecurity\Checks\SPF\SpfRiskStatus;
use App\Domain\EmailSecurity\Checks\SPF\SpfStates;
use App\Domain\EmailSecurity\Checks\SPF\Validation\SpfValidationResult;

final class SpfStatusDeriver
{
    public function derive(
        SpfDiscoveryResult $discovery,
        SpfValidationResult $validation,
        SpfEvaluationResult $evaluation,
        SpfLookupCounter $lookupCounter,
        ?SpfMacroAssessment $macroAssessment = null,
    ): SpfDerivedStatusDTO {
        $lookupCount = $lookupCounter->count();
        $errors = array_merge($validation->errors, $evaluation->errors);
        $warnings = array_merge($validation->warnings, $evaluation->warnings);

        if ($discovery->hasDnsFailure()) {
            return new SpfDerivedStatusDTO(
                protocolStatus: SpfProtocolStatus::TEMPERROR,
                riskStatus: SpfRiskStatus::UNKNOWN,
                state: SpfStates::UNKNOWN,
                summary: 'SPF configuration could not be fully evaluated.',
            );
        }

        if ($discovery->isMissing()) {
            return new SpfDerivedStatusDTO(
                protocolStatus: SpfProtocolStatus::NONE,
                riskStatus: SpfRiskStatus::CRITICAL,
                state: SpfStates::MISSING,
                summary: 'SPF record missing.',
            );
        }

        if ($evaluation->hasTemperror) {
            return new SpfDerivedStatusDTO(
                protocolStatus: SpfProtocolStatus::TEMPERROR,
                riskStatus: SpfRiskStatus::UNKNOWN,
                state: SpfStates::UNKNOWN,
                summary: 'SPF configuration could not be fully evaluated.',
            );
        }

        if ($discovery->multipleRecords || $this->hasPermerror($errors, $validation, $evaluation, $lookupCounter)) {
            return $this->permerrorStatus($discovery, $errors, $lookupCount);
        }

        if ($macroAssessment?->hasUnsupportedMacro) {
            $reliable = !$this->hasCode($errors, 'UNKNOWN_MECHANISM')
                && !$this->hasCode($errors, 'INVALID_VERSION');

            return new SpfDerivedStatusDTO(
                protocolStatus: SpfProtocolStatus::PARTIALLY_EVALUATED,
                riskStatus: SpfRiskStatus::UNKNOWN,
                state: $reliable ? SpfStates::WARNING : SpfStates::UNKNOWN,
                summary: 'SPF configuration could not be fully evaluated.',
            );
        }

        if ($lookupCount > SpfLookupThresholds::RFC_LIMIT || $lookupCounter->attemptedOverLimit()) {
            return new SpfDerivedStatusDTO(
                protocolStatus: SpfProtocolStatus::PERMERROR,
                riskStatus: SpfRiskStatus::CRITICAL,
                state: SpfStates::FAIL,
                summary: 'SPF lookup budget exceeded.',
            );
        }

        if ($lookupCount === SpfLookupThresholds::RFC_LIMIT) {
            return new SpfDerivedStatusDTO(
                protocolStatus: SpfProtocolStatus::VALID,
                riskStatus: SpfRiskStatus::WARNING,
                state: SpfStates::WARNING,
                summary: 'SPF configuration valid; lookup budget at limit (10/10).',
            );
        }

        if ($lookupCount >= SpfLookupThresholds::PRODUCT_WARNING_MIN || $this->hasConfigurationWarnings($warnings)) {
            return new SpfDerivedStatusDTO(
                protocolStatus: SpfProtocolStatus::VALID,
                riskStatus: SpfRiskStatus::WARNING,
                state: SpfStates::WARNING,
                summary: "SPF configuration valid; elevated lookup count ({$lookupCount}/10).",
            );
        }

        return new SpfDerivedStatusDTO(
            protocolStatus: SpfProtocolStatus::VALID,
            riskStatus: SpfRiskStatus::HEALTHY,
            state: SpfStates::PASS,
            summary: 'SPF configuration valid.',
        );
    }

    /**
     * @param list<array{code: string}> $errors
     */
    private function hasPermerror(
        array $errors,
        SpfValidationResult $validation,
        SpfEvaluationResult $evaluation,
        SpfLookupCounter $lookupCounter,
    ): bool {
        if ($validation->hasHardErrors()) {
            return true;
        }

        $permerrorCodes = [
            'PLUS_ALL',
            'UNKNOWN_MECHANISM',
            'INVALID_VERSION',
            'VOID_LOOKUP_LIMIT',
            'LOOKUP_LIMIT',
            'INCLUDE_NONE_PERMERROR',
            'REDIRECT_NONE_PERMERROR',
            'PERMERROR_DEPTH',
            'DUPLICATE_REDIRECT',
            'DUPLICATE_EXP',
            'INVALID_IPV4',
            'INVALID_IPV6',
            'INVALID_DOMAIN',
            'INVALID_A_MECHANISM',
            'INVALID_MX_MECHANISM',
        ];

        foreach ($permerrorCodes as $code) {
            if ($this->hasCode($errors, $code)) {
                return true;
            }
        }

        return $lookupCounter->attemptedOverLimit();
    }

    /**
     * @param list<array{code: string}> $errors
     */
    private function permerrorStatus(SpfDiscoveryResult $discovery, array $errors, int $lookupCount): SpfDerivedStatusDTO
    {
        if ($discovery->multipleRecords) {
            return new SpfDerivedStatusDTO(
                protocolStatus: SpfProtocolStatus::PERMERROR,
                riskStatus: SpfRiskStatus::CRITICAL,
                state: SpfStates::FAIL,
                summary: 'SPF configuration invalid (multiple records).',
            );
        }

        if ($this->hasCode($errors, 'PLUS_ALL')) {
            return new SpfDerivedStatusDTO(
                protocolStatus: SpfProtocolStatus::PERMERROR,
                riskStatus: SpfRiskStatus::CRITICAL,
                state: SpfStates::FAIL,
                summary: 'SPF policy uses a weak terminal qualifier.',
            );
        }

        if ($lookupCount > SpfLookupThresholds::RFC_LIMIT || $this->hasCode($errors, 'LOOKUP_LIMIT')) {
            return new SpfDerivedStatusDTO(
                protocolStatus: SpfProtocolStatus::PERMERROR,
                riskStatus: SpfRiskStatus::CRITICAL,
                state: SpfStates::FAIL,
                summary: 'SPF lookup budget exceeded.',
            );
        }

        return new SpfDerivedStatusDTO(
            protocolStatus: SpfProtocolStatus::PERMERROR,
            riskStatus: SpfRiskStatus::CRITICAL,
            state: SpfStates::FAIL,
            summary: 'SPF configuration invalid.',
        );
    }

    /**
     * @param list<array{code: string}> $warnings
     */
    private function hasConfigurationWarnings(array $warnings): bool
    {
        $codes = [
            'DEPRECATED_PTR',
            'WEAK_TERMINAL_POLICY',
            'MISSING_TERMINAL_ALL',
            'DEAD_CONFIGURATION_AFTER_ALL',
            'VOID_LOOKUP_WARNING',
            'UNSUPPORTED_SPF_MACRO',
        ];

        foreach ($codes as $code) {
            if ($this->hasCode($warnings, $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<array{code: string}> $items
     */
    private function hasCode(array $items, string $code): bool
    {
        foreach ($items as $item) {
            if (($item['code'] ?? '') === $code) {
                return true;
            }
        }

        return false;
    }
}
