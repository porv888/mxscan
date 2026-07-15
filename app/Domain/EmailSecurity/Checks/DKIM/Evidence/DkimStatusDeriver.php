<?php

namespace App\Domain\EmailSecurity\Checks\DKIM\Evidence;

use App\Domain\EmailSecurity\Checks\DKIM\DkimProtocolStatus;
use App\Domain\EmailSecurity\Checks\DKIM\DkimRiskStatus;
use App\Domain\EmailSecurity\Checks\DKIM\DkimStates;
use App\Domain\EmailSecurity\Checks\DKIM\Validation\DkimValidationResult;

final class DkimStatusDeriver
{
    /**
     * @return array{record_status: string, protocol_status: string, risk_status: string, state: string}
     */
    public function deriveSelector(DkimValidationResult $validation): array
    {
        if ($validation->recordStatus === 'revoked') {
            return [
                'record_status' => 'revoked',
                'protocol_status' => DkimProtocolStatus::REVOKED,
                'risk_status' => DkimRiskStatus::CRITICAL,
                'state' => DkimStates::FAIL,
            ];
        }

        if ($validation->recordStatus === 'ambiguous') {
            return [
                'record_status' => 'ambiguous',
                'protocol_status' => DkimProtocolStatus::PERMERROR,
                'risk_status' => DkimRiskStatus::CRITICAL,
                'state' => DkimStates::FAIL,
            ];
        }

        if ($validation->recordStatus === 'unsupported') {
            return [
                'record_status' => 'unsupported',
                'protocol_status' => DkimProtocolStatus::PARTIALLY_EVALUATED,
                'risk_status' => DkimRiskStatus::UNKNOWN,
                'state' => DkimStates::UNKNOWN,
            ];
        }

        if (!$validation->isValid()) {
            return [
                'record_status' => 'invalid',
                'protocol_status' => DkimProtocolStatus::PERMERROR,
                'risk_status' => DkimRiskStatus::CRITICAL,
                'state' => DkimStates::FAIL,
            ];
        }

        $bits = $validation->keyInfo['bits'] ?? null;
        $type = $validation->keyInfo['type'] ?? null;

        if ($type === 'rsa' && $bits !== null && $bits < 2048) {
            return [
                'record_status' => 'valid',
                'protocol_status' => DkimProtocolStatus::VALID,
                'risk_status' => DkimRiskStatus::WARNING,
                'state' => DkimStates::WARNING,
            ];
        }

        if ($validation->testingMode) {
            return [
                'record_status' => 'valid',
                'protocol_status' => DkimProtocolStatus::VALID,
                'risk_status' => DkimRiskStatus::WARNING,
                'state' => DkimStates::WARNING,
            ];
        }

        return [
            'record_status' => 'valid',
            'protocol_status' => DkimProtocolStatus::VALID,
            'risk_status' => DkimRiskStatus::HEALTHY,
            'state' => DkimStates::PASS,
        ];
    }

    /**
     * @param list<array<string, mixed>> $selectorResults
     * @param array<string, mixed> $coverage
     * @return array{protocol_status: string, risk_status: string, state: string, summary: string}
     */
    public function deriveDomain(array $selectorResults, array $coverage): array
    {
        if (($coverage['selectors_available'] ?? false) === false) {
            return [
                'protocol_status' => DkimProtocolStatus::PARTIALLY_EVALUATED,
                'risk_status' => DkimRiskStatus::UNKNOWN,
                'state' => DkimStates::UNKNOWN,
                'summary' => 'DKIM signing cannot be confirmed without inspecting a signed message or supplying a selector.',
            ];
        }

        $validSelectors = array_values(array_filter(
            $selectorResults,
            fn (array $row) => ($row['record_status'] ?? '') === 'valid',
        ));
        if ($validSelectors !== []) {
            $first = reset($validSelectors);
            $selector = $first['selector'] ?? 'a tested selector';
            $validStates = array_column($validSelectors, 'state');
            $validRisks = array_column($validSelectors, 'risk_status');

            return [
                'protocol_status' => DkimProtocolStatus::VALID,
                'risk_status' => $this->worstRisk($validRisks),
                'state' => $this->bestState($validStates),
                'summary' => "A valid DKIM key is published for selector {$selector}.",
            ];
        }

        $hasTemperror = false;
        $hasPermerror = false;
        foreach ($selectorResults as $row) {
            if (($row['protocol_status'] ?? '') === DkimProtocolStatus::TEMPERROR) {
                $hasTemperror = true;
            }
            if (in_array($row['protocol_status'] ?? '', [DkimProtocolStatus::PERMERROR, DkimProtocolStatus::REVOKED], true)) {
                $hasPermerror = true;
            }
        }

        if ($hasTemperror) {
            return [
                'protocol_status' => DkimProtocolStatus::TEMPERROR,
                'risk_status' => DkimRiskStatus::UNKNOWN,
                'state' => DkimStates::UNKNOWN,
                'summary' => 'DNS errors prevented full DKIM key evaluation for tested selectors.',
            ];
        }

        if ($hasPermerror && ($coverage['coverage_type'] ?? '') !== 'catalog_only') {
            return [
                'protocol_status' => DkimProtocolStatus::PERMERROR,
                'risk_status' => DkimRiskStatus::CRITICAL,
                'state' => DkimStates::FAIL,
                'summary' => 'The tested selector contains an invalid DKIM key record.',
            ];
        }

        $state = ($coverage['coverage_type'] ?? '') === 'catalog_only'
            ? DkimStates::MISSING
            : DkimStates::MISSING;

        return [
            'protocol_status' => DkimProtocolStatus::NONE,
            'risk_status' => DkimRiskStatus::CRITICAL,
            'state' => $state,
            'summary' => 'No DKIM key was found for the tested selectors.',
        ];
    }

    /**
     * @param list<string> $statuses
     */
    private function worstRisk(array $statuses): string
    {
        if (in_array(DkimRiskStatus::CRITICAL, $statuses, true)) {
            return DkimRiskStatus::CRITICAL;
        }
        if (in_array(DkimRiskStatus::WARNING, $statuses, true)) {
            return DkimRiskStatus::WARNING;
        }
        if (in_array(DkimRiskStatus::UNKNOWN, $statuses, true)) {
            return DkimRiskStatus::UNKNOWN;
        }

        return DkimRiskStatus::HEALTHY;
    }

    /**
     * @param list<string> $states
     */
    private function worstState(array $states): string
    {
        foreach ([DkimStates::FAIL, DkimStates::UNKNOWN, DkimStates::WARNING, DkimStates::MISSING, DkimStates::PASS] as $state) {
            if (in_array($state, $states, true)) {
                return $state;
            }
        }

        return DkimStates::UNKNOWN;
    }

    /**
     * Prefer the strongest positive state among selectors with valid keys.
     *
     * @param list<string> $states
     */
    private function bestState(array $states): string
    {
        foreach ([DkimStates::PASS, DkimStates::WARNING, DkimStates::UNKNOWN, DkimStates::MISSING, DkimStates::FAIL] as $state) {
            if (in_array($state, $states, true)) {
                return $state;
            }
        }

        return DkimStates::UNKNOWN;
    }
}
