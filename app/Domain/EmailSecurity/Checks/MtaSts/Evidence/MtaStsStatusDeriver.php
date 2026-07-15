<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts\Evidence;

use App\Domain\EmailSecurity\Checks\MtaSts\Discovery\MtaStsDiscoveryResult;
use App\Domain\EmailSecurity\Checks\MtaSts\Fetch\MtaStsPolicyFetchResult;
use App\Domain\EmailSecurity\Checks\MtaSts\Matching\MtaStsMxMatchResult;
use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsProtocolStatus;
use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsRiskStatus;
use App\Domain\EmailSecurity\Checks\MtaSts\MtaStsStates;
use App\Domain\EmailSecurity\Checks\MtaSts\Validation\MtaStsDnsValidationResult;
use App\Domain\EmailSecurity\Checks\MtaSts\Validation\MtaStsPolicyValidationResult;

final class MtaStsStatusDeriver
{
    /**
     * @param list<MtaStsMxMatchResult> $mxMatches
     * @param list<array<string, mixed>> $mxValidation
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     * @return array{protocol_status: string, risk_status: string, state: string, summary: string, evaluation_completeness: string}
     */
    public function derive(
        MtaStsDiscoveryResult $discovery,
        ?MtaStsDnsValidationResult $dnsValidation,
        ?MtaStsPolicyFetchResult $policyFetch,
        ?array $policyHostTls,
        ?MtaStsPolicyValidationResult $policyValidation,
        array $mxMatches,
        array $mxValidation,
        array $errors,
        array $warnings,
    ): array {
        if ($discovery->hasDnsFailure()) {
            return $this->result(
                MtaStsProtocolStatus::TEMPERROR,
                MtaStsRiskStatus::UNKNOWN,
                MtaStsStates::UNKNOWN,
                'MTA-STS DNS lookup could not be completed reliably.',
                'failed',
            );
        }

        if ($discovery->isMissing()) {
            return $this->result(
                MtaStsProtocolStatus::NONE,
                MtaStsRiskStatus::WARNING,
                MtaStsStates::MISSING,
                'No MTA-STS DNS indicator was found.',
                'complete',
            );
        }

        if ($discovery->multipleRecords || ($dnsValidation !== null && !$dnsValidation->valid)) {
            return $this->result(
                MtaStsProtocolStatus::PERMERROR,
                MtaStsRiskStatus::CRITICAL,
                MtaStsStates::FAIL,
                'The MTA-STS DNS indicator is invalid or ambiguous.',
                'complete',
            );
        }

        if ($policyFetch === null || !$policyFetch->isSuccess()) {
            $isTemporary = $policyFetch !== null && in_array($policyFetch->status, [
                MtaStsPolicyFetchResult::STATUS_CONNECTION_TIMEOUT,
                MtaStsPolicyFetchResult::STATUS_TLS_HANDSHAKE_FAILURE,
                MtaStsPolicyFetchResult::STATUS_DNS_FAILURE,
            ], true);

            return $this->result(
                $isTemporary ? MtaStsProtocolStatus::TEMPERROR : MtaStsProtocolStatus::PERMERROR,
                $isTemporary ? MtaStsRiskStatus::UNKNOWN : MtaStsRiskStatus::CRITICAL,
                $isTemporary ? MtaStsStates::UNKNOWN : MtaStsStates::FAIL,
                $isTemporary
                    ? 'MTA-STS policy fetch could not be completed reliably.'
                    : 'The MTA-STS policy file is unavailable at the required HTTPS endpoint.',
                $isTemporary ? 'partial' : 'complete',
            );
        }

        if ($policyHostTls !== null && ($policyHostTls['valid'] ?? true) === false) {
            return $this->result(
                MtaStsProtocolStatus::PERMERROR,
                MtaStsRiskStatus::CRITICAL,
                MtaStsStates::FAIL,
                'The MTA-STS policy HTTPS endpoint presented an invalid certificate.',
                'complete',
            );
        }

        if ($policyValidation === null || !$policyValidation->valid) {
            return $this->result(
                MtaStsProtocolStatus::PERMERROR,
                MtaStsRiskStatus::CRITICAL,
                MtaStsStates::FAIL,
                'The published MTA-STS policy is invalid.',
                'complete',
            );
        }

        $mode = $policyValidation->mode;
        $unmatched = array_filter($mxMatches, fn (MtaStsMxMatchResult $m) => !$m->matchesPolicy);
        $timeouts = array_filter($mxValidation, fn (array $mx) => ($mx['smtp_tls']['inspection_status'] ?? '') === 'timeout');

        if ($mode === 'none') {
            return $this->result(
                MtaStsProtocolStatus::VALID,
                MtaStsRiskStatus::WARNING,
                MtaStsStates::WARNING,
                'MTA-STS is published in removal mode (mode: none).',
                'complete',
            );
        }

        if ($mode === 'enforce' && $unmatched !== []) {
            return $this->result(
                MtaStsProtocolStatus::VALID,
                MtaStsRiskStatus::CRITICAL,
                MtaStsStates::FAIL,
                'Current MX hosts do not match the published MTA-STS enforcement policy.',
                'complete',
            );
        }

        if ($timeouts !== [] && count($timeouts) < count($mxValidation)) {
            return $this->result(
                MtaStsProtocolStatus::PARTIALLY_EVALUATED,
                MtaStsRiskStatus::UNKNOWN,
                MtaStsStates::WARNING,
                'MTA-STS was partially evaluated because one or more MX hosts could not be tested.',
                'partial',
            );
        }

        if ($timeouts !== [] && count($timeouts) === count($mxValidation) && $mxValidation !== []) {
            return $this->result(
                MtaStsProtocolStatus::TEMPERROR,
                MtaStsRiskStatus::UNKNOWN,
                MtaStsStates::UNKNOWN,
                'MXScan could not complete TLS tests for the current MX hosts.',
                'failed',
            );
        }

        if ($mode === 'testing') {
            return $this->result(
                MtaStsProtocolStatus::VALID,
                MtaStsRiskStatus::WARNING,
                MtaStsStates::WARNING,
                'This policy is in testing mode.',
                'complete',
            );
        }

        return $this->result(
            MtaStsProtocolStatus::VALID,
            MtaStsRiskStatus::HEALTHY,
            MtaStsStates::PASS,
            'MTA-STS enforcement is configured for the current MX hosts.',
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
