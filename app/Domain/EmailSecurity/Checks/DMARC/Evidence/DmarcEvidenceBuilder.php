<?php

namespace App\Domain\EmailSecurity\Checks\DMARC\Evidence;

use App\Domain\EmailSecurity\Checks\DMARC\DmarcNativeResult;
use App\Domain\EmailSecurity\Checks\DMARC\DmarcProtocolStatus;
use App\Domain\EmailSecurity\Checks\DMARC\DmarcRiskStatus;
use App\Domain\EmailSecurity\Checks\DMARC\DmarcStates;
use App\Domain\EmailSecurity\Checks\DMARC\Evaluation\DmarcExternalDestinationValidator;
use App\Domain\EmailSecurity\Checks\DMARC\Evaluation\DmarcPolicyEvaluator;
use App\Domain\EmailSecurity\Checks\DMARC\Evaluation\DmarcReportingEvaluator;
use App\Domain\EmailSecurity\Checks\DMARC\Reporting\DmarcMxscanRuaExpectations;
use App\Domain\EmailSecurity\Checks\DMARC\Validation\DmarcValidationResult;

final class DmarcEvidenceBuilder
{
    public function __construct(
        private DmarcPolicyEvaluator $policyEvaluator,
        private DmarcReportingEvaluator $reportingEvaluator,
        private DmarcExternalDestinationValidator $externalValidator,
        private DmarcStatusDeriver $statusDeriver,
        private DmarcMxscanRuaExpectations $mxscanExpectations,
    ) {
    }

    /**
     * @param array<string, mixed> $discoveryMeta
     */
    public function build(
        array $discoveryMeta,
        ?DmarcValidationResult $validation,
        ?string $expectedMxscanRua = null,
    ): DmarcNativeResult {
        $queriedDomain = (string) ($discoveryMeta['queried_domain'] ?? '');
        $policyDiscovery = $discoveryMeta['policy_discovery'] ?? $discoveryMeta['exact_discovery'] ?? null;

        if (($discoveryMeta['exact_discovery'] ?? null)?->multipleRecords ?? false) {
            return $this->permErrorResult($discoveryMeta, 'Multiple DMARC records were found.');
        }

        $policyDiscovery = $discoveryMeta['policy_discovery'] ?? null;

        if ($policyDiscovery === null || $policyDiscovery->record === null) {
            if ($discoveryMeta['partially_evaluated'] ?? false) {
                return $this->temperrorResult($discoveryMeta, 'DMARC policy discovery was only partially evaluated due to DNS errors.');
            }

            return $this->missingResult($discoveryMeta);
        }

        if ($validation === null) {
            return $this->permErrorResult($discoveryMeta, 'DMARC validation failed.');
        }

        if ($validation->isPermError()) {
            return $this->permErrorResult($discoveryMeta, $validation->errors[0]['message'] ?? 'Invalid DMARC record.', $validation);
        }

        $parsed = $validation->parsed;
        $policy = $this->policyEvaluator->evaluate($queriedDomain, $parsed, $discoveryMeta);
        $alignment = $this->policyEvaluator->alignment($parsed);
        $aggregate = $this->reportingEvaluator->evaluateAggregate($parsed);
        $failure = $this->reportingEvaluator->evaluateFailure($parsed);

        $policyDomain = (string) ($discoveryMeta['policy_domain'] ?? $queriedDomain);
        $orgDomain = (string) ($discoveryMeta['organizational_domain'] ?? $policyDomain);
        $external = $this->externalValidator->validateAggregateDestinations(
            $aggregate['destinations'],
            $policyDomain,
            $orgDomain,
        );
        $aggregate['destinations'] = $external['destinations'];
        $aggregate['mxscan_expectation'] = $this->mxscanExpectations->evaluate($expectedMxscanRua, $aggregate['destinations']);

        $status = $this->statusDeriver->derive(DmarcProtocolStatus::VALID, $policy, $aggregate);
        $summary = $this->summary($policy, $aggregate);

        return new DmarcNativeResult(
            state: $status['state'],
            protocolStatus: DmarcProtocolStatus::VALID,
            riskStatus: $status['risk_status'],
            summary: $summary,
            rawRecord: $parsed->rawRecord,
            recordDomain: $policyDiscovery->hostname,
            policyDomain: $policyDomain,
            policySource: (string) ($discoveryMeta['policy_source'] ?? 'exact'),
            organizationalDomain: $discoveryMeta['organizational_domain'] ?? null,
            discovery: $this->sanitizeDiscovery($discoveryMeta),
            policy: $policy,
            alignment: $alignment,
            aggregateReporting: $aggregate,
            failureReporting: $failure,
            externalAuthorization: [
                'destinations_checked' => count($external['destinations']),
                'unauthorized_count' => $external['unauthorized_count'],
            ],
            errors: $validation->errors,
            warnings: $validation->warnings,
            resolverDiagnostics: $policyDiscovery->resolverDiagnostics,
        );
    }

    /**
     * @param array<string, mixed> $discoveryMeta
     */
    private function missingResult(array $discoveryMeta): DmarcNativeResult
    {
        return new DmarcNativeResult(
            state: DmarcStates::MISSING,
            protocolStatus: DmarcProtocolStatus::NONE,
            riskStatus: DmarcRiskStatus::CRITICAL,
            summary: 'No DMARC policy record was discovered.',
            rawRecord: null,
            recordDomain: null,
            policyDomain: null,
            policySource: 'none',
            organizationalDomain: null,
            discovery: $this->sanitizeDiscovery($discoveryMeta),
            policy: [],
            alignment: ['dkim' => 'relaxed', 'spf' => 'relaxed'],
            aggregateReporting: ['configured' => false, 'destinations' => []],
            failureReporting: ['configured' => false, 'destinations' => []],
            externalAuthorization: ['destinations_checked' => 0, 'unauthorized_count' => 0],
            errors: [],
            warnings: [],
            resolverDiagnostics: [],
        );
    }

    /**
     * @param array<string, mixed> $discoveryMeta
     */
    private function permErrorResult(array $discoveryMeta, string $summary, ?DmarcValidationResult $validation = null): DmarcNativeResult
    {
        return new DmarcNativeResult(
            state: DmarcStates::FAIL,
            protocolStatus: DmarcProtocolStatus::PERMERROR,
            riskStatus: DmarcRiskStatus::CRITICAL,
            summary: $summary,
            rawRecord: $validation?->parsed->rawRecord,
            recordDomain: $discoveryMeta['policy_discovery']?->hostname ?? $discoveryMeta['exact_discovery']?->hostname,
            policyDomain: $discoveryMeta['policy_domain'] ?? null,
            policySource: (string) ($discoveryMeta['policy_source'] ?? 'none'),
            organizationalDomain: $discoveryMeta['organizational_domain'] ?? null,
            discovery: $this->sanitizeDiscovery($discoveryMeta),
            policy: [],
            alignment: ['dkim' => 'relaxed', 'spf' => 'relaxed'],
            aggregateReporting: ['configured' => false, 'destinations' => []],
            failureReporting: ['configured' => false, 'destinations' => []],
            externalAuthorization: ['destinations_checked' => 0, 'unauthorized_count' => 0],
            errors: $validation?->errors ?? [[
                'code' => 'MULTIPLE_DMARC_RECORDS',
                'message' => $summary,
            ]],
            warnings: $validation?->warnings ?? [],
            resolverDiagnostics: [],
        );
    }

    /**
     * @param array<string, mixed> $discoveryMeta
     */
    private function temperrorResult(array $discoveryMeta, string $summary): DmarcNativeResult
    {
        return new DmarcNativeResult(
            state: DmarcStates::UNKNOWN,
            protocolStatus: DmarcProtocolStatus::PARTIALLY_EVALUATED,
            riskStatus: DmarcRiskStatus::UNKNOWN,
            summary: $summary,
            rawRecord: null,
            recordDomain: null,
            policyDomain: null,
            policySource: 'none',
            organizationalDomain: null,
            discovery: $this->sanitizeDiscovery($discoveryMeta),
            policy: [],
            alignment: ['dkim' => 'relaxed', 'spf' => 'relaxed'],
            aggregateReporting: ['configured' => false, 'destinations' => []],
            failureReporting: ['configured' => false, 'destinations' => []],
            externalAuthorization: ['destinations_checked' => 0, 'unauthorized_count' => 0],
            errors: [],
            warnings: [],
            resolverDiagnostics: [],
        );
    }

    /**
     * @param array<string, mixed> $policy
     * @param array<string, mixed> $aggregate
     */
    private function summary(array $policy, array $aggregate): string
    {
        $enforcement = $policy['enforcement'] ?? 'unknown';

        return match ($enforcement) {
            'reject' => 'DMARC enforcement is enabled with a reject policy.',
            'quarantine' => 'DMARC enforcement is enabled with a quarantine policy.',
            'partial_enforcement' => 'DMARC enforcement is partially enabled.',
            'monitoring' => 'DMARC is published in monitoring mode.',
            default => 'DMARC configuration is valid.',
        };
    }

    /**
     * @param array<string, mixed> $discoveryMeta
     * @return array<string, mixed>
     */
    private function sanitizeDiscovery(array $discoveryMeta): array
    {
        return [
            'queried_domain' => $discoveryMeta['queried_domain'] ?? null,
            'policy_domain' => $discoveryMeta['policy_domain'] ?? null,
            'policy_source' => $discoveryMeta['policy_source'] ?? null,
            'organizational_domain' => $discoveryMeta['organizational_domain'] ?? null,
            'public_suffix_domain' => $discoveryMeta['public_suffix_domain'] ?? null,
            'lookup_path' => $discoveryMeta['lookup_path'] ?? [],
            'queries_used' => $discoveryMeta['queries_used'] ?? 0,
            'discovery_method' => $discoveryMeta['discovery_method'] ?? 'treewalk',
        ];
    }
}
