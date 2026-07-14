<?php

namespace Tests\Support\EmailSecurity;

use App\Domain\EmailSecurity\Checks\SPF\SpfNativeResult;
use App\Domain\EmailSecurity\Checks\SPF\SpfProtocolStatus;
use App\Domain\EmailSecurity\Checks\SPF\SpfRiskStatus;
use App\Domain\EmailSecurity\Checks\SPF\SpfStates;
use App\Domain\EmailSecurity\Checks\SPF\SpfTerminalPolicy;

final class SpfNativeResultFactory
{
    /**
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     * @param ?array{qualifier: string, mechanism: string, position?: int} $parsedTerminalPolicy
     */
    public static function make(
        string $protocolStatus = SpfProtocolStatus::VALID,
        string $riskStatus = SpfRiskStatus::HEALTHY,
        string $state = SpfStates::PASS,
        string $summary = 'SPF configuration valid.',
        ?string $rawRecord = 'v=spf1 -all',
        int $lookupCount = 0,
        string $terminalPolicy = SpfTerminalPolicy::HARD_FAIL,
        ?array $parsedTerminalPolicy = ['qualifier' => '-', 'mechanism' => 'all', 'position' => 1],
        array $errors = [],
        array $warnings = [],
        bool $multipleRecords = false,
    ): SpfNativeResult {
        return new SpfNativeResult(
            state: $state,
            protocolStatus: $protocolStatus,
            riskStatus: $riskStatus,
            summary: $summary,
            rawRecord: $rawRecord,
            normalizedRecord: $rawRecord,
            parsedTerms: [],
            parsedTerminalPolicy: $parsedTerminalPolicy,
            terminalPolicy: $terminalPolicy,
            lookupCount: $lookupCount,
            lookupLimit: 10,
            lookupsRemaining: max(0, 10 - $lookupCount),
            voidLookupCount: 0,
            lookupPaths: [],
            recursiveDependencies: [],
            resolvedIps: [],
            flattenedRecord: $rawRecord,
            errors: $errors,
            warnings: $warnings,
            resolverDiagnostics: [],
            discovery: [
                'source' => 'dns_collection',
                'domain' => 'example.test',
                'txt_evidence' => [],
                'multiple_records' => $multipleRecords,
                'dns_failure' => false,
            ],
        );
    }
}
