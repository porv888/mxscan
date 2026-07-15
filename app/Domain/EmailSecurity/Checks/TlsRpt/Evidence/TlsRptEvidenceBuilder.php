<?php

namespace App\Domain\EmailSecurity\Checks\TlsRpt\Evidence;

use App\Domain\EmailSecurity\Checks\TlsRpt\Discovery\TlsRptDiscoveryResult;
use App\Domain\EmailSecurity\Checks\TlsRpt\Discovery\TlsRptRecordDiscovery;
use App\Domain\EmailSecurity\Checks\TlsRpt\Parsing\TlsRptRecordParser;
use App\Domain\EmailSecurity\Checks\TlsRpt\Reporting\TlsRptMxscanRuaExpectations;
use App\Domain\EmailSecurity\Checks\TlsRpt\TlsRptNativeResult;
use App\Domain\EmailSecurity\Checks\TlsRpt\Validation\TlsRptDestinationValidator;
use App\Domain\EmailSecurity\Checks\TlsRpt\Validation\TlsRptRecordValidator;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;

final class TlsRptEvidenceBuilder
{
    public function __construct(
        private TlsRptRecordDiscovery $discovery,
        private TlsRptRecordValidator $recordValidator,
        private TlsRptRecordParser $recordParser,
        private TlsRptDestinationValidator $destinationValidator,
        private TlsRptMxscanRuaExpectations $mxscanExpectations,
        private TlsRptStatusDeriver $statusDeriver,
    ) {
    }

    public function build(string $domain, ?DnsCollectionResultDTO $dns, ?string $expectedRua = null): TlsRptNativeResult
    {
        $domain = strtolower(rtrim(trim($domain), '.'));
        $discovery = $this->discovery->discover($domain, $dns);
        $errors = [];
        $warnings = [];
        $resolverDiagnostics = $discovery->resolverDiagnostics;

        if ($discovery->hasDnsFailure()) {
            $status = $this->statusDeriver->derive($discovery, null, null, $errors, $warnings);

            return $this->nativeFromStatus($domain, $discovery, $status, [], [], $errors, $warnings, $resolverDiagnostics, false);
        }

        if ($discovery->isMissing()) {
            $status = $this->statusDeriver->derive($discovery, null, null, $errors, $warnings);

            return $this->nativeFromStatus($domain, $discovery, $status, [], [], $errors, $warnings, $resolverDiagnostics, false);
        }

        $recordValidation = $this->recordValidator->validateDiscovery($discovery);
        $errors = array_merge($errors, $recordValidation->errors);
        $warnings = array_merge($warnings, $recordValidation->warnings);

        $parsed = $discovery->record !== null ? $this->recordParser->parse($discovery->record) : null;
        $recordPayload = $this->recordPayload($discovery, $parsed);

        if (!$recordValidation->valid) {
            $status = $this->statusDeriver->derive($discovery, $recordValidation, null, $errors, $warnings);

            return $this->nativeFromStatus(
                $domain,
                $discovery,
                $status,
                $recordPayload,
                $this->emptyReporting($expectedRua),
                $errors,
                $warnings,
                $resolverDiagnostics,
                false,
            );
        }

        $destinationValidation = $this->destinationValidator->validate($recordValidation->ruaValue);
        $errors = array_merge($errors, $destinationValidation->errors);
        $warnings = array_merge($warnings, $destinationValidation->warnings);

        $reporting = $this->reportingPayload($destinationValidation, $expectedRua);
        $hasMaterialWarnings = $recordValidation->warnings !== []
            || $destinationValidation->hasMaterialWarnings;

        $status = $this->statusDeriver->derive(
            $discovery,
            $recordValidation,
            $destinationValidation,
            $errors,
            $warnings,
        );

        return $this->nativeFromStatus(
            $domain,
            $discovery,
            $status,
            $recordPayload,
            $reporting,
            $errors,
            $warnings,
            $resolverDiagnostics,
            $hasMaterialWarnings,
        );
    }

    /**
     * @param array{protocol_status: string, risk_status: string, state: string, summary: string, evaluation_completeness: string} $status
     * @param array<string, mixed> $recordPayload
     * @param array<string, mixed> $reporting
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     * @param list<array<string, mixed>> $resolverDiagnostics
     */
    private function nativeFromStatus(
        string $domain,
        TlsRptDiscoveryResult $discovery,
        array $status,
        array $recordPayload,
        array $reporting,
        array $errors,
        array $warnings,
        array $resolverDiagnostics,
        bool $hasMaterialWarnings,
    ): TlsRptNativeResult {
        return new TlsRptNativeResult(
            state: $status['state'],
            protocolStatus: $status['protocol_status'],
            riskStatus: $status['risk_status'],
            summary: $status['summary'],
            domain: $domain,
            recordHostname: $discovery->recordHostname,
            evaluationCompleteness: $status['evaluation_completeness'],
            rawRecord: $discovery->record,
            record: $recordPayload,
            reporting: $reporting,
            errors: $errors,
            warnings: $warnings,
            resolverDiagnostics: $resolverDiagnostics,
            hasMaterialWarnings: $hasMaterialWarnings,
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function recordPayload(TlsRptDiscoveryResult $discovery, $parsed): array
    {
        return [
            'raw' => $discovery->record,
            'normalized' => $parsed?->normalizedRecord ?? $discovery->record,
            'ttl' => $discovery->ttl,
            'alias_path' => $discovery->aliasPath,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function reportingPayload($destinationValidation, ?string $expectedRua): array
    {
        $destinations = $destinationValidation->destinationPayload();
        $expected = $this->mxscanExpectations->evaluate(
            $this->mxscanExpectations->resolveExpected($expectedRua),
            $destinations,
        );

        return [
            'configured' => $destinationValidation->configured,
            'destinations_total' => count($destinations),
            'valid_destinations' => $destinationValidation->validCount,
            'invalid_destinations' => $destinationValidation->invalidCount,
            'destinations' => $destinations,
            'expected_destination' => $expected,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function emptyReporting(?string $expectedRua): array
    {
        return [
            'configured' => false,
            'destinations_total' => 0,
            'valid_destinations' => 0,
            'invalid_destinations' => 0,
            'destinations' => [],
            'expected_destination' => $this->mxscanExpectations->evaluate(
                $this->mxscanExpectations->resolveExpected($expectedRua),
                [],
            ),
        ];
    }
}
