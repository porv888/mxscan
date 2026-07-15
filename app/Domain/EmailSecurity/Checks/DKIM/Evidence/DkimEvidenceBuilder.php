<?php

namespace App\Domain\EmailSecurity\Checks\DKIM\Evidence;

use App\Domain\EmailSecurity\Checks\DKIM\DkimNativeResult;
use App\Domain\EmailSecurity\Checks\DKIM\DkimProtocolStatus;
use App\Domain\EmailSecurity\Checks\DKIM\DkimRiskStatus;
use App\Domain\EmailSecurity\Checks\DKIM\DkimStates;
use App\Domain\EmailSecurity\Checks\DKIM\Discovery\DkimDiscoveryResult;
use App\Domain\EmailSecurity\Checks\DKIM\Evaluation\DkimDnsQueryResult;
use App\Domain\EmailSecurity\Checks\DKIM\Parsing\DkimRecordParser;
use App\Domain\EmailSecurity\Checks\DKIM\Validation\DkimRecordValidator;

final class DkimEvidenceBuilder
{
    public function __construct(
        private DkimRecordParser $parser,
        private DkimRecordValidator $validator,
        private DkimStatusDeriver $statusDeriver,
    ) {
    }

    /**
     * @param list<DkimDiscoveryResult> $discoveries
     * @param array<string, mixed> $coverage
     */
    public function build(string $signingDomain, array $discoveries, array $coverage): DkimNativeResult
    {
        if ($discoveries === []) {
            return new DkimNativeResult(
                state: DkimStates::UNKNOWN,
                protocolStatus: DkimProtocolStatus::PARTIALLY_EVALUATED,
                riskStatus: DkimRiskStatus::UNKNOWN,
                summary: 'DKIM signing cannot be confirmed without inspecting a signed message or supplying a selector.',
                signingDomain: $signingDomain,
                signingVerified: false,
                selectors: [],
                selectorCoverage: $coverage,
                errors: [],
                warnings: [[
                    'code' => 'NO_SELECTOR',
                    'message' => 'No selector was available to test.',
                ]],
                resolverDiagnostics: [],
            );
        }

        $selectorRows = [];
        $errors = [];
        $warnings = [];
        $diagnostics = [];

        foreach ($discoveries as $discovery) {
            $diagnostics = array_merge($diagnostics, $discovery->resolverDiagnostics);

            if ($discovery->hasDnsFailure()) {
                $selectorRows[] = $this->selectorRow(
                    $discovery,
                    [
                        'record_status' => 'dns_failure',
                        'protocol_status' => DkimProtocolStatus::TEMPERROR,
                        'risk_status' => DkimRiskStatus::UNKNOWN,
                        'state' => DkimStates::UNKNOWN,
                    ],
                    [],
                    [['code' => 'DNS_FAILURE', 'message' => $discovery->dnsError ?? 'DNS lookup failed.']],
                );
                continue;
            }

            if ($discovery->multipleRecords) {
                $parsed = $this->parser->parse($discovery->rawRecord ?? '');
                $validation = $this->validator->validateMultiple($parsed);
                $status = $this->statusDeriver->deriveSelector($validation);
                $selectorRows[] = $this->selectorRow($discovery, $status, $validation->errors, $validation->warnings);
                $errors = array_merge($errors, $validation->errors);
                continue;
            }

            if ($discovery->isEmpty()) {
                $selectorRows[] = $this->selectorRow(
                    $discovery,
                    [
                        'record_status' => 'none',
                        'protocol_status' => DkimProtocolStatus::NONE,
                        'risk_status' => DkimRiskStatus::CRITICAL,
                        'state' => DkimStates::MISSING,
                    ],
                    [],
                    [],
                );
                continue;
            }

            $parsed = $this->parser->parse($discovery->rawRecord ?? '');
            $validation = $this->validator->validate($parsed);
            $status = $this->statusDeriver->deriveSelector($validation);
            $selectorRows[] = $this->selectorRow(
                $discovery,
                $status,
                $validation->errors,
                $validation->warnings,
                $validation->keyInfo,
                $validation->testingMode,
                $validation->isRevoked(),
            );
            $errors = array_merge($errors, $validation->errors);
            $warnings = array_merge($warnings, $validation->warnings);
        }

        $domainStatus = $this->statusDeriver->deriveDomain($selectorRows, $coverage);

        return new DkimNativeResult(
            state: $domainStatus['state'],
            protocolStatus: $domainStatus['protocol_status'],
            riskStatus: $domainStatus['risk_status'],
            summary: $domainStatus['summary'],
            signingDomain: $signingDomain,
            signingVerified: false,
            selectors: $selectorRows,
            selectorCoverage: $coverage,
            errors: $this->uniqueMessages($errors),
            warnings: $this->uniqueMessages($warnings),
            resolverDiagnostics: $diagnostics,
        );
    }

    /**
     * @param array<string, mixed> $status
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     * @param array<string, mixed> $keyInfo
     * @return array<string, mixed>
     */
    private function selectorRow(
        DkimDiscoveryResult $discovery,
        array $status,
        array $errors,
        array $warnings,
        array $keyInfo = [],
        bool $testing = false,
        bool $revoked = false,
    ): array {
        return [
            'selector' => $discovery->candidate->selector,
            'source' => $discovery->candidate->source,
            'confidence' => $discovery->candidate->confidence,
            'hostname' => $discovery->candidate->hostname,
            'dns_status' => $discovery->dnsStatus,
            'record_status' => $status['record_status'],
            'protocol_status' => $status['protocol_status'],
            'risk_status' => $status['risk_status'],
            'state' => $status['state'],
            'key_type' => $keyInfo['type'] ?? null,
            'key_bits' => $keyInfo['bits'] ?? null,
            'testing' => $testing,
            'revoked' => $revoked,
            'errors' => $errors,
            'warnings' => $warnings,
        ];
    }

    /**
     * @param list<array{code: string, message: string}> $items
     * @return list<array{code: string, message: string}>
     */
    private function uniqueMessages(array $items): array
    {
        $seen = [];
        $unique = [];

        foreach ($items as $item) {
            $code = $item['code'] ?? '';
            if (isset($seen[$code])) {
                continue;
            }
            $seen[$code] = true;
            $unique[] = [
                'code' => (string) $code,
                'message' => (string) ($item['message'] ?? ''),
            ];
        }

        return $unique;
    }
}
