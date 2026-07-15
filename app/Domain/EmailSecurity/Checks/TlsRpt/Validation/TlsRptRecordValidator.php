<?php

namespace App\Domain\EmailSecurity\Checks\TlsRpt\Validation;

use App\Domain\EmailSecurity\Checks\TlsRpt\Discovery\TlsRptDiscoveryResult;
use App\Domain\EmailSecurity\Checks\TlsRpt\Parsing\TlsRptParsedRecord;
use App\Domain\EmailSecurity\Checks\TlsRpt\Parsing\TlsRptRecordParser;

final class TlsRptRecordValidator
{
    public function __construct(
        private TlsRptRecordParser $parser,
    ) {
    }

    public function validateDiscovery(TlsRptDiscoveryResult $discovery): TlsRptRecordValidationResult
    {
        if ($discovery->hasDnsFailure()) {
            return new TlsRptRecordValidationResult(
                valid: false,
                errors: [[
                    'code' => 'DNS_FAILURE',
                    'message' => $discovery->dnsError ?? 'DNS lookup failed',
                ]],
            );
        }

        if ($discovery->multipleRecords) {
            return new TlsRptRecordValidationResult(
                valid: false,
                errors: [[
                    'code' => 'MULTIPLE_TLS_RPT_RECORDS',
                    'message' => 'Multiple TLS-RPT policy records were found.',
                ]],
            );
        }

        if ($discovery->record === null) {
            return new TlsRptRecordValidationResult(valid: false);
        }

        return $this->validateParsed($this->parser->parse($discovery->record));
    }

    public function validateParsed(TlsRptParsedRecord $parsed): TlsRptRecordValidationResult
    {
        $errors = $parsed->parseErrors;
        $warnings = [];

        if ($parsed->malformed) {
            $errors[] = [
                'code' => 'MALFORMED_TLS_RPT_RECORD',
                'message' => 'The TLS-RPT record contains malformed tag syntax.',
            ];
        }

        if (!$parsed->versionFirst || strtoupper($parsed->tag('v') ?? '') !== 'TLSRPTV1') {
            $errors[] = [
                'code' => 'INVALID_TLS_RPT_VERSION',
                'message' => 'The TLS-RPT record must begin with v=TLSRPTv1.',
            ];
        }

        $rua = $parsed->tag('rua');
        if ($rua === null || trim($rua) === '') {
            $errors[] = [
                'code' => 'MISSING_RUA',
                'message' => 'The TLS-RPT record requires a rua reporting destination.',
            ];
        }

        foreach ($parsed->duplicateTags as $duplicate) {
            $warnings[] = [
                'code' => 'DUPLICATE_TAG',
                'message' => 'Duplicate tag ignored: ' . $duplicate,
            ];
        }

        foreach ($parsed->unknownTags as $unknown) {
            $warnings[] = [
                'code' => 'UNKNOWN_EXTENSION',
                'message' => 'Unknown extension tag preserved: ' . $unknown,
            ];
        }

        return new TlsRptRecordValidationResult(
            valid: $errors === [],
            ruaValue: $rua,
            errors: $errors,
            warnings: $warnings,
        );
    }
}
