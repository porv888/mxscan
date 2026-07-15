<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts\Validation;

use App\Domain\EmailSecurity\Checks\MtaSts\Discovery\MtaStsDiscoveryResult;
use App\Domain\EmailSecurity\Checks\MtaSts\Parsing\MtaStsDnsRecordParser;
use App\Domain\EmailSecurity\Checks\MtaSts\Parsing\MtaStsParsedIndicator;

final class MtaStsDnsRecordValidator
{
    public function __construct(
        private MtaStsDnsRecordParser $parser,
    ) {
    }

    public function validate(MtaStsDiscoveryResult $discovery): MtaStsDnsValidationResult
    {
        if ($discovery->hasDnsFailure()) {
            return new MtaStsDnsValidationResult(
                valid: false,
                errors: [[
                    'code' => 'DNS_FAILURE',
                    'message' => $discovery->dnsError ?? 'DNS lookup failed',
                ]],
            );
        }

        if ($discovery->multipleRecords) {
            return new MtaStsDnsValidationResult(
                valid: false,
                errors: [[
                    'code' => 'MULTIPLE_MTA_STS_INDICATORS',
                    'message' => 'Multiple MTA-STS indicator records were found.',
                ]],
            );
        }

        if ($discovery->record === null) {
            return new MtaStsDnsValidationResult(valid: false);
        }

        $parsed = $this->parser->parse($discovery->record);

        return $this->validateParsed($parsed);
    }

    public function validateParsed(MtaStsParsedIndicator $parsed): MtaStsDnsValidationResult
    {
        $errors = [];
        $warnings = [];

        if ($parsed->malformed) {
            $errors[] = [
                'code' => 'MALFORMED_INDICATOR',
                'message' => 'The MTA-STS DNS indicator contains malformed key/value syntax.',
            ];
        }

        if (!$parsed->versionFirst || ($parsed->version ?? '') !== 'STSv1') {
            $errors[] = [
                'code' => 'INVALID_INDICATOR_VERSION',
                'message' => 'The MTA-STS indicator must begin with v=STSv1.',
            ];
        }

        if (!$this->parser->isValidId($parsed->id)) {
            $errors[] = [
                'code' => 'MISSING_OR_INVALID_ID',
                'message' => 'The MTA-STS indicator requires a valid id field.',
            ];
        }

        foreach ($parsed->duplicateFields as $duplicate) {
            $warnings[] = [
                'code' => 'DUPLICATE_INDICATOR_FIELD',
                'message' => 'Duplicate indicator field ignored: ' . $duplicate['field'],
            ];
        }

        return new MtaStsDnsValidationResult(
            valid: $errors === [],
            policyId: $parsed->id,
            errors: $errors,
            warnings: $warnings,
        );
    }
}
