<?php

namespace App\Domain\EmailSecurity\Checks\TlsRpt\Validation;

use App\Domain\EmailSecurity\Checks\TlsRpt\Parsing\TlsRptDestinationParser;
use App\Domain\EmailSecurity\Checks\TlsRpt\Parsing\TlsRptParsedDestination;

final class TlsRptDestinationValidator
{
    public function __construct(
        private TlsRptDestinationParser $parser,
    ) {
    }

    public function validate(?string $ruaValue): TlsRptDestinationValidationResult
    {
        if ($ruaValue === null || trim($ruaValue) === '') {
            return new TlsRptDestinationValidationResult(
                destinations: [],
                errors: [[
                    'code' => 'MISSING_RUA',
                    'message' => 'No reporting destinations were published.',
                ]],
            );
        }

        $parsed = $this->parser->parseList($ruaValue);
        $seen = [];
        $validCount = 0;
        $invalidCount = 0;
        $hasMaterialWarnings = false;
        $warnings = [];
        $errors = [];
        $final = [];

        foreach ($parsed as $destination) {
            $normalized = $destination->normalizedUri;
            $duplicate = false;

            if ($destination->isValidSupported() && $normalized !== null) {
                if (isset($seen[$normalized])) {
                    $duplicate = true;
                    $hasMaterialWarnings = true;
                    $warnings[] = [
                        'code' => 'DUPLICATE_DESTINATION',
                        'message' => 'Duplicate reporting destination: ' . $normalized,
                    ];
                } else {
                    $seen[$normalized] = true;
                }
                $validCount++;
            } elseif ($destination->status === TlsRptParsedDestination::STATUS_UNSUPPORTED_SCHEME) {
                $invalidCount++;
                $hasMaterialWarnings = true;
            } elseif ($destination->status !== TlsRptParsedDestination::STATUS_EMPTY) {
                $invalidCount++;
                $hasMaterialWarnings = true;
            }

            $final[] = new TlsRptParsedDestination(
                rawUri: $destination->rawUri,
                normalizedUri: $destination->normalizedUri,
                scheme: $destination->scheme,
                addressOrHost: $destination->addressOrHost,
                status: $destination->status,
                duplicate: $duplicate,
                errors: $destination->errors,
                warnings: $destination->warnings,
            );
        }

        if ($validCount === 0) {
            $errors[] = [
                'code' => 'NO_VALID_DESTINATIONS',
                'message' => 'No syntactically valid supported reporting destinations were found.',
            ];
        } elseif ($invalidCount > 0) {
            $warnings[] = [
                'code' => 'MIXED_DESTINATIONS',
                'message' => 'One or more published reporting destinations are malformed or unsupported.',
            ];
        }

        return new TlsRptDestinationValidationResult(
            destinations: $final,
            validCount: $validCount,
            invalidCount: $invalidCount,
            configured: $validCount > 0,
            hasMaterialWarnings: $hasMaterialWarnings,
            errors: $errors,
            warnings: $warnings,
        );
    }
}
