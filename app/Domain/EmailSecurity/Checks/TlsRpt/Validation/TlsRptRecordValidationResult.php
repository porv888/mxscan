<?php

namespace App\Domain\EmailSecurity\Checks\TlsRpt\Validation;

final class TlsRptRecordValidationResult
{
    /**
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     */
    public function __construct(
        public readonly bool $valid,
        public readonly ?string $ruaValue = null,
        public readonly array $errors = [],
        public readonly array $warnings = [],
    ) {
    }
}
