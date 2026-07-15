<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts\Validation;

final class MtaStsDnsValidationResult
{
    /**
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     */
    public function __construct(
        public readonly bool $valid,
        public readonly ?string $policyId = null,
        public readonly array $errors = [],
        public readonly array $warnings = [],
    ) {
    }
}
