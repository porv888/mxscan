<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts\Validation;

use App\Domain\EmailSecurity\Checks\MtaSts\Parsing\MtaStsParsedPolicy;

final class MtaStsPolicyValidationResult
{
    public const MAX_MAX_AGE = 31557600;
    public const OPERATIONAL_SHORT_MAX_AGE = 86400;

    /**
     * @param list<string> $validMxPatterns
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     */
    public function __construct(
        public readonly bool $valid,
        public readonly ?string $mode = null,
        public readonly ?int $maxAge = null,
        public readonly array $validMxPatterns = [],
        public readonly array $errors = [],
        public readonly array $warnings = [],
    ) {
    }
}
