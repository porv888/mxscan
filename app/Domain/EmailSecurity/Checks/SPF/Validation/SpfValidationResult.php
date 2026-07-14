<?php

namespace App\Domain\EmailSecurity\Checks\SPF\Validation;

final class SpfValidationResult
{
    /**
     * @param list<SpfParsedTerm> $terms
     * @param list<array{code: string, message: string, position?: int}> $errors
     * @param list<array{code: string, message: string, position?: int}> $warnings
     */
    public function __construct(
        public readonly array $terms,
        public readonly array $errors = [],
        public readonly array $warnings = [],
        public readonly bool $hasTerminalAll = false,
        public readonly ?array $terminalPolicy = null,
    ) {
    }

    public function hasHardErrors(): bool
    {
        return $this->errors !== [];
    }
}
