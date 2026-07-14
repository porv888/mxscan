<?php

namespace App\Domain\EmailSecurity\Checks\SPF\Evaluation;

final class SpfEvaluationResult
{
    /**
     * @param list<string> $resolvedIps
     * @param list<array<string, mixed>> $dependencies
     * @param list<array{code: string, message: string}> $warnings
     * @param list<array{code: string, message: string}> $errors
     * @param list<array<string, mixed>> $diagnostics
     */
    public function __construct(
        public readonly array $resolvedIps = [],
        public readonly array $dependencies = [],
        public readonly array $warnings = [],
        public readonly array $errors = [],
        public readonly array $diagnostics = [],
        public readonly bool $lookupLimitExceeded = false,
    ) {
    }
}
