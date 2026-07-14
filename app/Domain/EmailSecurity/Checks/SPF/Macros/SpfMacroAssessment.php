<?php

namespace App\Domain\EmailSecurity\Checks\SPF\Macros;

final class SpfMacroAssessment
{
    /**
     * @param list<string> $unsupportedTokens
     * @param list<string> $affectedMechanisms
     */
    public function __construct(
        public readonly bool $hasUnsupportedMacro,
        public readonly array $unsupportedTokens = [],
        public readonly array $affectedMechanisms = [],
    ) {
    }
}
