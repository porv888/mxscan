<?php

namespace App\Domain\EmailSecurity\Checks\DKIM\Validation;

use App\Domain\EmailSecurity\Checks\DKIM\Inspection\DkimPublicKeyInspector;
use App\Domain\EmailSecurity\Checks\DKIM\Parsing\DkimParsedRecord;

final class DkimValidationResult
{
    /**
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     * @param array{type: ?string, bits: ?int, revoked: bool, valid: bool} $keyInfo
     */
    public function __construct(
        public readonly DkimParsedRecord $parsed,
        public readonly string $recordStatus,
        public readonly array $errors = [],
        public readonly array $warnings = [],
        public readonly array $keyInfo = [],
        public readonly bool $testingMode = false,
        public readonly bool $supportsEmail = true,
    ) {
    }

    public function isValid(): bool
    {
        return $this->recordStatus === 'valid';
    }

    public function isRevoked(): bool
    {
        return $this->recordStatus === 'revoked';
    }

    public function isPermError(): bool
    {
        return in_array($this->recordStatus, ['invalid', 'revoked', 'ambiguous'], true);
    }
}
