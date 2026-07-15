<?php

namespace App\Domain\EmailSecurity\Checks\DMARC\Validation;

use App\Domain\EmailSecurity\Checks\DMARC\Discovery\DmarcDiscoveryResult;
use App\Domain\EmailSecurity\Checks\DMARC\Parsing\DmarcParsedRecord;
use App\Domain\EmailSecurity\Checks\DMARC\Support\DmarcTxtReconstructor;

final class DmarcValidationResult
{
    /**
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     */
    public function __construct(
        public readonly DmarcParsedRecord $parsed,
        public readonly bool $valid,
        public readonly array $errors = [],
        public readonly array $warnings = [],
    ) {
    }

    public function isPermError(): bool
    {
        return !$this->valid;
    }
}
