<?php

namespace App\Domain\EmailSecurity\Checks\TlsRpt\Parsing;

final class TlsRptParsedDestination
{
    public const STATUS_VALID = 'valid';
    public const STATUS_INVALID = 'invalid';
    public const STATUS_UNSUPPORTED_SCHEME = 'unsupported_scheme';
    public const STATUS_EMPTY = 'empty';

    /**
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     */
    public function __construct(
        public readonly string $rawUri,
        public readonly ?string $normalizedUri,
        public readonly ?string $scheme,
        public readonly ?string $addressOrHost,
        public readonly string $status,
        public readonly bool $duplicate = false,
        public readonly array $errors = [],
        public readonly array $warnings = [],
    ) {
    }

    public function isValidSupported(): bool
    {
        return $this->status === self::STATUS_VALID;
    }
}
