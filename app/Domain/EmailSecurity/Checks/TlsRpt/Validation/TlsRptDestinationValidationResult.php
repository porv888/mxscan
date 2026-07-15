<?php

namespace App\Domain\EmailSecurity\Checks\TlsRpt\Validation;

use App\Domain\EmailSecurity\Checks\TlsRpt\Parsing\TlsRptParsedDestination;

final class TlsRptDestinationValidationResult
{
    /**
     * @param list<TlsRptParsedDestination> $destinations
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     */
    public function __construct(
        public readonly array $destinations,
        public readonly int $validCount = 0,
        public readonly int $invalidCount = 0,
        public readonly bool $configured = false,
        public readonly bool $hasMaterialWarnings = false,
        public readonly array $errors = [],
        public readonly array $warnings = [],
    ) {
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function destinationPayload(): array
    {
        return array_map(
            fn (TlsRptParsedDestination $d) => [
                'raw_uri' => $d->rawUri,
                'normalized_uri' => $d->normalizedUri,
                'scheme' => $d->scheme,
                'address_or_host' => $d->addressOrHost,
                'status' => $d->status,
                'duplicate' => $d->duplicate,
                'errors' => $d->errors,
                'warnings' => $d->warnings,
            ],
            $this->destinations,
        );
    }
}
