<?php

namespace App\Domain\EmailSecurity\DTO;

final class CheckCollectionResultDTO
{
    /**
     * @param array<string, CheckResultDTO> $results
     * @param array<string, mixed> $artifacts
     * @param array<string, mixed> $diagnostics
     */
    public function __construct(
        public readonly array $results,
        public readonly array $artifacts,
        public readonly array $diagnostics,
    ) {
    }
}
