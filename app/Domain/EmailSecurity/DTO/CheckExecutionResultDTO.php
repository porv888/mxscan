<?php

namespace App\Domain\EmailSecurity\DTO;

final class CheckExecutionResultDTO
{
    /**
     * @param array<string, mixed> $artifacts
     * @param array<string, mixed> $diagnostics
     */
    public function __construct(
        public readonly CheckResultDTO $result,
        public readonly array $artifacts = [],
        public readonly array $diagnostics = [],
    ) {
    }
}
