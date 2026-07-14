<?php

namespace App\Domain\EmailSecurity\DTO;

final class CheckResultDTO
{
    /**
     * @param array<string, mixed>|null $data
     * @param list<string> $messages
     */
    public function __construct(
        public readonly string $key,
        public readonly string $status,
        public readonly ?array $data = null,
        public readonly array $messages = [],
    ) {
    }
}
