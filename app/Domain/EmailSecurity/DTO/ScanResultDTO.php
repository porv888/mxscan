<?php

namespace App\Domain\EmailSecurity\DTO;

final class ScanResultDTO
{
    /**
     * @param array<string, mixed> $sections
     */
    public function __construct(
        public readonly array $sections,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->sections;
    }
}
