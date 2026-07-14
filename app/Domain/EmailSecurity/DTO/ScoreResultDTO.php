<?php

namespace App\Domain\EmailSecurity\DTO;

final class ScoreResultDTO
{
    /**
     * @param list<array<string, mixed>> $breakdown
     */
    public function __construct(
        public readonly ?int $total,
        public readonly array $breakdown,
    ) {
    }
}
