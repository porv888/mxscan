<?php

namespace App\Domain\EmailSecurity\DTO;

final class RecommendationListDTO
{
    /**
     * @param list<array<string, mixed>> $items
     * @param array{state: string, message: ?string} $allClear
     */
    public function __construct(
        public readonly array $items,
        public readonly array $allClear,
    ) {
    }
}
