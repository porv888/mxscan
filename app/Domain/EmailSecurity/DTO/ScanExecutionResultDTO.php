<?php

namespace App\Domain\EmailSecurity\DTO;

use App\Services\Spf\DTOs\SpfResultDTO;

final class ScanExecutionResultDTO
{
    /**
     * @param array<string, mixed> $resultJson
     * @param list<array<string, mixed>> $recommendations
     */
    public function __construct(
        public readonly array $resultJson,
        public readonly array $recommendations,
        public readonly ?int $score,
        public readonly int $durationMs,
        public readonly string $scanType,
        public readonly ?SpfResultDTO $spfRawResult = null,
    ) {
    }
}
