<?php

namespace App\Services\Dmarc\DTO;

use App\Models\Scan;

final readonly class DmarcStatusContext
{
    public function __construct(
        public ?array $analysis,
        public ?string $record,
        public string $source,
        public ?Scan $scan,
    ) {
    }
}
