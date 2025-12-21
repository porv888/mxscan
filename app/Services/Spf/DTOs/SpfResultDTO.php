<?php

namespace App\Services\Spf\DTOs;

class SpfResultDTO
{
    public function __construct(
        public readonly ?string $currentRecord,
        public readonly int $lookupsUsed,
        public readonly ?string $flattenedSpf,
        public readonly array $warnings,
        public readonly array $resolvedIps
    ) {}

    public function toArray(): array
    {
        return [
            'current_record' => $this->currentRecord,
            'lookups_used' => $this->lookupsUsed,
            'flattened_spf' => $this->flattenedSpf,
            'warnings' => $this->warnings,
            'resolved_ips' => $this->resolvedIps,
        ];
    }
}
