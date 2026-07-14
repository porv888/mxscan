<?php

namespace App\Domain\EmailSecurity\DTO;

final class ScoreComponentDTO
{
    public function __construct(
        public readonly string $key,
        public readonly string $label,
        public readonly int $earned,
        public readonly int $possible,
        public readonly string $status,
        public readonly ?string $reason,
        public readonly string $modelVersion = 'spf-v2',
    ) {
    }

    /**
     * @return array{key: string, label: string, earned: int, possible: int, status: string, hint: ?string, model_version: string}
     */
    public function toBreakdownRow(): array
    {
        return [
            'key' => $this->key,
            'label' => $this->label,
            'earned' => $this->earned,
            'possible' => $this->possible,
            'status' => $this->status,
            'hint' => $this->reason,
            'model_version' => $this->modelVersion,
        ];
    }
}
