<?php

namespace App\Domain\EmailSecurity\DTO;

/**
 * View-model payload for scan report pages.
 * Mirrors the array historically returned by PreparesScanReport.
 */
final class ScanReportViewModelDTO
{
    /**
     * @param array<string, mixed> $data
     */
    public function __construct(
        public readonly array $data,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->data;
    }
}
