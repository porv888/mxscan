<?php

namespace App\Domain\EmailSecurity\Reporting;

final class ReportingService
{
    public function __construct(
        private ScanReportStatusMapper $mapper,
    ) {
    }

    /**
     * @param array<string, mixed> $resultJson
     * @param array<string, mixed> $records
     * @return array<string, mixed>
     */
    public function buildStatusCards(array $resultJson, array $records, ?int $score): array
    {
        return $this->mapper->buildStatusCards($resultJson, $records, $score);
    }
}
