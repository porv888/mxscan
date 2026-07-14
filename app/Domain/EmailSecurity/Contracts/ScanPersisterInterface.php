<?php

namespace App\Domain\EmailSecurity\Contracts;

use App\Domain\EmailSecurity\DTO\ScanExecutionResultDTO;
use App\Domain\EmailSecurity\DTO\ScanOptionsDTO;
use App\Models\Domain;
use App\Models\Scan;

interface ScanPersisterInterface
{
    /**
     * @param array<string, mixed> $factsJson
     */
    public function saveFinished(
        Scan $scan,
        Domain $domain,
        ScanExecutionResultDTO $execution,
        ScanOptionsDTO $options,
        array $factsJson,
    ): void;

    public function markFailed(Scan $scan, int $durationMs, ?string $userError = null): void;

    public function updateProgress(Scan $scan, int $progressPct): void;
}
