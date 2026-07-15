<?php

namespace App\Domain\EmailSecurity\Checks;

use App\Domain\EmailSecurity\DTO\CheckResultDTO;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;

/**
 * Exposes legacy bundled DNS scanner results as individual check results.
 * Does not query DNS, score, or generate recommendations.
 */
final class BundledDnsChecksAdapter
{
    /** @var array<string, string> */
    private const RECORD_KEY_MAP = [];

    /**
     * @return array<string, CheckResultDTO>
     */
    public function adapt(DnsCollectionResultDTO $dns): array
    {
        $results = [];

        foreach (self::RECORD_KEY_MAP as $recordKey => $checkKey) {
            $record = $dns->records[$recordKey] ?? null;
            if (!is_array($record)) {
                continue;
            }

            $results[$checkKey] = new CheckResultDTO(
                key: $checkKey,
                status: (string) ($record['status'] ?? 'missing'),
                data: $record,
            );
        }

        return $results;
    }
}
