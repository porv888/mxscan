<?php

namespace App\Domain\EmailSecurity\Checks\Bimi;

final class BimiIndicatorComparator
{
    public const METHOD = 'exact_decompressed_sha256';

    /**
     * @return array<string, mixed>
     */
    public function compare(?string $externalHash, ?string $embeddedHash): array
    {
        if ($externalHash === null || $embeddedHash === null) {
            return [
                'method' => self::METHOD,
                'external_hash' => $externalHash,
                'embedded_hash' => $embeddedHash,
                'identical' => null,
                'completeness' => 'incomplete',
            ];
        }

        return [
            'method' => self::METHOD,
            'external_hash' => $externalHash,
            'embedded_hash' => $embeddedHash,
            'identical' => hash_equals($externalHash, $embeddedHash),
            'completeness' => 'complete',
        ];
    }
}
