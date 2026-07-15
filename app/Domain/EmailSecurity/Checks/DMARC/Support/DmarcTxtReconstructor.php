<?php

namespace App\Domain\EmailSecurity\Checks\DMARC\Support;

/**
 * Reconstructs TXT RRset values without merging separate resource records.
 */
final class DmarcTxtReconstructor
{
    public static function fromDnsRow(array $record): ?string
    {
        if (isset($record['entries']) && is_array($record['entries']) && $record['entries'] !== []) {
            $chunks = [];
            foreach ($record['entries'] as $chunk) {
                if (is_string($chunk) || is_numeric($chunk)) {
                    $chunks[] = (string) $chunk;
                }
            }

            if ($chunks !== []) {
                return implode('', $chunks);
            }
        }

        if (isset($record['txt'])) {
            if (is_array($record['txt'])) {
                $chunks = [];
                foreach ($record['txt'] as $chunk) {
                    if (is_string($chunk) || is_numeric($chunk)) {
                        $chunks[] = (string) $chunk;
                    }
                }

                return $chunks !== [] ? implode('', $chunks) : null;
            }

            if (is_string($record['txt']) || is_numeric($record['txt'])) {
                return (string) $record['txt'];
            }
        }

        return null;
    }

    /**
     * @param list<array<string, mixed>> $dnsRows
     * @return list<string>
     */
    public static function allFromDnsRows(array $dnsRows): array
    {
        $reconstructed = [];

        foreach ($dnsRows as $row) {
            if (!is_array($row)) {
                continue;
            }

            $value = self::fromDnsRow($row);
            if ($value !== null && $value !== '') {
                $reconstructed[] = $value;
            }
        }

        return $reconstructed;
    }

    /**
     * @param list<string> $reconstructed
     * @return list<string>
     */
    public static function selectDmarcRecords(array $reconstructed): array
    {
        $matches = [];

        foreach ($reconstructed as $value) {
            if (self::isDmarcVersionToken($value)) {
                $matches[] = $value;
            }
        }

        return $matches;
    }

    public static function isDmarcVersionToken(string $value): bool
    {
        $trimmed = ltrim($value);

        if (stripos($trimmed, 'v=DMARC1') !== 0) {
            return false;
        }

        $remainder = substr($trimmed, 8);

        return $remainder === '' || $remainder[0] === ';' || $remainder[0] === ' ';
    }
}
