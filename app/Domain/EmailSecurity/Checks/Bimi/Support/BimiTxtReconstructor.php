<?php

namespace App\Domain\EmailSecurity\Checks\Bimi\Support;

/**
 * Reconstructs TXT RRset values without merging separate resource records.
 */
final class BimiTxtReconstructor
{
    private const VERSION_PREFIX = 'v=BIMI1';

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

    public static function isBimiVersionToken(string $txt): bool
    {
        $txt = ltrim($txt);
        if (!str_starts_with($txt, self::VERSION_PREFIX)) {
            return false;
        }

        $after = substr($txt, strlen(self::VERSION_PREFIX));

        return $after === '' || str_starts_with($after, ';');
    }

    /**
     * @param list<string> $txtValues
     * @return list<string>
     */
    public static function selectBimiRecords(array $txtValues): array
    {
        return array_values(array_filter(
            $txtValues,
            fn (string $txt) => self::isBimiVersionToken($txt),
        ));
    }
}
