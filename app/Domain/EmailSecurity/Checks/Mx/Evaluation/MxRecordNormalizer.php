<?php

namespace App\Domain\EmailSecurity\Checks\Mx\Evaluation;

final class MxRecordNormalizer
{
    public function normalizeDomain(string $domain): string
    {
        $domain = strtolower(rtrim(trim($domain), '.'));

        if ($domain === '') {
            return '';
        }

        if (function_exists('idn_to_ascii')) {
            $ascii = idn_to_ascii($domain, IDNA_NONTRANSITIONAL_TO_ASCII, INTL_IDNA_VARIANT_UTS46);
            if (is_string($ascii) && $ascii !== '') {
                return strtolower($ascii);
            }
        }

        return $domain;
    }

    public function normalizeExchange(string $exchange): string
    {
        $exchange = trim($exchange);

        if ($exchange === '.') {
            return '.';
        }

        return $this->normalizeDomain($exchange);
    }

    /**
     * @param list<array<string, mixed>> $rawRecords
     * @return list<array<string, mixed>>
     */
    public function normalizeRecords(array $rawRecords): array
    {
        $normalized = [];

        foreach ($rawRecords as $record) {
            $rawExchange = (string) ($record['target'] ?? $record['exchange'] ?? '');
            $preference = (int) ($record['pri'] ?? $record['preference'] ?? 0);

            $normalized[] = [
                'preference' => $preference,
                'raw_exchange' => $rawExchange,
                'normalized_exchange' => $this->normalizeExchange($rawExchange),
                'null_mx_candidate' => rtrim($rawExchange, '.') === '' || rtrim($rawExchange, '.') === '.',
                'source_ttl' => $record['ttl'] ?? null,
                'rr_index' => $record['rr_index'] ?? null,
            ];
        }

        usort($normalized, function (array $a, array $b): int {
            $pref = $a['preference'] <=> $b['preference'];
            if ($pref !== 0) {
                return $pref;
            }

            return ($a['rr_index'] ?? 0) <=> ($b['rr_index'] ?? 0);
        });

        return $normalized;
    }

    public function duplicateIdentity(array $record): string
    {
        return $record['preference'] . '|' . $record['normalized_exchange'];
    }
}
