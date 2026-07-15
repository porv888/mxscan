<?php

namespace App\Domain\EmailSecurity\Checks\Bimi;

use App\Domain\EmailSecurity\Checks\Bimi\DTO\BimiParsedRecord;

final class BimiRecordParser
{
    private const KNOWN_TAGS = ['v', 'l', 'a', 'lps', 'avp'];

    public function parse(string $rawRecord): BimiParsedRecord
    {
        $rawRecord = trim($rawRecord);
        $parts = preg_split('/\s*;\s*/', trim($rawRecord, "; \t\n\r\0\x0B")) ?: [];
        $tags = [];
        $duplicateTags = [];
        $unknownTags = [];
        $parseErrors = [];
        $versionFirst = false;
        $malformed = false;
        $firstKey = null;
        $lpsPrefixes = [];
        $avatarPreference = 'brand';

        foreach ($parts as $index => $part) {
            $part = trim($part);
            if ($part === '') {
                continue;
            }

            if (!preg_match('/^([a-zA-Z0-9]+)\s*=\s*(.*)$/s', $part, $matches)) {
                $malformed = true;
                $parseErrors[] = [
                    'code' => 'MALFORMED_TAG',
                    'message' => 'Malformed tag syntax in BIMI record.',
                ];
                continue;
            }

            $key = strtolower($matches[1]);
            $value = trim($matches[2]);

            if ($key === '') {
                $malformed = true;
                $parseErrors[] = [
                    'code' => 'EMPTY_TAG_KEY',
                    'message' => 'Empty tag key in BIMI record.',
                ];
                continue;
            }

            if ($index === 0) {
                $firstKey = $key;
                $versionFirst = ($key === 'v' && $value === 'BIMI1');
            }

            if (isset($tags[$key])) {
                $duplicateTags[] = $key;
                continue;
            }

            $normalized = $this->normalizeTagValue($key, $value);
            $tags[$key] = [
                'raw' => $value,
                'normalized' => $normalized,
                'present' => true,
            ];

            if ($key === 'lps') {
                $lpsPrefixes = $this->parseLpsPrefixes($value);
            }

            if ($key === 'avp') {
                $avatarPreference = in_array($normalized, ['brand', 'personal'], true) ? $normalized : 'brand';
            }

            if (!in_array($key, self::KNOWN_TAGS, true)) {
                $unknownTags[] = $key;
            }
        }

        if ($firstKey !== 'v') {
            $versionFirst = false;
        }

        $declined = isset($tags['l'])
            && ($tags['l']['raw'] === '' || $tags['l']['normalized'] === '')
            && (!isset($tags['a']) || $tags['a']['raw'] === '' || $tags['a']['normalized'] === '');

        return new BimiParsedRecord(
            rawRecord: $rawRecord,
            normalizedRecord: $this->buildNormalized($tags),
            tags: $tags,
            unknownTags: array_values(array_unique($unknownTags)),
            duplicateTags: array_values(array_unique($duplicateTags)),
            parseErrors: $parseErrors,
            versionFirst: $versionFirst,
            malformed: $malformed,
            declined: $declined,
            lpsPrefixes: $lpsPrefixes,
            avatarPreference: $avatarPreference,
        );
    }

    private function normalizeTagValue(string $key, string $value): string
    {
        return match ($key) {
            'v' => $value,
            'avp' => strtolower($value),
            'lps' => strtolower($value),
            default => $value,
        };
    }

    /**
     * @return list<string>
     */
    private function parseLpsPrefixes(string $value): array
    {
        if ($value === '') {
            return [];
        }

        $prefixes = array_map('trim', explode(',', $value));
        $normalized = [];

        foreach ($prefixes as $prefix) {
            $prefix = strtolower($prefix);
            if ($prefix === '' || in_array($prefix, $normalized, true)) {
                continue;
            }
            $normalized[] = $prefix;
        }

        return $normalized;
    }

    /**
     * @param array<string, array{raw: string, normalized: string, present: bool}> $tags
     */
    private function buildNormalized(array $tags): string
    {
        $order = ['v', 'l', 'a', 'lps', 'avp'];
        $segments = [];

        foreach ($order as $key) {
            if (!isset($tags[$key])) {
                continue;
            }
            $segments[] = $key . '=' . $tags[$key]['raw'];
        }

        foreach ($tags as $key => $tag) {
            if (in_array($key, $order, true)) {
                continue;
            }
            $segments[] = $key . '=' . $tag['raw'];
        }

        return implode('; ', $segments);
    }
}
