<?php

namespace App\Domain\EmailSecurity\Checks\TlsRpt\Parsing;

final class TlsRptRecordParser
{
    private const KNOWN_TAGS = ['v', 'rua'];

    public function parse(string $rawRecord): TlsRptParsedRecord
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

        foreach ($parts as $index => $part) {
            $part = trim($part);
            if ($part === '') {
                continue;
            }

            if (!preg_match('/^([a-zA-Z0-9]+)\s*=\s*(.*)$/s', $part, $matches)) {
                $malformed = true;
                $parseErrors[] = [
                    'code' => 'MALFORMED_TAG',
                    'message' => 'Malformed tag syntax in TLS-RPT record.',
                ];
                continue;
            }

            $key = strtolower($matches[1]);
            $value = trim($matches[2]);

            if ($key === '' || $value === '') {
                $malformed = true;
                $parseErrors[] = [
                    'code' => 'EMPTY_TAG_VALUE',
                    'message' => 'Empty tag key or value in TLS-RPT record.',
                ];
                continue;
            }

            if ($index === 0) {
                $firstKey = $key;
                $versionFirst = ($key === 'v' && strtoupper($value) === 'TLSRPTV1');
            }

            if (isset($tags[$key])) {
                $duplicateTags[] = $key;
                continue;
            }

            $tags[$key] = [
                'raw' => $value,
                'normalized' => $this->normalizeTagValue($key, $value),
            ];

            if (!in_array($key, self::KNOWN_TAGS, true)) {
                $unknownTags[] = $key;
            }
        }

        if ($firstKey !== 'v') {
            $versionFirst = false;
        }

        return new TlsRptParsedRecord(
            rawRecord: $rawRecord,
            normalizedRecord: $this->buildNormalized($tags),
            tags: $tags,
            unknownTags: array_values(array_unique($unknownTags)),
            duplicateTags: array_values(array_unique($duplicateTags)),
            parseErrors: $parseErrors,
            versionFirst: $versionFirst,
            malformed: $malformed,
        );
    }

    private function normalizeTagValue(string $key, string $value): string
    {
        return match ($key) {
            'v' => strtoupper($value),
            default => $value,
        };
    }

    /**
     * @param array<string, array{raw: string, normalized: string}> $tags
     */
    private function buildNormalized(array $tags): string
    {
        $segments = [];

        if (isset($tags['v'])) {
            $segments[] = 'v=' . $tags['v']['normalized'];
        }

        if (isset($tags['rua'])) {
            $segments[] = 'rua=' . $tags['rua']['raw'];
        }

        foreach ($tags as $key => $tag) {
            if (in_array($key, ['v', 'rua'], true)) {
                continue;
            }
            $segments[] = $key . '=' . $tag['raw'];
        }

        return implode('; ', $segments);
    }
}
