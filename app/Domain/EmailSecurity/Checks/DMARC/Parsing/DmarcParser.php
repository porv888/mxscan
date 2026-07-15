<?php

namespace App\Domain\EmailSecurity\Checks\DMARC\Parsing;

final class DmarcParser
{
    /** @var list<string> */
    private const KNOWN_TAGS = [
        'v', 'p', 'sp', 'np', 'pct', 'rua', 'ruf', 'adkim', 'aspf', 'fo', 'ri', 't', 'psd', 'rf',
    ];

    public function parse(string $record): DmarcParsedRecord
    {
        $rawRecord = trim($record);
        $parts = preg_split('/\s*;\s*/', trim($rawRecord, "; \t\n\r\0\x0B")) ?: [];
        $tags = [];
        $duplicateTags = [];
        $unknownTags = [];
        $ordered = [];

        foreach ($parts as $part) {
            $part = trim($part);
            if ($part === '') {
                continue;
            }

            if (!preg_match('/^([a-z]+)\s*=\s*(.+)$/i', $part, $matches)) {
                continue;
            }

            $key = strtolower($matches[1]);
            $value = trim($matches[2]);
            $ordered[] = $key;

            if (isset($tags[$key])) {
                $duplicateTags[] = $key;
            }

            $tags[$key] = [
                'raw' => $value,
                'normalized' => $this->normalizeTagValue($key, $value),
            ];

            if (!in_array($key, self::KNOWN_TAGS, true)) {
                $unknownTags[] = $key;
            }
        }

        $normalized = $this->buildNormalized($tags);

        return new DmarcParsedRecord(
            rawRecord: $rawRecord,
            normalizedRecord: $normalized,
            tags: $tags,
            duplicateTags: array_values(array_unique($duplicateTags)),
            unknownTags: array_values(array_unique($unknownTags)),
        );
    }

    private function normalizeTagValue(string $key, string $value): string
    {
        return match ($key) {
            'p', 'sp', 'np' => strtolower($value),
            'adkim', 'aspf' => strtolower($value),
            't', 'psd' => strtolower($value),
            default => $value,
        };
    }

    /**
     * @param array<string, array{raw: string, normalized: string}> $tags
     */
    private function buildNormalized(array $tags): string
    {
        $segments = ['v=DMARC1'];
        $order = ['p', 'sp', 'np', 'pct', 'rua', 'ruf', 'adkim', 'aspf', 'fo', 'ri', 't', 'psd'];

        foreach ($order as $key) {
            if (isset($tags[$key])) {
                $segments[] = $key . '=' . $tags[$key]['raw'];
            }
        }

        foreach ($tags as $key => $tag) {
            if ($key === 'v' || in_array($key, $order, true)) {
                continue;
            }
            $segments[] = $key . '=' . $tag['raw'];
        }

        return implode('; ', $segments);
    }
}
