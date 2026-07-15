<?php

namespace App\Domain\EmailSecurity\Checks\DKIM\Parsing;

final class DkimRecordParser
{
    private const KNOWN_TAGS = ['v', 'k', 'p', 'h', 's', 't', 'g', 'n'];

    public function parse(string $record): DkimParsedRecord
    {
        $raw = trim($record);
        $normalized = preg_replace('/\s+/', '', $raw) ?? $raw;
        $tags = [];
        $duplicateTags = [];
        $unknownTags = [];
        $parseErrors = [];

        $parts = preg_split('/\s*;\s*/', $raw) ?: [];
        foreach ($parts as $index => $part) {
            $part = trim($part);
            if ($part === '') {
                continue;
            }

            if (!str_contains($part, '=')) {
                if ($index === 0 && stripos($part, 'v=DKIM1') === 0) {
                    $tags['v'] = 'DKIM1';
                    continue;
                }
                $parseErrors[] = ['code' => 'MALFORMED_TAG', 'message' => "Malformed tag segment: {$part}"];
                continue;
            }

            [$key, $value] = explode('=', $part, 2);
            $key = strtolower(trim($key));
            $value = trim($value);

            if ($key === '') {
                $parseErrors[] = ['code' => 'EMPTY_TAG', 'message' => 'Empty tag name'];
                continue;
            }

            if (isset($tags[$key])) {
                $duplicateTags[$key][] = $value;
                continue;
            }

            if (!in_array($key, self::KNOWN_TAGS, true)) {
                $unknownTags[] = $key;
            }

            $tags[$key] = $value;
        }

        return new DkimParsedRecord(
            rawRecord: $raw,
            normalizedRecord: $normalized,
            tags: $tags,
            duplicateTags: $duplicateTags,
            unknownTags: $unknownTags,
            parseErrors: $parseErrors,
        );
    }
}
