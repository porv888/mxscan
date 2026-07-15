<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts\Parsing;

final class MtaStsDnsRecordParser
{
    private const KNOWN_FIELDS = ['v', 'id'];
    private const MAX_ID_LENGTH = 255;

    public function parse(string $rawRecord): MtaStsParsedIndicator
    {
        $rawRecord = trim($rawRecord);
        $normalized = preg_replace('/\s+/', '', $rawRecord) ?? $rawRecord;
        $parts = array_values(array_filter(explode(';', $normalized), fn (string $p) => $p !== ''));

        $fields = [];
        $unknownFields = [];
        $duplicateFields = [];
        $versionFirst = false;
        $malformed = false;
        $firstKey = null;

        foreach ($parts as $index => $part) {
            if (!str_contains($part, '=')) {
                $malformed = true;
                continue;
            }

            [$key, $value] = explode('=', $part, 2);
            $key = strtolower(trim($key));
            $value = trim($value);

            if ($key === '' || $value === '') {
                $malformed = true;
                continue;
            }

            if ($index === 0) {
                $firstKey = $key;
                $versionFirst = ($key === 'v' && $value === 'STSv1');
            }

            if (array_key_exists($key, $fields)) {
                $duplicateFields[] = ['field' => $key, 'value' => $value];
                continue;
            }

            if (in_array($key, self::KNOWN_FIELDS, true)) {
                $fields[$key] = $value;
            } else {
                $unknownFields[$key] = $value;
            }
        }

        if ($firstKey !== 'v') {
            $versionFirst = false;
        }

        return new MtaStsParsedIndicator(
            version: $fields['v'] ?? null,
            id: $fields['id'] ?? null,
            rawRecord: $rawRecord,
            normalizedRecord: $normalized,
            fields: $fields,
            unknownFields: $unknownFields,
            duplicateFields: $duplicateFields,
            versionFirst: $versionFirst,
            malformed: $malformed,
        );
    }

    public function isValidId(?string $id): bool
    {
        if ($id === null || $id === '') {
            return false;
        }

        if (strlen($id) > self::MAX_ID_LENGTH) {
            return false;
        }

        return (bool) preg_match('/^[A-Za-z0-9_-]+$/', $id);
    }
}
