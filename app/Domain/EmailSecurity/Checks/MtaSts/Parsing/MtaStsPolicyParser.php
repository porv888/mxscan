<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts\Parsing;

final class MtaStsPolicyParser
{
    private const KNOWN_FIELDS = ['version', 'mode', 'mx', 'max_age'];

    public function parse(string $body): MtaStsParsedPolicy
    {
        $rawBody = str_replace("\r\n", "\n", $body);
        $rawBody = rtrim($rawBody, "\n");
        $lineRows = explode("\n", $rawBody);

        $version = null;
        $mode = null;
        $maxAge = null;
        $mxPatterns = [];
        $lines = [];
        $duplicateFields = [];
        $unknownFields = [];
        $seenFields = [];
        $malformed = false;

        foreach ($lineRows as $index => $line) {
            $trimmed = trim($line);
            if ($trimmed === '') {
                continue;
            }

            if (!str_contains($trimmed, ':')) {
                $malformed = true;
                continue;
            }

            [$key, $value] = explode(':', $trimmed, 2);
            $key = strtolower(trim($key));
            $value = trim($value);
            $lines[] = ['line' => $index + 1, 'key' => $key, 'value' => $value];

            if ($key === '' || $value === '') {
                $malformed = true;
                continue;
            }

            if ($key === 'mx') {
                $mxPatterns[] = $value;
                continue;
            }

            if (array_key_exists($key, $seenFields)) {
                $duplicateFields[] = ['field' => $key, 'value' => $value];
                continue;
            }

            $seenFields[$key] = true;

            if (!in_array($key, self::KNOWN_FIELDS, true)) {
                $unknownFields[$key] = $value;
                continue;
            }

            match ($key) {
                'version' => $version = $value,
                'mode' => $mode = strtolower($value),
                'max_age' => $maxAge = is_numeric($value) ? (int) $value : null,
                default => null,
            };
        }

        return new MtaStsParsedPolicy(
            version: $version,
            mode: $mode,
            maxAge: $maxAge,
            mxPatterns: $mxPatterns,
            rawBody: $rawBody,
            lines: $lines,
            duplicateFields: $duplicateFields,
            unknownFields: $unknownFields,
            malformed: $malformed,
        );
    }
}
