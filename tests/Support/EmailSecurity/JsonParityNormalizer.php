<?php

namespace Tests\Support\EmailSecurity;

final class JsonParityNormalizer
{
    /**
     * @param array<string, mixed> $payload
     * @return array<string, mixed>
     */
    public static function normalize(array $payload): array
    {
        $stripKeys = [
            'started_at',
            'finished_at',
            'created_at',
            'updated_at',
            'duration_ms',
            'timestamp',
            'collectedAt',
            'executedAt',
            'correlationId',
        ];

        return self::stripRecursive($payload, $stripKeys);
    }

    /**
     * @param array<string, mixed> $payload
     * @param list<string> $stripKeys
     * @return array<string, mixed>
     */
    private static function stripRecursive(array $payload, array $stripKeys): array
    {
        $normalized = [];

        foreach ($payload as $key => $value) {
            if (in_array($key, $stripKeys, true)) {
                continue;
            }

            if ($key === 'id' && is_int($value)) {
                $normalized[$key] = '__id__';
                continue;
            }

            if (is_array($value)) {
                $normalized[$key] = self::stripRecursive($value, $stripKeys);
                continue;
            }

            $normalized[$key] = $value;
        }

        return $normalized;
    }
}
