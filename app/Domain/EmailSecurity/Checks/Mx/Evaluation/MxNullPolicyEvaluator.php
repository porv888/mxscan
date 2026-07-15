<?php

namespace App\Domain\EmailSecurity\Checks\Mx\Evaluation;

final class MxNullPolicyEvaluator
{
    /**
     * @param list<array<string, mixed>> $records
     * @return array{published: bool, valid: bool, mixed: bool, service_mode: string, errors: list<array{code: string, message: string}>}
     */
    public function evaluate(array $records): array
    {
        $nullRecords = array_values(array_filter(
            $records,
            fn (array $record) => ($record['is_null_mx'] ?? false) === true
                || ($record['normalized_exchange'] ?? '') === '.',
        ));
        $ordinaryRecords = array_values(array_filter(
            $records,
            fn (array $record) => ($record['normalized_exchange'] ?? '') !== '.',
        ));

        if ($nullRecords === [] && $ordinaryRecords === []) {
            return [
                'published' => false,
                'valid' => false,
                'mixed' => false,
                'service_mode' => 'unknown',
                'errors' => [],
            ];
        }

        if ($nullRecords !== [] && $ordinaryRecords !== []) {
            return [
                'published' => true,
                'valid' => false,
                'mixed' => true,
                'service_mode' => 'unknown',
                'errors' => [[
                    'code' => 'MIXED_NULL_MX',
                    'message' => 'Null MX is published together with ordinary MX records.',
                ]],
            ];
        }

        if ($nullRecords !== []) {
            $validNull = count($nullRecords) === 1
                && count($records) === 1
                && (int) ($nullRecords[0]['preference'] ?? -1) === 0;

            if (!$validNull) {
                return [
                    'published' => true,
                    'valid' => false,
                    'mixed' => false,
                    'service_mode' => 'unknown',
                    'errors' => [[
                        'code' => 'INVALID_NULL_MX',
                        'message' => 'Null MX must be the only MX record with preference 0 and exchange ".".',
                    ]],
                ];
            }

            return [
                'published' => true,
                'valid' => true,
                'mixed' => false,
                'service_mode' => 'no_inbound_mail',
                'errors' => [],
            ];
        }

        return [
            'published' => false,
            'valid' => false,
            'mixed' => false,
            'service_mode' => 'accepts_mail',
            'errors' => [],
        ];
    }
}
