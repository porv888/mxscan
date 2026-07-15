<?php

namespace App\Domain\EmailSecurity\Checks\Mx\Evaluation;

final class MxRecordValidator
{
    public function __construct(
        private MxRecordNormalizer $normalizer,
    ) {
    }

    /**
     * @param list<array<string, mixed>> $records
     * @return array{valid: bool, records: list<array<string, mixed>>, errors: list<array{code: string, message: string}>, warnings: list<array{code: string, message: string}>}
     */
    public function validate(array $records): array
    {
        $errors = [];
        $warnings = [];
        $validated = [];
        $seen = [];

        foreach ($records as $record) {
            $preference = (int) ($record['preference'] ?? 0);
            $rawExchange = (string) ($record['raw_exchange'] ?? '');
            $normalized = (string) ($record['normalized_exchange'] ?? '');

            if ($preference < 0 || $preference > 65535) {
                $errors[] = [
                    'code' => 'INVALID_PREFERENCE',
                    'message' => 'MX preference must be an integer in the valid DNS wire range.',
                ];
                continue;
            }

            if ($normalized === '.') {
                $validated[] = array_merge($record, [
                    'syntactically_valid' => true,
                    'is_null_mx' => true,
                ]);
                continue;
            }

            if ($this->isIpLiteral($rawExchange) || $this->isIpLiteral($normalized)) {
                $errors[] = [
                    'code' => 'IP_LITERAL_EXCHANGE',
                    'message' => 'MX exchange cannot be an IP literal.',
                ];
                continue;
            }

            if (!$this->isValidHostname($normalized)) {
                $errors[] = [
                    'code' => 'INVALID_HOSTNAME',
                    'message' => 'MX exchange is not a valid domain name.',
                ];
                continue;
            }

            $identity = $this->normalizer->duplicateIdentity($record);
            if (isset($seen[$identity])) {
                $warnings[] = [
                    'code' => 'DUPLICATE_MX_RECORD',
                    'message' => 'An identical MX record is published more than once.',
                ];
            }
            $seen[$identity] = true;

            $validated[] = array_merge($record, [
                'syntactically_valid' => true,
                'is_null_mx' => false,
            ]);
        }

        return [
            'valid' => $errors === [],
            'records' => $validated,
            'errors' => $errors,
            'warnings' => $warnings,
        ];
    }

    private function isIpLiteral(string $value): bool
    {
        $value = rtrim(trim($value), '.');

        return filter_var($value, FILTER_VALIDATE_IP) !== false;
    }

    private function isValidHostname(string $hostname): bool
    {
        if ($hostname === '' || strlen($hostname) > 253) {
            return false;
        }

        if (!preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i', $hostname)) {
            return false;
        }

        return true;
    }
}
