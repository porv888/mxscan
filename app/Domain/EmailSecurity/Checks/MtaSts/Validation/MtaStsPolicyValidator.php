<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts\Validation;

use App\Domain\EmailSecurity\Checks\MtaSts\Parsing\MtaStsParsedPolicy;

final class MtaStsPolicyValidator
{
    public function validate(MtaStsParsedPolicy $parsed): MtaStsPolicyValidationResult
    {
        $errors = [];
        $warnings = [];
        $validMxPatterns = [];

        if ($parsed->malformed) {
            $errors[] = [
                'code' => 'MALFORMED_POLICY_LINE',
                'message' => 'The MTA-STS policy contains malformed lines.',
            ];
        }

        if (($parsed->version ?? '') !== 'STSv1') {
            $errors[] = [
                'code' => 'INVALID_POLICY_VERSION',
                'message' => 'The MTA-STS policy requires version: STSv1.',
            ];
        }

        $mode = $parsed->mode;
        if (!in_array($mode, ['none', 'testing', 'enforce'], true)) {
            $errors[] = [
                'code' => 'INVALID_POLICY_MODE',
                'message' => 'The MTA-STS policy requires mode: none, testing, or enforce.',
            ];
        }

        $maxAge = $parsed->maxAge;
        if ($maxAge === null) {
            $errors[] = [
                'code' => 'MISSING_MAX_AGE',
                'message' => 'The MTA-STS policy requires max_age.',
            ];
        } elseif ($maxAge < 0 || $maxAge > MtaStsPolicyValidationResult::MAX_MAX_AGE) {
            $errors[] = [
                'code' => 'INVALID_MAX_AGE',
                'message' => 'The MTA-STS policy max_age is out of range.',
            ];
        } elseif ($maxAge < MtaStsPolicyValidationResult::OPERATIONAL_SHORT_MAX_AGE) {
            $warnings[] = [
                'code' => 'SHORT_MAX_AGE',
                'message' => 'The published max_age is operationally short.',
            ];
        }

        if ($mode !== 'none') {
            if ($parsed->mxPatterns === []) {
                $errors[] = [
                    'code' => 'MISSING_MX_PATTERNS',
                    'message' => 'The MTA-STS policy requires at least one mx field unless mode is none.',
                ];
            } else {
                foreach ($parsed->mxPatterns as $pattern) {
                    $normalized = $this->normalizeDomain($pattern);
                    if (!$this->isValidMxPattern($normalized)) {
                        $errors[] = [
                            'code' => 'INVALID_MX_PATTERN',
                            'message' => 'Invalid MTA-STS mx pattern: ' . $pattern,
                        ];
                    } else {
                        $validMxPatterns[] = $normalized;
                    }
                }
            }
        }

        foreach ($parsed->duplicateFields as $duplicate) {
            $warnings[] = [
                'code' => 'DUPLICATE_POLICY_FIELD',
                'message' => 'Duplicate policy field ignored: ' . $duplicate['field'],
            ];
        }

        return new MtaStsPolicyValidationResult(
            valid: $errors === [],
            mode: $mode,
            maxAge: $maxAge,
            validMxPatterns: $validMxPatterns,
            errors: $errors,
            warnings: $warnings,
        );
    }

    public function normalizeDomain(string $domain): string
    {
        $domain = strtolower(rtrim(trim($domain), '.'));

        if (function_exists('idn_to_ascii')) {
            $ascii = idn_to_ascii($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if ($ascii !== false) {
                $domain = $ascii;
            }
        }

        return $domain;
    }

    public function isValidMxPattern(string $pattern): bool
    {
        if ($pattern === '' || filter_var($pattern, FILTER_VALIDATE_IP)) {
            return false;
        }

        if (str_starts_with($pattern, '*.')) {
            $suffix = substr($pattern, 2);
            if ($suffix === '' || !str_contains($suffix, '.')) {
                return false;
            }

            return $this->isValidDomainName($suffix);
        }

        if (str_contains($pattern, '*')) {
            return false;
        }

        return $this->isValidDomainName($pattern);
    }

    private function isValidDomainName(string $domain): bool
    {
        if ($domain === '' || str_contains($domain, '..')) {
            return false;
        }

        return (bool) preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i', $domain);
    }
}
