<?php

namespace App\Domain\EmailSecurity\Checks\SPF\Validation;

use App\Domain\EmailSecurity\Checks\SPF\Discovery\SpfDiscoveryResult;
use App\Domain\EmailSecurity\Checks\SPF\Parsing\SpfParsedTerm;

final class SpfValidator
{
    private const LOOKUP_LIMIT = 10;
    private const MAX_RECORD_LENGTH = 255;

    /**
     * @param list<SpfParsedTerm> $terms
     */
    public function validate(array $terms, SpfDiscoveryResult $discovery, string $record): SpfValidationResult
    {
        $errors = [];
        $warnings = [];
        $hasTerminalAll = false;
        $terminalPolicy = null;
        $redirectCount = 0;
        $afterAll = false;

        if (trim($record) === '' || !preg_match('/^v=spf1\b/i', trim($record))) {
            $errors[] = ['code' => 'INVALID_VERSION', 'message' => 'SPF record must begin with v=spf1.'];
        }

        if ($discovery->multipleRecords) {
            $errors[] = ['code' => 'MULTIPLE_SPF_RECORDS', 'message' => 'Multiple SPF records were found.'];
        }

        if (strlen($record) > self::MAX_RECORD_LENGTH) {
            $warnings[] = ['code' => 'RECORD_TOO_LONG', 'message' => 'SPF record exceeds recommended TXT length.'];
        }

        foreach ($terms as $term) {
            foreach ($term->errors as $termError) {
                $errors[] = $termError + ['position' => $term->position];
            }

            if ($afterAll) {
                $errors[] = [
                    'code' => 'TERMS_AFTER_ALL',
                    'message' => 'Terms found after the all mechanism.',
                    'position' => $term->position,
                ];
            }

            if ($term->name === 'redirect') {
                $redirectCount++;
                if ($redirectCount > 1) {
                    $errors[] = ['code' => 'DUPLICATE_REDIRECT', 'message' => 'Only one redirect modifier is allowed.'];
                }
            }

            if ($term->name === 'ptr') {
                $warnings[] = ['code' => 'DEPRECATED_PTR', 'message' => 'The ptr mechanism is deprecated.'];
            }

            if ($term->name === 'unknown') {
                $errors[] = ['code' => 'UNKNOWN_MECHANISM', 'message' => "Unknown SPF mechanism: {$term->raw}"];
            }

            if ($term->name === 'ip4' && !$this->isValidIp4($term->argument, $term->cidrV4)) {
                $errors[] = ['code' => 'INVALID_IPV4', 'message' => "Invalid ip4 value: {$term->raw}", 'position' => $term->position];
            }

            if ($term->name === 'ip6' && !$this->isValidIp6($term->argument, $term->cidrV6)) {
                $errors[] = ['code' => 'INVALID_IPV6', 'message' => "Invalid ip6 value: {$term->raw}", 'position' => $term->position];
            }

            if (in_array($term->name, ['include', 'redirect'], true) && !$this->isValidDomain($term->argument)) {
                $errors[] = ['code' => 'INVALID_DOMAIN', 'message' => "Invalid domain in {$term->name}: {$term->raw}", 'position' => $term->position];
            }

            if ($term->name === 'all') {
                $hasTerminalAll = true;
                $terminalPolicy = [
                    'qualifier' => $term->qualifier,
                    'mechanism' => 'all',
                    'position' => $term->position,
                ];
                if ($term->qualifier === '+') {
                    $errors[] = ['code' => 'PLUS_ALL', 'message' => 'SPF uses +all which allows any sender.', 'position' => $term->position];
                }
                if (in_array($term->qualifier, ['~', '?'], true)) {
                    $warnings[] = ['code' => 'WEAK_TERMINAL_POLICY', 'message' => 'SPF terminal policy is weak.', 'position' => $term->position];
                }
                $afterAll = true;
            }
        }

        if (!$hasTerminalAll) {
            $warnings[] = ['code' => 'MISSING_TERMINAL_ALL', 'message' => 'SPF record has no explicit all mechanism.'];
        }

        return new SpfValidationResult(
            terms: $terms,
            errors: $errors,
            warnings: $warnings,
            hasTerminalAll: $hasTerminalAll,
            terminalPolicy: $terminalPolicy,
        );
    }

    private function isValidIp4(?string $ip, ?int $cidr): bool
    {
        if ($ip === null || $ip === '') {
            return false;
        }
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }
        if ($cidr !== null && ($cidr < 0 || $cidr > 32)) {
            return false;
        }

        return true;
    }

    private function isValidIp6(?string $ip, ?int $cidr): bool
    {
        if ($ip === null || $ip === '') {
            return false;
        }
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return false;
        }
        if ($cidr !== null && ($cidr < 0 || $cidr > 128)) {
            return false;
        }

        return true;
    }

    private function isValidDomain(?string $domain): bool
    {
        if ($domain === null || trim($domain) === '') {
            return false;
        }

        return (bool) preg_match('/^[a-z0-9._-]+$/i', $domain);
    }
}
