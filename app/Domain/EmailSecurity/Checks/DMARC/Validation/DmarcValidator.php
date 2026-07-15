<?php

namespace App\Domain\EmailSecurity\Checks\DMARC\Validation;

use App\Domain\EmailSecurity\Checks\DMARC\Discovery\DmarcDiscoveryResult;
use App\Domain\EmailSecurity\Checks\DMARC\Parsing\DmarcParsedRecord;
use App\Domain\EmailSecurity\Checks\DMARC\Parsing\DmarcParser;
use App\Domain\EmailSecurity\Checks\DMARC\Support\DmarcTxtReconstructor;

final class DmarcValidator
{
    public function __construct(
        private DmarcParser $parser,
    ) {
    }

    public function validate(DmarcDiscoveryResult $discovery, ?string $record): DmarcValidationResult
    {
        if ($discovery->multipleRecords) {
            return new DmarcValidationResult(
                parsed: new DmarcParsedRecord('', '', []),
                valid: false,
                errors: [[
                    'code' => 'MULTIPLE_DMARC_RECORDS',
                    'message' => 'Multiple DMARC records found at ' . $discovery->hostname . '.',
                ]],
            );
        }

        if ($record === null || $record === '') {
            return new DmarcValidationResult(
                parsed: new DmarcParsedRecord('', '', []),
                valid: false,
                errors: [[
                    'code' => 'DMARC_MISSING',
                    'message' => 'No DMARC record found.',
                ]],
            );
        }

        if (!DmarcTxtReconstructor::isDmarcVersionToken($record)) {
            return new DmarcValidationResult(
                parsed: new DmarcParsedRecord($record, $record, []),
                valid: false,
                errors: [[
                    'code' => 'INVALID_DMARC_VERSION',
                    'message' => 'DMARC record must begin with v=DMARC1.',
                ]],
            );
        }

        $parsed = $this->parser->parse($record);
        $errors = [];
        $warnings = [];

        if (!isset($parsed->tags['v'])) {
            $errors[] = ['code' => 'MISSING_VERSION_TAG', 'message' => 'DMARC version tag is required.'];
        } elseif (($parsed->tags['v']['normalized'] ?? '') !== 'DMARC1') {
            $errors[] = ['code' => 'INVALID_DMARC_VERSION', 'message' => 'DMARC version must be DMARC1.'];
        }

        if ($parsed->duplicateTags !== []) {
            $errors[] = [
                'code' => 'DUPLICATE_DMARC_TAGS',
                'message' => 'Duplicate DMARC tags: ' . implode(', ', $parsed->duplicateTags) . '.',
            ];
        }

        $policy = $parsed->tag('p');
        if ($policy === null) {
            $errors[] = ['code' => 'MISSING_POLICY', 'message' => 'DMARC policy tag p is required.'];
        } elseif (!in_array($policy, ['none', 'quarantine', 'reject'], true)) {
            $errors[] = ['code' => 'INVALID_POLICY', 'message' => 'DMARC policy must be none, quarantine, or reject.'];
        }

        foreach (['sp', 'np'] as $subTag) {
            $value = $parsed->tag($subTag);
            if ($value !== null && !in_array($value, ['none', 'quarantine', 'reject'], true)) {
                $errors[] = [
                    'code' => 'INVALID_' . strtoupper($subTag),
                    'message' => "DMARC {$subTag} must be none, quarantine, or reject.",
                ];
            }
        }

        $pct = $parsed->tag('pct');
        if ($pct !== null) {
            if (!ctype_digit($pct) || (int) $pct < 0 || (int) $pct > 100) {
                $errors[] = ['code' => 'INVALID_PCT', 'message' => 'DMARC pct must be an integer from 0 to 100.'];
            } else {
                $warnings[] = ['code' => 'DEPRECATED_PCT', 'message' => 'The pct tag is deprecated in RFC 9989; consider using t=y for testing mode.'];
            }
        }

        foreach (['adkim', 'aspf'] as $alignTag) {
            $value = $parsed->tag($alignTag);
            if ($value !== null && !in_array($value, ['r', 's'], true)) {
                $errors[] = [
                    'code' => 'INVALID_' . strtoupper($alignTag),
                    'message' => "DMARC {$alignTag} must be r or s.",
                ];
            }
        }

        $t = $parsed->tag('t');
        if ($t !== null && !in_array($t, ['y', 'n'], true)) {
            $errors[] = ['code' => 'INVALID_T', 'message' => 'DMARC t must be y or n.'];
        }

        $psd = $parsed->tag('psd');
        if ($psd !== null && !in_array($psd, ['y', 'n', 'u'], true)) {
            $errors[] = ['code' => 'INVALID_PSD', 'message' => 'DMARC psd must be y, n, or u.'];
        }

        $fo = $parsed->tag('fo');
        if ($fo !== null && !preg_match('/^[01ds:]*$/', $fo)) {
            $errors[] = ['code' => 'INVALID_FO', 'message' => 'DMARC fo contains invalid characters.'];
        }

        $ri = $parsed->tag('ri');
        if ($ri !== null && (!ctype_digit($ri) || (int) $ri < 0)) {
            $errors[] = ['code' => 'INVALID_RI', 'message' => 'DMARC ri must be a non-negative integer.'];
        }

        return new DmarcValidationResult(
            parsed: $parsed,
            valid: $errors === [],
            errors: $errors,
            warnings: $warnings,
        );
    }
}
