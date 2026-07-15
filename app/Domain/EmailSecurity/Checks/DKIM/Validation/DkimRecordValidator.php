<?php

namespace App\Domain\EmailSecurity\Checks\DKIM\Validation;

use App\Domain\EmailSecurity\Checks\DKIM\Inspection\DkimPublicKeyInspector;
use App\Domain\EmailSecurity\Checks\DKIM\Parsing\DkimParsedRecord;

final class DkimRecordValidator
{
    public function __construct(
        private DkimPublicKeyInspector $keyInspector,
    ) {
    }

    public function validate(DkimParsedRecord $parsed): DkimValidationResult
    {
        $errors = $parsed->parseErrors;
        $warnings = [];

        if ($parsed->duplicateTags !== []) {
            $errors[] = ['code' => 'DUPLICATE_TAGS', 'message' => 'Duplicate DKIM tags found in record.'];
        }

        $version = $parsed->tag('v');
        if ($version !== null && strcasecmp($version, 'DKIM1') !== 0) {
            $errors[] = ['code' => 'INVALID_VERSION', 'message' => 'DKIM version must be DKIM1 when present.'];
        }

        if ($parsed->tag('p') === null) {
            $errors[] = ['code' => 'MISSING_PUBLIC_KEY', 'message' => 'Public key tag p= is required.'];
        }

        $keyType = strtolower($parsed->tag('k') ?? DkimPublicKeyInspector::TYPE_RSA);
        $publicKey = $parsed->tag('p') ?? '';
        $keyInfo = $this->keyInspector->inspect($keyType, $publicKey);

        if ($keyInfo['revoked']) {
            return new DkimValidationResult(
                parsed: $parsed,
                recordStatus: 'revoked',
                errors: [['code' => 'REVOKED_KEY', 'message' => 'The DKIM public key has been revoked (empty p=).']],
                keyInfo: $keyInfo,
            );
        }

        if ($keyInfo['error'] === 'INVALID_BASE64') {
            $errors[] = ['code' => 'INVALID_BASE64', 'message' => 'Public key contains invalid Base64.'];
        } elseif ($keyInfo['error'] === 'MALFORMED_PUBLIC_KEY') {
            $errors[] = ['code' => 'MALFORMED_PUBLIC_KEY', 'message' => 'Public key material is malformed.'];
        } elseif ($keyInfo['error'] === 'RSA_TOO_WEAK') {
            $errors[] = ['code' => 'RSA_TOO_WEAK', 'message' => 'RSA key is below 1024 bits.'];
        } elseif ($keyInfo['error'] === 'UNSUPPORTED_KEY_TYPE') {
            return new DkimValidationResult(
                parsed: $parsed,
                recordStatus: 'unsupported',
                errors: [['code' => 'UNSUPPORTED_KEY_TYPE', 'message' => 'DKIM key type is not supported for full evaluation.']],
                keyInfo: $keyInfo,
            );
        } elseif ($keyInfo['error'] === 'MALFORMED_ED25519_KEY') {
            $errors[] = ['code' => 'MALFORMED_ED25519_KEY', 'message' => 'Ed25519 key has invalid encoded form.'];
        }

        $hashAlg = $parsed->tag('h');
        if ($hashAlg !== null && $hashAlg !== '') {
            $algorithms = array_map('trim', explode(':', strtolower($hashAlg)));
            $algorithms = array_filter($algorithms);
            if ($algorithms !== [] && !in_array('sha256', $algorithms, true)) {
                $errors[] = ['code' => 'SHA1_ONLY', 'message' => 'DKIM record restricts hashing to SHA-1 only.'];
            }
        }

        $serviceType = $parsed->tag('s');
        $supportsEmail = true;
        if ($serviceType !== null && $serviceType !== '' && $serviceType !== '*') {
            $services = array_map('trim', explode(':', strtolower($serviceType)));
            $supportsEmail = in_array('email', $services, true) || in_array('*', $services, true);
            if (!$supportsEmail) {
                $errors[] = ['code' => 'NON_EMAIL_SERVICE', 'message' => 'DKIM key does not apply to email service.'];
            }
        }

        $flags = $parsed->tag('t') ?? '';
        $testingMode = str_contains(strtolower($flags), 'y');
        if ($testingMode) {
            $warnings[] = ['code' => 'TESTING_MODE', 'message' => 'DKIM key is in testing mode (t=y).'];
        }

        if ($parsed->tag('g') !== null && $parsed->tag('g') !== '') {
            $warnings[] = ['code' => 'GRANULARITY_PRESENT', 'message' => 'Granularity tag g= is present; signer scope cannot be confirmed without a message i= value.'];
        }

        foreach ($parsed->unknownTags as $tag) {
            $warnings[] = ['code' => 'UNKNOWN_TAG', 'message' => "Unknown DKIM tag ignored: {$tag}."];
        }

        if ($errors !== []) {
            $status = ($keyInfo['error'] ?? null) === 'RSA_TOO_WEAK' ? 'invalid' : 'invalid';

            return new DkimValidationResult(
                parsed: $parsed,
                recordStatus: $status,
                errors: $errors,
                warnings: $warnings,
                keyInfo: $keyInfo,
                testingMode: $testingMode,
                supportsEmail: $supportsEmail,
            );
        }

        if (!$keyInfo['valid']) {
            return new DkimValidationResult(
                parsed: $parsed,
                recordStatus: 'unsupported',
                errors: [['code' => 'PARTIAL_EVALUATION', 'message' => 'Key could not be fully evaluated.']],
                warnings: $warnings,
                keyInfo: $keyInfo,
                testingMode: $testingMode,
                supportsEmail: $supportsEmail,
            );
        }

        if ($keyInfo['type'] === DkimPublicKeyInspector::TYPE_RSA
            && ($keyInfo['bits'] ?? 0) >= 1024
            && ($keyInfo['bits'] ?? 0) < 2048) {
            $warnings[] = ['code' => 'WEAK_RSA_KEY', 'message' => 'RSA key is valid but below 2048 bits.'];
        }

        return new DkimValidationResult(
            parsed: $parsed,
            recordStatus: 'valid',
            errors: [],
            warnings: $warnings,
            keyInfo: $keyInfo,
            testingMode: $testingMode,
            supportsEmail: $supportsEmail,
        );
    }

    public function validateMultiple(DkimParsedRecord $parsed): DkimValidationResult
    {
        return new DkimValidationResult(
            parsed: $parsed,
            recordStatus: 'ambiguous',
            errors: [['code' => 'MULTIPLE_DKIM_RECORDS', 'message' => 'Multiple DKIM key records found for the same selector.']],
        );
    }
}
