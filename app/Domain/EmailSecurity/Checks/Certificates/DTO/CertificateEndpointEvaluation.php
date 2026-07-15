<?php

namespace App\Domain\EmailSecurity\Checks\Certificates\DTO;

use App\Domain\EmailSecurity\Checks\Certificates\CertificateEndpoint;

final class CertificateEndpointEvaluation
{
    public const PROTOCOL_EVALUATED = 'evaluated';
    public const PROTOCOL_PARTIALLY_EVALUATED = 'partially_evaluated';
    public const PROTOCOL_UNAVAILABLE = 'unavailable';
    public const PROTOCOL_INVALID = 'invalid';
    public const PROTOCOL_NOT_APPLICABLE = 'not_applicable';

    public const CERTIFICATE_VALID = 'valid';
    public const CERTIFICATE_WARNING = 'warning';
    public const CERTIFICATE_INVALID = 'invalid';
    public const CERTIFICATE_EXPIRED = 'expired';
    public const CERTIFICATE_NOT_YET_VALID = 'not_yet_valid';
    public const CERTIFICATE_UNKNOWN = 'unknown';
    public const CERTIFICATE_UNAVAILABLE = 'unavailable';

    public const UI_PASS = 'pass';
    public const UI_WARNING = 'warning';
    public const UI_FAIL = 'fail';
    public const UI_UNKNOWN = 'unknown';
    public const UI_NOT_CHECKED = 'not_checked';

    /**
     * @param list<array{code: string, message: string}> $errors
     * @param list<array{code: string, message: string}> $warnings
     */
    public function __construct(
        public readonly CertificateEndpoint $endpoint,
        public readonly string $protocolStatus,
        public readonly string $certificateStatus,
        public readonly string $uiState,
        public readonly ?bool $hostnameMatch,
        public readonly ?string $matchedIdentity,
        public readonly ?string $hostnameMismatchReason,
        public readonly bool $trusted,
        public readonly ?string $trustStatus,
        public readonly ?CertificateParsedFields $parsed,
        public readonly string $evidenceSource,
        public readonly bool $reused,
        public readonly ?string $validityClassification,
        public readonly ?string $keyStrengthClassification,
        public readonly ?string $signatureClassification,
        public readonly ?string $failureCategory,
        public readonly array $errors,
        public readonly array $warnings,
    ) {
    }
}
