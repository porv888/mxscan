<?php

namespace App\Domain\EmailSecurity\Checks\Certificates\DTO;

final class CertificateParsedFields
{
    /**
     * @param list<string> $sanDns
     * @param list<string> $sanIp
     */
    public function __construct(
        public readonly ?string $subject,
        public readonly ?string $issuer,
        public readonly ?string $serialFingerprint,
        public readonly ?string $sha256Fingerprint,
        public readonly array $sanDns,
        public readonly array $sanIp,
        public readonly ?string $commonName,
        public readonly ?string $validFrom,
        public readonly ?string $validTo,
        public readonly ?int $validFromTimestamp,
        public readonly ?int $validToTimestamp,
        public readonly ?int $daysUntilExpiry,
        public readonly ?string $keyAlgorithm,
        public readonly ?int $keyBits,
        public readonly ?string $keyCurve,
        public readonly ?string $signatureAlgorithm,
        public readonly int $chainLength,
        public readonly bool $selfSigned,
    ) {
    }
}
