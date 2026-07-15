<?php

namespace App\Domain\EmailSecurity\Checks\Certificates;

use App\Domain\EmailSecurity\Checks\Certificates\DTO\CertificateParsedFields;

final class CertificateKeyInspector
{
    public const CLASSIFICATION_WEAK = 'weak';
    public const CLASSIFICATION_ACCEPTABLE = 'acceptable';
    public const CLASSIFICATION_STRONG = 'strong';
    public const CLASSIFICATION_UNKNOWN = 'unknown';
    public const CLASSIFICATION_UNAVAILABLE = 'unavailable';

    /**
     * @return array{classification: string, warnings: list<array{code: string, message: string}>}
     */
    public function inspect(?CertificateParsedFields $parsed): array
    {
        if ($parsed === null) {
            return [
                'classification' => self::CLASSIFICATION_UNAVAILABLE,
                'warnings' => [],
            ];
        }

        $algorithm = strtolower((string) ($parsed->keyAlgorithm ?? ''));

        if ($algorithm === '') {
            return [
                'classification' => self::CLASSIFICATION_UNKNOWN,
                'warnings' => [[
                    'code' => 'KEY_ALGORITHM_UNKNOWN',
                    'message' => 'Certificate public-key algorithm could not be determined.',
                ]],
            ];
        }

        if (str_contains($algorithm, 'rsa')) {
            return $this->inspectRsa($parsed->keyBits);
        }

        if (str_contains($algorithm, 'ec') || str_contains($algorithm, 'id-ecpublickey')) {
            return $this->inspectEc($parsed->keyCurve, $parsed->keyBits);
        }

        if (str_contains($algorithm, 'ed25519') || str_contains($algorithm, 'ed448') || str_contains($algorithm, 'eddsa')) {
            return [
                'classification' => self::CLASSIFICATION_STRONG,
                'warnings' => [],
            ];
        }

        return [
            'classification' => self::CLASSIFICATION_UNKNOWN,
            'warnings' => [[
                'code' => 'KEY_ALGORITHM_UNRECOGNIZED',
                'message' => 'Certificate uses an unrecognized public-key algorithm.',
            ]],
        ];
    }

    /**
     * @return array{classification: string, warnings: list<array{code: string, message: string}>}
     */
    private function inspectRsa(?int $bits): array
    {
        if ($bits === null) {
            return [
                'classification' => self::CLASSIFICATION_UNKNOWN,
                'warnings' => [[
                    'code' => 'RSA_KEY_SIZE_UNKNOWN',
                    'message' => 'RSA key size could not be determined.',
                ]],
            ];
        }

        if ($bits < 2048) {
            return [
                'classification' => self::CLASSIFICATION_WEAK,
                'warnings' => [[
                    'code' => 'RSA_KEY_WEAK',
                    'message' => 'RSA key size is below 2048 bits.',
                ]],
            ];
        }

        if ($bits === 2048) {
            return [
                'classification' => self::CLASSIFICATION_ACCEPTABLE,
                'warnings' => [],
            ];
        }

        if (in_array($bits, [3072, 4096], true)) {
            return [
                'classification' => self::CLASSIFICATION_STRONG,
                'warnings' => [],
            ];
        }

        return [
            'classification' => self::CLASSIFICATION_UNKNOWN,
            'warnings' => [[
                'code' => 'RSA_KEY_SIZE_UNUSUAL',
                'message' => 'RSA key size is unusual and was not fully classified.',
            ]],
        ];
    }

    /**
     * @return array{classification: string, warnings: list<array{code: string, message: string}>}
     */
    private function inspectEc(?string $curve, ?int $bits): array
    {
        $curveName = strtolower((string) ($curve ?? ''));

        if (in_array($curveName, ['prime256v1', 'secp256r1', 'nistp256'], true)) {
            return ['classification' => self::CLASSIFICATION_STRONG, 'warnings' => []];
        }

        if (in_array($curveName, ['secp384r1', 'nistp384'], true)) {
            return ['classification' => self::CLASSIFICATION_STRONG, 'warnings' => []];
        }

        if (in_array($curveName, ['secp521r1', 'nistp521'], true)) {
            return ['classification' => self::CLASSIFICATION_STRONG, 'warnings' => []];
        }

        if ($bits !== null && in_array($bits, [256, 384, 521], true)) {
            return ['classification' => self::CLASSIFICATION_STRONG, 'warnings' => []];
        }

        return [
            'classification' => self::CLASSIFICATION_UNKNOWN,
            'warnings' => [[
                'code' => 'EC_CURVE_UNRECOGNIZED',
                'message' => 'Elliptic-curve parameters were not fully recognized.',
            ]],
        ];
    }
}
