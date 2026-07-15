<?php

namespace App\Domain\EmailSecurity\Checks\Certificates;

use App\Domain\EmailSecurity\Checks\Certificates\DTO\CertificateParsedFields;

final class CertificateSignatureInspector
{
    public const CLASSIFICATION_WEAK = 'weak';
    public const CLASSIFICATION_OBSOLETE = 'obsolete';
    public const CLASSIFICATION_MODERN = 'modern';
    public const CLASSIFICATION_UNKNOWN = 'unknown';
    public const CLASSIFICATION_UNAVAILABLE = 'unavailable';

    /**
     * @return array{classification: string, warnings: list<array{code: string, message: string}>}
     */
    public function inspect(?CertificateParsedFields $parsed): array
    {
        if ($parsed === null || $parsed->signatureAlgorithm === null || $parsed->signatureAlgorithm === '') {
            return [
                'classification' => self::CLASSIFICATION_UNAVAILABLE,
                'warnings' => [],
            ];
        }

        $algorithm = strtolower($parsed->signatureAlgorithm);

        if (str_contains($algorithm, 'md5')) {
            return [
                'classification' => self::CLASSIFICATION_WEAK,
                'warnings' => [[
                    'code' => 'SIGNATURE_MD5',
                    'message' => 'Certificate uses an MD5-based signature algorithm.',
                ]],
            ];
        }

        if (str_contains($algorithm, 'sha1') || str_contains($algorithm, 'sha-1')) {
            return [
                'classification' => self::CLASSIFICATION_OBSOLETE,
                'warnings' => [[
                    'code' => 'SIGNATURE_SHA1',
                    'message' => 'Certificate uses a SHA-1 signature algorithm.',
                ]],
            ];
        }

        if (preg_match('/sha(256|384|512)/', $algorithm) === 1) {
            return [
                'classification' => self::CLASSIFICATION_MODERN,
                'warnings' => [],
            ];
        }

        return [
            'classification' => self::CLASSIFICATION_UNKNOWN,
            'warnings' => [[
                'code' => 'SIGNATURE_ALGORITHM_UNRECOGNIZED',
                'message' => 'Certificate signature algorithm was not fully classified.',
            ]],
        ];
    }
}
