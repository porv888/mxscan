<?php

namespace App\Domain\EmailSecurity\Checks\Bimi;

final class BimiMarkCertificateParser
{
    /**
     * @return array{
     *     success: bool,
     *     certificates: list<array<string, mixed>>,
     *     errors: list<array{code: string, message: string}>
     * }
     */
    public function parsePemBundle(string $pem): array
    {
        $maxCertificates = (int) config('bimi.mark_certificate.max_certificates', 10);
        $matches = [];
        preg_match_all('/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s', $pem, $matches);

        $blocks = $matches[0] ?? [];
        if ($blocks === []) {
            return [
                'success' => false,
                'certificates' => [],
                'errors' => [[
                    'code' => 'NO_CERTIFICATES',
                    'message' => 'No PEM certificates were found.',
                ]],
            ];
        }

        if (count($blocks) > $maxCertificates) {
            return [
                'success' => false,
                'certificates' => [],
                'errors' => [[
                    'code' => 'TOO_MANY_CERTIFICATES',
                    'message' => 'PEM bundle exceeds maximum certificate count.',
                ]],
            ];
        }

        $certificates = [];
        foreach ($blocks as $index => $block) {
            $resource = openssl_x509_read($block);
            if ($resource === false) {
                return [
                    'success' => false,
                    'certificates' => [],
                    'errors' => [[
                        'code' => 'MALFORMED_CERTIFICATE',
                        'message' => 'Certificate at index ' . $index . ' could not be parsed.',
                    ]],
                ];
            }

            $parsed = openssl_x509_parse($resource);
            if (!is_array($parsed)) {
                return [
                    'success' => false,
                    'certificates' => [],
                    'errors' => [[
                        'code' => 'MALFORMED_CERTIFICATE',
                        'message' => 'Certificate metadata at index ' . $index . ' could not be parsed.',
                    ]],
                ];
            }

            $certificates[] = [
                'index' => $index,
                'pem' => $block,
                'subject' => $parsed['subject'] ?? [],
                'issuer' => $parsed['issuer'] ?? [],
                'valid_from' => isset($parsed['validFrom_time_t']) ? gmdate('c', (int) $parsed['validFrom_time_t']) : null,
                'valid_to' => isset($parsed['validTo_time_t']) ? gmdate('c', (int) $parsed['validTo_time_t']) : null,
                'extensions' => $parsed['extensions'] ?? [],
                'fingerprint_sha256' => openssl_x509_fingerprint($resource, 'sha256') ?: null,
                'parsed' => $parsed,
            ];
        }

        return [
            'success' => true,
            'certificates' => $certificates,
            'errors' => [],
        ];
    }

    /**
     * @param array<string, mixed> $certificate
     */
    public function classifyType(array $certificate): string
    {
        $extensions = $certificate['extensions'] ?? [];
        if (!is_array($extensions)) {
            return 'unknown';
        }

        $subjectAltName = strtolower((string) ($extensions['subjectAltName'] ?? ''));
        if (str_contains($subjectAltName, 'mark certificate')) {
            return 'vmc';
        }

        $extendedKeyUsage = strtolower((string) ($extensions['extendedKeyUsage'] ?? ''));
        if (str_contains($extendedKeyUsage, 'brand indicator for message identification')) {
            return 'vmc';
        }

        if (str_contains($subjectAltName, 'common mark certificate') || str_contains($extendedKeyUsage, 'common mark')) {
            return 'cmc';
        }

        return 'unknown';
    }
}
