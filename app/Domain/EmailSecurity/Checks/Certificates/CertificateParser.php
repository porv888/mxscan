<?php

namespace App\Domain\EmailSecurity\Checks\Certificates;

use App\Domain\EmailSecurity\Checks\Certificates\Contracts\CertificateClockInterface;
use App\Domain\EmailSecurity\Checks\Certificates\DTO\CertificateParsedFields;

final class CertificateParser
{
    public function __construct(
        private CertificateClockInterface $clock,
    ) {
    }

    /**
     * @param array<string, mixed> $parsed
     * @param list<\OpenSSLCertificate|resource>|null $certificateChain
     */
    public function parse(array $parsed, ?array $certificateChain = null): CertificateParsedFields
    {
        $sanDns = [];
        $sanIp = [];
        $extensions = $parsed['extensions']['subjectAltName'] ?? '';

        if (is_string($extensions) && $extensions !== '') {
            foreach (explode(',', $extensions) as $entry) {
                $entry = trim($entry);
                if (str_starts_with($entry, 'DNS:')) {
                    $sanDns[] = CertificateEndpoint::normalizeHostname(substr($entry, 4));
                } elseif (str_starts_with($entry, 'IP Address:')) {
                    $sanIp[] = trim(substr($entry, 11));
                } elseif (str_starts_with($entry, 'IP:')) {
                    $sanIp[] = trim(substr($entry, 3));
                }
            }
        }

        $sanDns = array_values(array_unique(array_filter($sanDns)));
        $sanIp = array_values(array_unique(array_filter($sanIp)));

        $validFromTimestamp = isset($parsed['validFrom_time_t']) ? (int) $parsed['validFrom_time_t'] : null;
        $validToTimestamp = isset($parsed['validTo_time_t']) ? (int) $parsed['validTo_time_t'] : null;
        $now = $this->clock->now();
        $daysUntilExpiry = $validToTimestamp !== null
            ? (int) floor(($validToTimestamp - $now) / 86400)
            : null;

        $issuer = $this->formatDistinguishedName($parsed['issuer'] ?? []);
        $subject = $this->formatDistinguishedName($parsed['subject'] ?? []);
        $commonName = isset($parsed['subject']['CN']) ? (string) $parsed['subject']['CN'] : null;
        $serial = isset($parsed['serialNumber']) ? (string) $parsed['serialNumber'] : null;
        $signatureAlgorithm = isset($parsed['signatureTypeSN']) ? (string) $parsed['signatureTypeSN'] : null;

        $publicKey = $parsed['subjectPublicKeyInfo'] ?? [];
        $keyAlgorithm = null;
        $keyBits = null;
        $keyCurve = null;

        if (is_array($publicKey)) {
            $keyAlgorithm = isset($publicKey['algorithm']) ? strtolower((string) $publicKey['algorithm']) : null;
            if (isset($publicKey['bits'])) {
                $keyBits = (int) $publicKey['bits'];
            }
            if (isset($publicKey['ec_curve_name'])) {
                $keyCurve = (string) $publicKey['ec_curve_name'];
            }
        }

        $chainLength = $certificateChain !== null ? count($certificateChain) : 1;
        $selfSigned = $this->isSelfSigned($parsed);

        return new CertificateParsedFields(
            subject: $subject,
            issuer: $issuer,
            serialFingerprint: $this->normalizeSerial($serial),
            sha256Fingerprint: $this->resolveSha256Fingerprint($certificateChain),
            sanDns: $sanDns,
            sanIp: $sanIp,
            commonName: $commonName !== null ? CertificateEndpoint::normalizeHostname($commonName) : null,
            validFrom: $validFromTimestamp !== null ? gmdate('c', $validFromTimestamp) : null,
            validTo: $validToTimestamp !== null ? gmdate('c', $validToTimestamp) : null,
            validFromTimestamp: $validFromTimestamp,
            validToTimestamp: $validToTimestamp,
            daysUntilExpiry: $daysUntilExpiry,
            keyAlgorithm: $keyAlgorithm,
            keyBits: $keyBits,
            keyCurve: $keyCurve,
            signatureAlgorithm: $signatureAlgorithm,
            chainLength: $chainLength,
            selfSigned: $selfSigned,
        );
    }

    /**
     * @param list<\OpenSSLCertificate|resource>|null $certificateChain
     */
    private function resolveSha256Fingerprint(?array $certificateChain): ?string
    {
        if ($certificateChain === null || $certificateChain === []) {
            return null;
        }

        $fingerprint = openssl_x509_fingerprint($certificateChain[0], 'sha256');

        return is_string($fingerprint) && $fingerprint !== '' ? strtolower($fingerprint) : null;
    }

    private function normalizeSerial(?string $serial): ?string
    {
        if ($serial === null || $serial === '') {
            return null;
        }

        return preg_replace('/[^a-f0-9]/i', '', strtolower($serial)) ?: $serial;
    }

    /**
     * @param array<string, mixed>|string $dn
     */
    private function formatDistinguishedName(array|string $dn): ?string
    {
        if (!is_array($dn)) {
            return $dn !== '' ? (string) $dn : null;
        }

        if (isset($dn['CN']) && is_string($dn['CN']) && $dn['CN'] !== '') {
            return $dn['CN'];
        }

        if (isset($dn['O']) && is_string($dn['O']) && $dn['O'] !== '') {
            return $dn['O'];
        }

        return null;
    }

    /**
     * @param array<string, mixed> $parsed
     */
    private function isSelfSigned(array $parsed): bool
    {
        $issuer = $parsed['issuer'] ?? [];
        $subject = $parsed['subject'] ?? [];

        if (!is_array($issuer) || !is_array($subject)) {
            return false;
        }

        return json_encode($issuer) === json_encode($subject);
    }
}
