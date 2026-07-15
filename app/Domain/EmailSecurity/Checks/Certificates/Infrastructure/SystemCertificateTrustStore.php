<?php

namespace App\Domain\EmailSecurity\Checks\Certificates\Infrastructure;

use App\Domain\EmailSecurity\Checks\Certificates\Contracts\CertificateTrustStoreInterface;

final class SystemCertificateTrustStore implements CertificateTrustStoreInterface
{
    public const STATUS_TRUSTED = 'trusted';
    public const STATUS_UNTRUSTED_ISSUER = 'untrusted_issuer';
    public const STATUS_INCOMPLETE_CHAIN = 'incomplete_chain';
    public const STATUS_SELF_SIGNED = 'self_signed';
    public const STATUS_VALIDATION_UNAVAILABLE = 'validation_unavailable';
    public const STATUS_MALFORMED = 'malformed';

    /**
     * @param list<\OpenSSLCertificate|resource> $certificateChain
     * @return array{trusted: bool, status: string, diagnostics: list<string>}
     */
    public function verifyChain(array $certificateChain, string $hostname): array
    {
        unset($hostname);

        if ($certificateChain === []) {
            return [
                'trusted' => false,
                'status' => self::STATUS_MALFORMED,
                'diagnostics' => ['Certificate chain is empty.'],
            ];
        }

        $leaf = $certificateChain[0];
        $parsed = openssl_x509_parse($leaf);
        if (!is_array($parsed)) {
            return [
                'trusted' => false,
                'status' => self::STATUS_MALFORMED,
                'diagnostics' => ['Leaf certificate could not be parsed.'],
            ];
        }

        if ($this->isSelfSigned($parsed)) {
            return [
                'trusted' => false,
                'status' => self::STATUS_SELF_SIGNED,
                'diagnostics' => ['Leaf certificate appears self-signed.'],
            ];
        }

        $caFile = $this->resolveCaBundlePath();
        if ($caFile === null) {
            return [
                'trusted' => false,
                'status' => self::STATUS_VALIDATION_UNAVAILABLE,
                'diagnostics' => ['System trust store is unavailable.'],
            ];
        }

        $verified = openssl_x509_checkpurpose($leaf, X509_PURPOSE_SSL_SERVER, [$caFile]);
        if ($verified === true) {
            return [
                'trusted' => true,
                'status' => self::STATUS_TRUSTED,
                'diagnostics' => [],
            ];
        }

        if (count($certificateChain) < 2) {
            return [
                'trusted' => false,
                'status' => self::STATUS_INCOMPLETE_CHAIN,
                'diagnostics' => ['Certificate chain is incomplete.'],
            ];
        }

        return [
            'trusted' => false,
            'status' => self::STATUS_UNTRUSTED_ISSUER,
            'diagnostics' => ['Certificate issuer is not trusted by the system store.'],
        ];
    }

    private function resolveCaBundlePath(): ?string
    {
        $candidates = [
            '/etc/ssl/certs/ca-certificates.crt',
            '/etc/pki/tls/certs/ca-bundle.crt',
            '/etc/ssl/ca-bundle.pem',
            '/usr/local/etc/openssl/cert.pem',
        ];

        foreach ($candidates as $path) {
            if (is_readable($path)) {
                return $path;
            }
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

        return $this->distinguishedNameFingerprint($issuer) === $this->distinguishedNameFingerprint($subject);
    }

    /**
     * @param array<string, mixed> $dn
     */
    private function distinguishedNameFingerprint(array $dn): string
    {
        ksort($dn);

        return json_encode($dn, JSON_THROW_ON_ERROR);
    }
}
