<?php

namespace App\Domain\EmailSecurity\Checks\Bimi\Infrastructure;

use App\Domain\EmailSecurity\Checks\Bimi\Contracts\BimiTrustStoreInterface;

final class BimiSystemTrustStore implements BimiTrustStoreInterface
{
    /**
     * @param list<string> $pemCertificates
     * @return array{trusted: bool, errors: list<string>, warnings: list<string>}
     */
    public function verifyChain(array $pemCertificates): array
    {
        if ($pemCertificates === []) {
            return [
                'trusted' => false,
                'errors' => ['Certificate chain is empty.'],
                'warnings' => [],
            ];
        }

        $leafPem = $pemCertificates[0];
        $leaf = openssl_x509_read($leafPem);
        if ($leaf === false) {
            return [
                'trusted' => false,
                'errors' => ['Leaf certificate could not be parsed.'],
                'warnings' => [],
            ];
        }

        $parsed = openssl_x509_parse($leaf);
        if (!is_array($parsed)) {
            return [
                'trusted' => false,
                'errors' => ['Leaf certificate metadata could not be parsed.'],
                'warnings' => [],
            ];
        }

        if ($this->isSelfSigned($parsed)) {
            return [
                'trusted' => false,
                'errors' => ['Leaf certificate appears self-signed.'],
                'warnings' => [],
            ];
        }

        $caFile = $this->resolveCaBundlePath();
        if ($caFile === null) {
            return [
                'trusted' => false,
                'errors' => [],
                'warnings' => ['System trust store is unavailable; chain trust could not be verified.'],
            ];
        }

        $verified = openssl_x509_checkpurpose($leaf, X509_PURPOSE_ANY, [$caFile]);
        if ($verified === true) {
            return [
                'trusted' => true,
                'errors' => [],
                'warnings' => [],
            ];
        }

        if (count($pemCertificates) < 2) {
            return [
                'trusted' => false,
                'errors' => ['Certificate chain is incomplete.'],
                'warnings' => [],
            ];
        }

        return [
            'trusted' => false,
            'errors' => ['Certificate issuer is not trusted by the system store.'],
            'warnings' => [],
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

        ksort($issuer);
        ksort($subject);

        return json_encode($issuer) === json_encode($subject);
    }
}
