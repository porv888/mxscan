<?php

namespace App\Domain\EmailSecurity\Checks\Certificates;

use App\Domain\EmailSecurity\Checks\Certificates\Contracts\CertificateTrustStoreInterface;
use App\Domain\EmailSecurity\Checks\Certificates\DTO\CertificateParsedFields;
use App\Domain\EmailSecurity\Checks\Certificates\Infrastructure\SystemCertificateTrustStore;

class CertificateChainValidator
{
    public function __construct(
        private CertificateTrustStoreInterface $trustStore,
    ) {
    }

    /**
     * @param list<\OpenSSLCertificate|resource>|null $certificateChain
     * @return array{trusted: bool, status: string, diagnostics: list<string>}
     */
    public function validate(?array $certificateChain, string $hostname, ?CertificateParsedFields $parsed = null): array
    {
        if ($certificateChain === null || $certificateChain === []) {
            return [
                'trusted' => false,
                'status' => SystemCertificateTrustStore::STATUS_MALFORMED,
                'diagnostics' => ['No certificate chain was presented.'],
            ];
        }

        if ($parsed?->selfSigned === true) {
            return [
                'trusted' => false,
                'status' => SystemCertificateTrustStore::STATUS_SELF_SIGNED,
                'diagnostics' => ['Leaf certificate appears self-signed.'],
            ];
        }

        return $this->trustStore->verifyChain($certificateChain, $hostname);
    }
}
