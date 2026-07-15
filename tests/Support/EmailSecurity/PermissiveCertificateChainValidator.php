<?php

namespace Tests\Support\EmailSecurity;

use App\Domain\EmailSecurity\Checks\Certificates\CertificateChainValidator;
use App\Domain\EmailSecurity\Checks\Certificates\DTO\CertificateParsedFields;
use App\Domain\EmailSecurity\Checks\Certificates\Infrastructure\SystemCertificateTrustStore;

final class PermissiveCertificateChainValidator extends CertificateChainValidator
{
    public function __construct()
    {
        parent::__construct(new \App\Domain\EmailSecurity\Checks\Certificates\Infrastructure\SystemCertificateTrustStore());
    }

    /**
     * @param list<\OpenSSLCertificate|resource>|null $certificateChain
     * @return array{trusted: bool, status: string, diagnostics: list<string>}
     */
    public function validate(?array $certificateChain, string $hostname, ?CertificateParsedFields $parsed = null): array
    {
        unset($certificateChain, $hostname);

        if ($parsed !== null) {
            return [
                'trusted' => true,
                'status' => SystemCertificateTrustStore::STATUS_TRUSTED,
                'diagnostics' => [],
            ];
        }

        return parent::validate($certificateChain, $hostname, $parsed);
    }
}
