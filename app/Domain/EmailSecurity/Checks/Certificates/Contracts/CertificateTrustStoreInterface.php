<?php

namespace App\Domain\EmailSecurity\Checks\Certificates\Contracts;

interface CertificateTrustStoreInterface
{
    /**
     * @param list<\OpenSSLCertificate|resource> $certificateChain
     * @return array{trusted: bool, status: string, diagnostics: list<string>}
     */
    public function verifyChain(array $certificateChain, string $hostname): array;
}
