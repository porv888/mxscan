<?php

namespace App\Domain\EmailSecurity\Checks\Bimi\Contracts;

interface BimiTrustStoreInterface
{
    /**
     * @param list<string> $pemCertificates
     * @return array{trusted: bool, errors: list<string>, warnings: list<string>}
     */
    public function verifyChain(array $pemCertificates): array;
}
