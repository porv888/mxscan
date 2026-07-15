<?php

namespace App\Domain\EmailSecurity\Checks\Certificates\Contracts;

use App\Domain\EmailSecurity\Checks\Certificates\CertificateEndpoint;
use App\Domain\EmailSecurity\Checks\Certificates\DTO\CertificateNormalizedEvidence;

interface CertificateProbeInterface
{
    public function supports(CertificateEndpoint $endpoint): bool;

    public function probe(CertificateEndpoint $endpoint): CertificateNormalizedEvidence;
}
