<?php

namespace App\Domain\EmailSecurity\Checks\Certificates\Contracts;

use App\Domain\EmailSecurity\Checks\Certificates\CertificateEndpoint;
use App\Domain\EmailSecurity\Checks\Certificates\DTO\CertificateNormalizedEvidence;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;

interface CertificateEndpointEvidenceProviderInterface
{
    public function supports(CertificateEndpoint $endpoint): bool;

    public function provide(CheckContextDTO $context, CertificateEndpoint $endpoint): ?CertificateNormalizedEvidence;
}
