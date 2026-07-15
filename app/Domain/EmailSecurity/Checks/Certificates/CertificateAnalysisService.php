<?php

namespace App\Domain\EmailSecurity\Checks\Certificates;

use App\Domain\EmailSecurity\DTO\CheckContextDTO;

final class CertificateAnalysisService
{
    public function __construct(
        private CertificateEvidenceBuilder $evidenceBuilder,
    ) {
    }

    public function analyze(CheckContextDTO $context): CertificateNativeResult
    {
        return $this->evidenceBuilder->build($context);
    }
}
