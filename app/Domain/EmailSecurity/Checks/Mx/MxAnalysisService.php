<?php

namespace App\Domain\EmailSecurity\Checks\Mx;

use App\Domain\EmailSecurity\Checks\Mx\Evidence\MxEvidenceBuilder;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;

final class MxAnalysisService
{
    public function __construct(
        private MxEvidenceBuilder $evidenceBuilder,
    ) {
    }

    public function analyze(CheckContextDTO $context): MxNativeResult
    {
        return $this->evidenceBuilder->build($context->domainName);
    }
}
