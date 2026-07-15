<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts;

use App\Domain\EmailSecurity\Checks\MtaSts\Evidence\MtaStsEvidenceBuilder;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;

final class MtaStsAnalysisService
{
    public function __construct(
        private MtaStsEvidenceBuilder $evidenceBuilder,
    ) {
    }

    public function analyze(CheckContextDTO $context, ?DnsCollectionResultDTO $dns): MtaStsNativeResult
    {
        return $this->evidenceBuilder->build($context, $dns);
    }
}
