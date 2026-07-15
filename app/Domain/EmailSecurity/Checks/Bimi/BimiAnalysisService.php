<?php

namespace App\Domain\EmailSecurity\Checks\Bimi;

use App\Domain\EmailSecurity\Checks\DMARC\DmarcNativeResult;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;
use App\Domain\EmailSecurity\Support\ScanArtifactKeys;

final class BimiAnalysisService
{
    public function __construct(
        private BimiEvidenceBuilder $evidenceBuilder,
    ) {
    }

    public function analyze(CheckContextDTO $context, ?DnsCollectionResultDTO $dns): BimiNativeResult
    {
        $dmarcNative = $context->priorArtifacts[ScanArtifactKeys::NATIVE_DMARC_RESULT] ?? null;

        return $this->evidenceBuilder->build(
            $context,
            $dns,
            $dmarcNative instanceof DmarcNativeResult ? $dmarcNative : null,
        );
    }
}
