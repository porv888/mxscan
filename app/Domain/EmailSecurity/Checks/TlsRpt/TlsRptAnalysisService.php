<?php

namespace App\Domain\EmailSecurity\Checks\TlsRpt;

use App\Domain\EmailSecurity\Checks\TlsRpt\Evidence\TlsRptEvidenceBuilder;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;

final class TlsRptAnalysisService
{
    public function __construct(
        private TlsRptEvidenceBuilder $evidenceBuilder,
    ) {
    }

    public function analyze(CheckContextDTO $context, ?DnsCollectionResultDTO $dns): TlsRptNativeResult
    {
        $expectedRua = $context->enabledServices['tls_rpt_expected_rua'] ?? null;

        return $this->evidenceBuilder->build(
            $context->domainName,
            $dns,
            is_string($expectedRua) ? $expectedRua : null,
        );
    }
}
