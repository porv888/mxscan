<?php

namespace App\Domain\EmailSecurity\Checks\TlsRpt;

use App\Domain\EmailSecurity\Checks\TlsRpt\Compatibility\TlsRptLegacyPayloadAdapter;
use App\Domain\EmailSecurity\Contracts\SecurityCheckInterface;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\CheckExecutionResultDTO;
use App\Domain\EmailSecurity\DTO\CheckResultDTO;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;
use App\Domain\EmailSecurity\Support\ScanArtifactKeys;

final class TlsRptCheck implements SecurityCheckInterface
{
    public function __construct(
        private TlsRptAnalysisService $analysisService,
        private TlsRptLegacyPayloadAdapter $legacyAdapter,
    ) {
    }

    public function key(): string
    {
        return 'tlsrpt';
    }

    public function run(CheckContextDTO $context, ?DnsCollectionResultDTO $dns): CheckExecutionResultDTO
    {
        $native = $this->analysisService->analyze($context, $dns);
        $legacyPayload = $this->legacyAdapter->toResultJsonTlsRpt($native);

        return new CheckExecutionResultDTO(
            result: new CheckResultDTO(
                key: 'tlsrpt',
                status: $native->state,
                data: $legacyPayload,
                messages: $native->messageSummaries(),
            ),
            artifacts: [
                ScanArtifactKeys::NATIVE_TLS_RPT_RESULT => $native,
                ScanArtifactKeys::TLS_RPT_DNS_COMPAT => $this->legacyAdapter->toDnsRecordCompat($native),
            ],
        );
    }
}
