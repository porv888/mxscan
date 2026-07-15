<?php

namespace App\Domain\EmailSecurity\Checks\Mx;

use App\Domain\EmailSecurity\Checks\Mx\Compatibility\MxLegacyPayloadAdapter;
use App\Domain\EmailSecurity\Contracts\SecurityCheckInterface;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\CheckExecutionResultDTO;
use App\Domain\EmailSecurity\DTO\CheckResultDTO;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;
use App\Domain\EmailSecurity\Support\ScanArtifactKeys;

final class MxCheck implements SecurityCheckInterface
{
    public function __construct(
        private MxAnalysisService $analysisService,
        private MxLegacyPayloadAdapter $legacyAdapter,
    ) {
    }

    public function key(): string
    {
        return 'mx';
    }

    public function run(CheckContextDTO $context, ?DnsCollectionResultDTO $dns): CheckExecutionResultDTO
    {
        $native = $this->analysisService->analyze($context);
        $legacyPayload = $this->legacyAdapter->toResultJsonMx($native);

        return new CheckExecutionResultDTO(
            result: new CheckResultDTO(
                key: 'mx',
                status: $native->state,
                data: $legacyPayload,
                messages: $native->messageSummaries(),
            ),
            artifacts: [
                ScanArtifactKeys::NATIVE_MX_RESULT => $native,
                ScanArtifactKeys::MX_DNS_COMPAT => $this->legacyAdapter->toDnsRecordCompat($native),
            ],
        );
    }
}
