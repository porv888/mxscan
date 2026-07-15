<?php

namespace App\Domain\EmailSecurity\Checks\Bimi;

use App\Domain\EmailSecurity\Checks\Bimi\Compatibility\BimiLegacyPayloadAdapter;
use App\Domain\EmailSecurity\Contracts\SecurityCheckInterface;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\CheckExecutionResultDTO;
use App\Domain\EmailSecurity\DTO\CheckResultDTO;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;
use App\Domain\EmailSecurity\Support\ScanArtifactKeys;

final class BimiCheck implements SecurityCheckInterface
{
    public function __construct(
        private BimiAnalysisService $analysisService,
        private BimiLegacyPayloadAdapter $legacyAdapter,
    ) {
    }

    public function key(): string
    {
        return 'bimi';
    }

    public function run(CheckContextDTO $context, ?DnsCollectionResultDTO $dns): CheckExecutionResultDTO
    {
        $native = $this->analysisService->analyze($context, $dns);
        $legacyPayload = $this->legacyAdapter->toResultJsonBimi($native);

        return new CheckExecutionResultDTO(
            result: new CheckResultDTO(
                key: 'bimi',
                status: $native->state,
                data: $legacyPayload,
                messages: $native->messageSummaries(),
            ),
            artifacts: [
                ScanArtifactKeys::NATIVE_BIMI_RESULT => $native,
                ScanArtifactKeys::BIMI_DNS_COMPAT => $this->legacyAdapter->toDnsRecordCompat($native),
            ],
        );
    }
}
