<?php

namespace App\Domain\EmailSecurity\Checks\MtaSts;

use App\Domain\EmailSecurity\Checks\MtaSts\Compatibility\MtaStsLegacyPayloadAdapter;
use App\Domain\EmailSecurity\Contracts\SecurityCheckInterface;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\CheckExecutionResultDTO;
use App\Domain\EmailSecurity\DTO\CheckResultDTO;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;
use App\Domain\EmailSecurity\Support\ScanArtifactKeys;

final class MtaStsCheck implements SecurityCheckInterface
{
    public function __construct(
        private MtaStsAnalysisService $analysisService,
        private MtaStsLegacyPayloadAdapter $legacyAdapter,
    ) {
    }

    public function key(): string
    {
        return 'mtasts';
    }

    public function run(CheckContextDTO $context, ?DnsCollectionResultDTO $dns): CheckExecutionResultDTO
    {
        $native = $this->analysisService->analyze($context, $dns);
        $legacyPayload = $this->legacyAdapter->toResultJsonMtaSts($native);

        return new CheckExecutionResultDTO(
            result: new CheckResultDTO(
                key: 'mtasts',
                status: $native->state,
                data: $legacyPayload,
                messages: $native->messageSummaries(),
            ),
            artifacts: [
                ScanArtifactKeys::NATIVE_MTA_STS_RESULT => $native,
                ScanArtifactKeys::MTA_STS_DNS_COMPAT => $this->legacyAdapter->toDnsRecordCompat($native),
            ],
        );
    }
}
