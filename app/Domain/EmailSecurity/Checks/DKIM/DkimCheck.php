<?php

namespace App\Domain\EmailSecurity\Checks\DKIM;

use App\Domain\EmailSecurity\Checks\DKIM\Compatibility\DkimLegacyPayloadAdapter;
use App\Domain\EmailSecurity\Contracts\SecurityCheckInterface;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\CheckExecutionResultDTO;
use App\Domain\EmailSecurity\DTO\CheckResultDTO;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;
use App\Domain\EmailSecurity\Support\ScanArtifactKeys;

final class DkimCheck implements SecurityCheckInterface
{
    public function __construct(
        private DkimAnalysisService $analysisService,
        private DkimLegacyPayloadAdapter $legacyAdapter,
    ) {
    }

    public function key(): string
    {
        return 'dkim';
    }

    public function run(CheckContextDTO $context, ?DnsCollectionResultDTO $dns): CheckExecutionResultDTO
    {
        $native = $this->analysisService->analyze($context);
        $legacyPayload = $this->legacyAdapter->toResultJsonDkim($native);

        return new CheckExecutionResultDTO(
            result: new CheckResultDTO(
                key: 'dkim',
                status: $native->state,
                data: $legacyPayload,
                messages: $native->messageSummaries(),
            ),
            artifacts: [
                ScanArtifactKeys::NATIVE_DKIM_RESULT => $native,
                ScanArtifactKeys::DKIM_DNS_COMPAT => $this->legacyAdapter->toDnsRecordCompat($native),
            ],
        );
    }
}
