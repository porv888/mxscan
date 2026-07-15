<?php

namespace App\Domain\EmailSecurity\Checks\Certificates;

use App\Domain\EmailSecurity\Checks\Certificates\Compatibility\CertificateLegacyPayloadAdapter;
use App\Domain\EmailSecurity\Contracts\SecurityCheckInterface;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\DTO\CheckExecutionResultDTO;
use App\Domain\EmailSecurity\DTO\CheckResultDTO;
use App\Domain\EmailSecurity\DTO\DnsCollectionResultDTO;
use App\Domain\EmailSecurity\Support\ScanArtifactKeys;

final class CertificateCheck implements SecurityCheckInterface
{
    public function __construct(
        private CertificateAnalysisService $analysisService,
        private CertificateLegacyPayloadAdapter $legacyAdapter,
    ) {
    }

    public function key(): string
    {
        return 'certificates';
    }

    public function run(CheckContextDTO $context, ?DnsCollectionResultDTO $dns): CheckExecutionResultDTO
    {
        unset($dns);

        $native = $this->analysisService->analyze($context);
        $legacyPayload = $this->legacyAdapter->toResultJsonCertificates($native);

        return new CheckExecutionResultDTO(
            result: new CheckResultDTO(
                key: 'certificates',
                status: $native->state,
                data: $legacyPayload,
                messages: $native->messageSummaries(),
            ),
            artifacts: [
                ScanArtifactKeys::NATIVE_CERTIFICATE_RESULT => $native,
            ],
        );
    }
}
