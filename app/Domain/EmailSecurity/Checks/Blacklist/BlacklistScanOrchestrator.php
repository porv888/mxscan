<?php

namespace App\Domain\EmailSecurity\Checks\Blacklist;

use App\Domain\EmailSecurity\Checks\Blacklist\Compatibility\BlacklistLegacyPayloadAdapter;
use App\Domain\EmailSecurity\Checks\Blacklist\Persistence\BlacklistResultWriter;
use App\Domain\EmailSecurity\Checks\Mx\MxAnalysisService;
use App\Domain\EmailSecurity\Checks\Mx\MxNativeResult;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Domain\EmailSecurity\Support\ScanArtifactKeys;
use App\Models\Scan;

final class BlacklistScanOrchestrator
{
    public function __construct(
        private MxAnalysisService $mxAnalysisService,
        private BlacklistAnalysisService $blacklistAnalysisService,
        private BlacklistLegacyPayloadAdapter $legacyAdapter,
        private BlacklistResultWriter $resultWriter,
    ) {
    }

    /**
     * @return array{native: BlacklistNativeResult, payload: array<string, mixed>, mx_native: MxNativeResult}
     */
    public function run(Scan $scan, CheckContextDTO $context): array
    {
        $mxNative = $context->priorArtifacts[ScanArtifactKeys::NATIVE_MX_RESULT] ?? null;
        if (!$mxNative instanceof MxNativeResult) {
            $mxNative = $this->mxAnalysisService->analyze($context);
        }

        $contextWithMx = $context->withPriorArtifacts(array_merge(
            $context->priorArtifacts,
            [ScanArtifactKeys::NATIVE_MX_RESULT => $mxNative],
        ));

        $native = $this->blacklistAnalysisService->analyze($contextWithMx);
        $this->resultWriter->write($scan->id, $native);
        $payload = $this->legacyAdapter->toResultJsonBlacklist($native);

        return [
            'native' => $native,
            'payload' => $payload,
            'mx_native' => $mxNative,
        ];
    }
}
