<?php

namespace App\Domain\EmailSecurity\Checks\Certificates\Compatibility;

use App\Domain\EmailSecurity\Checks\Certificates\CertificateNativeResult;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateStates;

final class CertificateLegacyPayloadAdapter
{
    public function __construct(
        private CertificateNativeAnalysisPayload $analysisPayload = new CertificateNativeAnalysisPayload(),
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toResultJsonCertificates(CertificateNativeResult $native): array
    {
        $analysis = $this->analysisPayload->fromNative($native);

        return [
            'status' => $this->legacyStatus($native),
            'analysis_status' => $analysis['analysis_status'],
            'risk_status' => $analysis['risk_status'],
            'ui_state' => $analysis['state'],
            'summary' => $analysis['summary'],
            'analysis' => $analysis,
        ];
    }

    private function legacyStatus(CertificateNativeResult $native): string
    {
        return match ($native->state) {
            CertificateStates::PASS => 'ok',
            CertificateStates::WARNING => 'warning',
            CertificateStates::FAIL => 'error',
            CertificateStates::NOT_CHECKED => 'not_checked',
            default => 'unknown',
        };
    }
}
