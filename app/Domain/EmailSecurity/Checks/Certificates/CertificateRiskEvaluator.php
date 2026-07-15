<?php

namespace App\Domain\EmailSecurity\Checks\Certificates;

final class CertificateRiskEvaluator
{
    /**
     * @return array{
     *     risk_status: string,
     *     state: string,
     *     analysis_status: string,
     *     has_expiring_certificates: bool,
     *     has_invalid_certificates: bool,
     *     has_unavailable_endpoints: bool,
     *     critical_endpoint_failures: int
     * }
     */
    public function evaluate(CertificateNativeResult $native): array
    {
        $expiring = (int) ($native->counts['expiring_soon'] ?? 0) > 0;
        $invalid = (int) ($native->counts['invalid'] ?? 0) > 0;
        $unavailable = (int) ($native->counts['unavailable'] ?? 0) > 0;
        $criticalFailures = 0;

        foreach ($native->endpoints as $endpoint) {
            if (($endpoint['endpoint_type'] ?? '') !== CertificateEndpoint::KIND_MTA_STS_HTTPS) {
                continue;
            }

            if (in_array($endpoint['ui_state'] ?? '', [
                CertificateStates::FAIL,
            ], true)) {
                $criticalFailures++;
            }
        }

        return [
            'risk_status' => $native->riskStatus,
            'state' => $native->state,
            'analysis_status' => $native->analysisStatus,
            'has_expiring_certificates' => $expiring,
            'has_invalid_certificates' => $invalid,
            'has_unavailable_endpoints' => $unavailable,
            'critical_endpoint_failures' => $criticalFailures,
        ];
    }
}
