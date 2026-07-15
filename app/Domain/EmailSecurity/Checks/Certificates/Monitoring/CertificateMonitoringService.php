<?php

namespace App\Domain\EmailSecurity\Checks\Certificates\Monitoring;

use App\Domain\EmailSecurity\Checks\Certificates\CertificateNativeResult;
use App\Domain\EmailSecurity\Checks\Certificates\Compatibility\CertificateNativeAnalysisPayload;
use App\Domain\EmailSecurity\Checks\Certificates\Support\CertificateAnalysisReader;

final class CertificateMonitoringService
{
    public function __construct(
        private CertificateRenewalDetector $renewalDetector,
        private CertificateAlertEvaluator $alertEvaluator,
    ) {
    }

    /**
     * @param array<string, mixed>|null $previousCertificatesInfo
     * @param list<string> $alreadySentDedupKeys
     * @return array{
     *     renewal_changes: list<array<string, mixed>>,
     *     alerts: list<array<string, mixed>>,
     *     resolved_dedup_keys: list<string>
     * }
     */
    public function evaluateMonitoringDelta(
        string $domain,
        CertificateNativeResult $current,
        ?array $previousCertificatesInfo = null,
        array $alreadySentDedupKeys = [],
    ): array {
        $previousAnalysis = CertificateAnalysisReader::analysis($previousCertificatesInfo);
        $previousEndpoints = is_array($previousAnalysis['endpoints'] ?? null)
            ? $previousAnalysis['endpoints']
            : [];

        $renewalChanges = $this->renewalDetector->detectAll($previousEndpoints, $current->endpoints);
        $alerts = $this->alertEvaluator->evaluate($domain, $current, $alreadySentDedupKeys);

        $resolved = $this->resolveClearedAlerts($domain, $previousEndpoints, $current->endpoints, $alreadySentDedupKeys);

        return [
            'renewal_changes' => $renewalChanges,
            'alerts' => $alerts,
            'resolved_dedup_keys' => $resolved,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function monitoringSnapshot(CertificateNativeResult $native): array
    {
        $payload = (new CertificateNativeAnalysisPayload())->fromNative($native);

        return [
            'analysis_status' => $native->analysisStatus,
            'risk_status' => $native->riskStatus,
            'state' => $native->state,
            'summary' => $native->summary,
            'counts' => $native->counts,
            'earliest_expiry' => $native->earliestExpiry,
            'endpoints' => array_map(
                fn (array $endpoint) => [
                    'endpoint_key' => $endpoint['endpoint_key'] ?? null,
                    'endpoint_type' => $endpoint['endpoint_type'] ?? null,
                    'hostname' => $endpoint['hostname'] ?? null,
                    'fingerprint_sha256' => $endpoint['fingerprint_sha256'] ?? null,
                    'serial_fingerprint' => $endpoint['serial_fingerprint'] ?? null,
                    'valid_to' => $endpoint['valid_to'] ?? null,
                    'days_until_expiry' => $endpoint['days_until_expiry'] ?? null,
                    'certificate_status' => $endpoint['certificate_status'] ?? null,
                    'ui_state' => $endpoint['ui_state'] ?? null,
                ],
                $native->endpoints,
            ),
            'analysis' => $payload,
        ];
    }

    /**
     * @param list<array<string, mixed>> $previousEndpoints
     * @param list<array<string, mixed>> $currentEndpoints
     * @param list<string> $alreadySentDedupKeys
     * @return list<string>
     */
    private function resolveClearedAlerts(
        string $domain,
        array $previousEndpoints,
        array $currentEndpoints,
        array $alreadySentDedupKeys,
    ): array {
        $resolved = [];
        $currentByKey = [];

        foreach ($currentEndpoints as $endpoint) {
            if (!is_array($endpoint)) {
                continue;
            }

            $key = (string) ($endpoint['endpoint_key'] ?? '');
            if ($key !== '') {
                $currentByKey[$key] = $endpoint;
            }
        }

        foreach ($previousEndpoints as $previous) {
            if (!is_array($previous)) {
                continue;
            }

            $endpointKey = (string) ($previous['endpoint_key'] ?? '');
            $current = $currentByKey[$endpointKey] ?? null;
            if (!is_array($current)) {
                continue;
            }

            $previousDays = $previous['days_until_expiry'] ?? null;
            $currentDays = $current['days_until_expiry'] ?? null;
            if (!is_int($previousDays) || !is_int($currentDays)) {
                continue;
            }

            if ($previousDays <= 30 && $currentDays > 30) {
                foreach ($alreadySentDedupKeys as $sentKey) {
                    if (str_contains($sentKey, $endpointKey)) {
                        $resolved[] = $sentKey;
                    }
                }
            }

            if ($previousDays < 0 && $currentDays >= 0) {
                $fingerprint = (string) ($current['fingerprint_sha256'] ?? 'unknown');
                $validTo = (string) ($current['valid_to'] ?? 'unknown');
                $resolved[] = $this->alertEvaluator->dedupKey(
                    $domain,
                    $endpointKey,
                    $fingerprint,
                    $validTo,
                    CertificateAlertEvaluator::THRESHOLD_EXPIRED,
                );
            }
        }

        return array_values(array_unique($resolved));
    }
}
