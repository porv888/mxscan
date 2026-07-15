<?php

namespace App\Domain\EmailSecurity\Checks\Bimi\Monitoring;

use App\Domain\EmailSecurity\Checks\Bimi\BimiAnalysisReader;
use App\Domain\EmailSecurity\Checks\Bimi\BimiNativeResult;
use App\Domain\EmailSecurity\Checks\Bimi\Compatibility\BimiNativeAnalysisPayload;

final class BimiMonitoringService
{
    public function __construct(
        private BimiChangeDetector $changeDetector,
        private BimiAlertEvaluator $alertEvaluator,
    ) {
    }

    /**
     * @param array<string, mixed>|null $previousBimiInfo
     * @param list<string> $alreadySentDedupKeys
     * @return array{
     *     changes: list<array<string, mixed>>,
     *     alerts: list<array<string, mixed>>,
     *     resolved_dedup_keys: list<string>
     * }
     */
    public function evaluateMonitoringDelta(
        string $domain,
        BimiNativeResult $current,
        ?array $previousBimiInfo = null,
        array $alreadySentDedupKeys = [],
    ): array {
        $previousAnalysis = BimiAnalysisReader::analysis($previousBimiInfo);
        $currentPayload = (new BimiNativeAnalysisPayload())->fromNative($current);

        $changes = $this->changeDetector->detectAll($previousAnalysis, $currentPayload);
        $alerts = $this->alertEvaluator->evaluate($domain, $current, $alreadySentDedupKeys);
        $resolved = $this->resolveClearedAlerts($domain, $previousAnalysis, $currentPayload, $alreadySentDedupKeys);

        return [
            'changes' => $changes,
            'alerts' => $alerts,
            'resolved_dedup_keys' => $resolved,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function monitoringSnapshot(BimiNativeResult $native): array
    {
        $payload = (new BimiNativeAnalysisPayload())->fromNative($native);

        return [
            'protocol_status' => $native->protocolStatus,
            'readiness_status' => $native->readinessStatus,
            'evidence_status' => $native->evidenceStatus,
            'risk_status' => $native->riskStatus,
            'state' => $native->state,
            'summary' => $native->summary,
            'selector' => $native->selector['value'] ?? null,
            'indicator_hash' => $native->indicator['sha256'] ?? null,
            'certificate_fingerprint' => $native->authorityEvidence['fingerprint_sha256'] ?? null,
            'certificate_expires_at' => $native->authorityEvidence['valid_to'] ?? null,
            'analysis' => $payload,
        ];
    }

    /**
     * @param array<string, mixed>|null $previousAnalysis
     * @param array<string, mixed> $currentAnalysis
     * @param list<string> $alreadySentDedupKeys
     * @return list<string>
     */
    private function resolveClearedAlerts(
        string $domain,
        ?array $previousAnalysis,
        array $currentAnalysis,
        array $alreadySentDedupKeys,
    ): array {
        if (!is_array($previousAnalysis)) {
            return [];
        }

        $resolved = [];
        $selector = (string) ($currentAnalysis['selector']['value'] ?? 'default');

        $previousDays = $previousAnalysis['authority_evidence']['days_until_expiry'] ?? null;
        $currentDays = $currentAnalysis['authority_evidence']['days_until_expiry'] ?? null;

        if (is_int($previousDays) && is_int($currentDays) && $previousDays <= 30 && $currentDays > 30) {
            foreach ($alreadySentDedupKeys as $sentKey) {
                if (str_contains($sentKey, BimiAlertEvaluator::THRESHOLD_CERT_EXPIRING)) {
                    $resolved[] = $sentKey;
                }
            }
        }

        if (is_int($previousDays) && is_int($currentDays) && $previousDays < 0 && $currentDays >= 0) {
            $fingerprint = (string) ($currentAnalysis['authority_evidence']['fingerprint_sha256'] ?? 'unknown');
            $resolved[] = $this->alertEvaluator->dedupKey(
                $domain,
                $selector,
                $fingerprint,
                BimiAlertEvaluator::THRESHOLD_CERT_EXPIRED,
            );
        }

        if (($previousAnalysis['indicator']['status'] ?? '') === 'unavailable'
            && ($currentAnalysis['indicator']['status'] ?? '') === 'valid') {
            $hash = (string) ($currentAnalysis['indicator']['sha256'] ?? 'unknown');
            $resolved[] = $this->alertEvaluator->dedupKey(
                $domain,
                $selector,
                $hash,
                BimiAlertEvaluator::THRESHOLD_LOGO_UNAVAILABLE,
            );
        }

        return array_values(array_unique($resolved));
    }
}
