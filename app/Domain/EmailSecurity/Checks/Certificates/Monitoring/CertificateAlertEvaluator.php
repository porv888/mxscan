<?php

namespace App\Domain\EmailSecurity\Checks\Certificates\Monitoring;

use App\Domain\EmailSecurity\Checks\Certificates\CertificateNativeResult;
use App\Domain\EmailSecurity\Checks\Certificates\DTO\CertificateEndpointEvaluation;

final class CertificateAlertEvaluator
{
    public const THRESHOLD_EXPIRED = 'expired';
    public const THRESHOLD_7_DAYS = '7_days';
    public const THRESHOLD_14_DAYS = '14_days';
    public const THRESHOLD_30_DAYS = '30_days';

    /**
     * @param list<string> $alreadySentDedupKeys
     * @return list<array{
     *     dedup_key: string,
     *     threshold: string,
     *     severity: string,
     *     endpoint_key: string,
     *     hostname: ?string,
     *     fingerprint: ?string,
     *     days_remaining: ?int,
     *     message: string
     * }>
     */
    public function evaluate(
        string $domain,
        CertificateNativeResult $native,
        array $alreadySentDedupKeys = [],
    ): array {
        $domain = strtolower(rtrim(trim($domain), '.'));
        $sent = array_fill_keys($alreadySentDedupKeys, true);
        $alerts = [];

        foreach ($native->endpoints as $endpoint) {
            if (!is_array($endpoint)) {
                continue;
            }

            $days = $endpoint['days_until_expiry'] ?? null;
            if (!is_int($days)) {
                continue;
            }

            $endpointKey = (string) ($endpoint['endpoint_key'] ?? '');
            $hostname = isset($endpoint['hostname']) ? (string) $endpoint['hostname'] : null;
            $fingerprint = isset($endpoint['fingerprint_sha256']) ? (string) $endpoint['fingerprint_sha256'] : null;
            $validTo = isset($endpoint['valid_to']) ? (string) $endpoint['valid_to'] : '';

            $thresholds = $this->thresholdsForDays($days);
            foreach ($thresholds as $threshold => $severity) {
                $dedupKey = $this->dedupKey($domain, $endpointKey, $fingerprint, $validTo, $threshold);
                if (isset($sent[$dedupKey])) {
                    continue;
                }

                $alerts[] = [
                    'dedup_key' => $dedupKey,
                    'threshold' => $threshold,
                    'severity' => $severity,
                    'endpoint_key' => $endpointKey,
                    'hostname' => $hostname,
                    'fingerprint' => $fingerprint,
                    'days_remaining' => $days,
                    'message' => $this->messageForThreshold($threshold, $endpointKey, $hostname, $days),
                ];
                $sent[$dedupKey] = true;
            }

            if ($endpoint['certificate_status'] === CertificateEndpointEvaluation::CERTIFICATE_INVALID
                && ($endpoint['hostname_match'] ?? true) === false) {
                $threshold = 'hostname_mismatch';
                $dedupKey = $this->dedupKey($domain, $endpointKey, $fingerprint, $validTo, $threshold);
                if (!isset($sent[$dedupKey])) {
                    $alerts[] = [
                        'dedup_key' => $dedupKey,
                        'threshold' => $threshold,
                        'severity' => 'critical',
                        'endpoint_key' => $endpointKey,
                        'hostname' => $hostname,
                        'fingerprint' => $fingerprint,
                        'days_remaining' => $days,
                        'message' => 'Certificate hostname mismatch detected for ' . ($hostname ?? $endpointKey) . '.',
                    ];
                }
            }
        }

        return $alerts;
    }

    public function dedupKey(
        string $domain,
        string $endpointKey,
        ?string $fingerprint,
        string $validTo,
        string $threshold,
    ): string {
        return implode('|', [
            strtolower(rtrim(trim($domain), '.')),
            $endpointKey,
            $fingerprint ?? 'unknown',
            $validTo !== '' ? $validTo : 'unknown',
            $threshold,
        ]);
    }

    /**
     * @return array<string, string>
     */
    private function thresholdsForDays(int $days): array
    {
        if ($days < 0) {
            return [self::THRESHOLD_EXPIRED => 'critical'];
        }

        $thresholds = [];
        $warningDays = (int) config('email-security.certificates.expiry_warning_days', 30);
        $criticalDays = (int) config('email-security.certificates.expiry_critical_days', 14);
        $urgentDays = (int) config('email-security.certificates.expiry_urgent_days', 7);

        if ($days <= $warningDays) {
            $thresholds[self::THRESHOLD_30_DAYS] = 'low';
        }

        if ($days <= $criticalDays) {
            $thresholds[self::THRESHOLD_14_DAYS] = 'medium';
        }

        if ($days <= $urgentDays) {
            $thresholds[self::THRESHOLD_7_DAYS] = 'high';
        }

        return $thresholds;
    }

    private function messageForThreshold(string $threshold, string $endpointKey, ?string $hostname, int $days): string
    {
        $target = $hostname ?? $endpointKey;

        return match ($threshold) {
            self::THRESHOLD_EXPIRED => 'Certificate for ' . $target . ' has expired.',
            self::THRESHOLD_7_DAYS => 'Certificate for ' . $target . ' expires in ' . $days . ' days (7-day threshold).',
            self::THRESHOLD_14_DAYS => 'Certificate for ' . $target . ' expires in ' . $days . ' days (14-day threshold).',
            self::THRESHOLD_30_DAYS => 'Certificate for ' . $target . ' expires in ' . $days . ' days (30-day threshold).',
            default => 'Certificate alert for ' . $target . '.',
        };
    }
}
