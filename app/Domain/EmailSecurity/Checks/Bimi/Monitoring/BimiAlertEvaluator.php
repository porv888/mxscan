<?php

namespace App\Domain\EmailSecurity\Checks\Bimi\Monitoring;

use App\Domain\EmailSecurity\Checks\Bimi\BimiNativeResult;

final class BimiAlertEvaluator
{
    public const THRESHOLD_LOGO_UNAVAILABLE = 'logo_unavailable';
    public const THRESHOLD_SVG_INVALID = 'svg_invalid';
    public const THRESHOLD_CERT_EXPIRED = 'cert_expired';
    public const THRESHOLD_CERT_EXPIRING = 'cert_expiring';
    public const THRESHOLD_DMARC_INELIGIBLE = 'dmarc_ineligible';
    public const THRESHOLD_INDICATOR_MISMATCH = 'indicator_mismatch';

    /**
     * @param list<string> $alreadySentDedupKeys
     * @return list<array<string, mixed>>
     */
    public function evaluate(
        string $domain,
        BimiNativeResult $native,
        array $alreadySentDedupKeys = [],
    ): array {
        $domain = strtolower(rtrim(trim($domain), '.'));
        $sent = array_fill_keys($alreadySentDedupKeys, true);
        $alerts = [];
        $selector = (string) ($native->selector['value'] ?? 'default');

        if (($native->indicator['status'] ?? '') === 'unavailable') {
            $alerts[] = $this->alert(
                $domain,
                $selector,
                self::THRESHOLD_LOGO_UNAVAILABLE,
                'critical',
                'BIMI logo is unavailable.',
                (string) ($native->indicator['sha256'] ?? 'unknown'),
                $sent,
            );
        }

        if (($native->indicator['status'] ?? '') === 'invalid') {
            $alerts[] = $this->alert(
                $domain,
                $selector,
                self::THRESHOLD_SVG_INVALID,
                'high',
                'BIMI SVG failed validation.',
                (string) ($native->indicator['sha256'] ?? 'unknown'),
                $sent,
            );
        }

        $daysUntilExpiry = $native->authorityEvidence['days_until_expiry'] ?? null;
        if (is_int($daysUntilExpiry) && $daysUntilExpiry < 0) {
            $alerts[] = $this->alert(
                $domain,
                $selector,
                self::THRESHOLD_CERT_EXPIRED,
                'critical',
                'BIMI Mark Certificate has expired.',
                (string) ($native->authorityEvidence['fingerprint_sha256'] ?? 'unknown'),
                $sent,
            );
        } elseif (is_int($daysUntilExpiry) && $daysUntilExpiry <= 30) {
            $alerts[] = $this->alert(
                $domain,
                $selector,
                self::THRESHOLD_CERT_EXPIRING,
                'high',
                'BIMI Mark Certificate is expiring soon.',
                (string) ($native->authorityEvidence['fingerprint_sha256'] ?? 'unknown'),
                $sent,
            );
        }

        if (($native->dmarcEligibility['core_eligible'] ?? false) === false) {
            $alerts[] = $this->alert(
                $domain,
                $selector,
                self::THRESHOLD_DMARC_INELIGIBLE,
                'high',
                'Domain is not DMARC-eligible for BIMI.',
                'dmarc',
                $sent,
            );
        }

        if (($native->indicatorComparison['identical'] ?? null) === false) {
            $alerts[] = $this->alert(
                $domain,
                $selector,
                self::THRESHOLD_INDICATOR_MISMATCH,
                'high',
                'Published BIMI logo does not match certificate indicator.',
                (string) ($native->indicator['sha256'] ?? 'unknown'),
                $sent,
            );
        }

        return $alerts;
    }

    public function dedupKey(
        string $domain,
        string $selector,
        string $resourceHash,
        string $threshold,
    ): string {
        return implode('|', [
            strtolower(rtrim(trim($domain), '.')),
            $selector,
            $threshold,
            $resourceHash,
        ]);
    }

    /**
     * @param array<string, bool> $sent
     * @return array<string, mixed>
     */
    private function alert(
        string $domain,
        string $selector,
        string $threshold,
        string $severity,
        string $message,
        string $resourceHash,
        array &$sent,
    ): array {
        $dedupKey = $this->dedupKey($domain, $selector, $resourceHash, $threshold);
        $sent[$dedupKey] = true;

        return [
            'dedup_key' => $dedupKey,
            'threshold' => $threshold,
            'severity' => $severity,
            'selector' => $selector,
            'resource_hash' => $resourceHash,
            'message' => $message,
        ];
    }
}
