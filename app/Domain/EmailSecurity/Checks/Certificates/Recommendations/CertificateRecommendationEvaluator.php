<?php

namespace App\Domain\EmailSecurity\Checks\Certificates\Recommendations;

use App\Domain\EmailSecurity\Checks\Certificates\CertificateEndpoint;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateVerificationState;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateKeyInspector;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateNativeResult;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateSignatureInspector;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateStates;
use App\Domain\EmailSecurity\Checks\Certificates\CertificateValidityEvaluator;
use App\Domain\EmailSecurity\Checks\Certificates\DTO\CertificateEndpointEvaluation;
use App\Domain\EmailSecurity\Checks\Certificates\Infrastructure\SystemCertificateTrustStore;
use App\Domain\EmailSecurity\Checks\Certificates\Support\CertificateAnalysisReader;
use App\Domain\EmailSecurity\Reporting\ScanReportStatusMapper;

final class CertificateRecommendationEvaluator
{
    /**
     * @param array<string, mixed>|null $certificatesInfo
     * @param array<string, mixed>|null $certificatesCard
     * @return list<array{semantic_key: string, legacy_key: string, severity: string, title: string, body: string, suggested: ?string, card_state: string}>
     */
    public function evaluate(
        string $domain,
        ?array $certificatesInfo,
        ?array $certificatesCard = null,
        ?CertificateNativeResult $native = null,
    ): array {
        $analysis = CertificateAnalysisReader::analysis($certificatesInfo)
            ?? ($native !== null ? (new \App\Domain\EmailSecurity\Checks\Certificates\Compatibility\CertificateNativeAnalysisPayload())->fromNative($native) : null);
        $cardState = $certificatesCard['state'] ?? CertificateAnalysisReader::state($certificatesInfo) ?? ScanReportStatusMapper::UNKNOWN;
        $endpoints = is_array($analysis['endpoints'] ?? null)
            ? $analysis['endpoints']
            : ($native?->endpoints ?? []);

        if ($cardState === CertificateStates::NOT_CHECKED || $endpoints === []) {
            return [];
        }

        $items = [];
        $seen = [];

        foreach ($endpoints as $endpoint) {
            if (!is_array($endpoint)) {
                continue;
            }

            $hostname = (string) ($endpoint['hostname'] ?? 'unknown');
            $endpointLabel = $this->endpointLabel($endpoint);

            $validity = (string) ($endpoint['validity_classification'] ?? '');
            $days = $endpoint['days_until_expiry'] ?? null;
            $certificateStatus = (string) ($endpoint['certificate_status'] ?? '');
            $trustStatus = (string) ($endpoint['trust_status'] ?? '');
            $failureCategory = (string) ($endpoint['failure_category'] ?? '');

            if ($certificateStatus === CertificateEndpointEvaluation::CERTIFICATE_EXPIRED
                || $validity === CertificateValidityEvaluator::STATUS_EXPIRED) {
                $items[] = $this->once($seen, 'replace_expired_certificate', $this->item(
                    'replace_expired_certificate',
                    'Replace expired certificate',
                    'The certificate for ' . $endpointLabel . ' has expired.',
                    'critical',
                    ScanReportStatusMapper::FAIL,
                ));
                continue;
            }

            if ($certificateStatus === CertificateEndpointEvaluation::CERTIFICATE_NOT_YET_VALID
                || $validity === CertificateValidityEvaluator::STATUS_NOT_YET_VALID) {
                $items[] = $this->once($seen, 'fix_not_yet_valid_certificate', $this->item(
                    'fix_not_yet_valid_certificate',
                    'Fix not-yet-valid certificate',
                    'The certificate for ' . $endpointLabel . ' is not yet valid.',
                    'high',
                    ScanReportStatusMapper::FAIL,
                ));
                continue;
            }

            if ($this->isEvaluatedEndpoint($endpoint)
                && ($endpoint['verification_state'] ?? '') === CertificateVerificationState::HOSTNAME_MISMATCH) {
                $items[] = $this->once($seen, 'fix_certificate_hostname_mismatch', $this->item(
                    'fix_certificate_hostname_mismatch',
                    'Fix certificate hostname mismatch',
                    $this->hostnameMismatchBody($endpoint),
                    'high',
                    ScanReportStatusMapper::FAIL,
                ));
            }

            if ($trustStatus === SystemCertificateTrustStore::STATUS_SELF_SIGNED) {
                $items[] = $this->once($seen, 'replace_self_signed_certificate', $this->item(
                    'replace_self_signed_certificate',
                    'Replace self-signed certificate',
                    'The certificate for ' . $endpointLabel . ' is self-signed.',
                    'high',
                    ScanReportStatusMapper::FAIL,
                ));
            } elseif ($trustStatus === SystemCertificateTrustStore::STATUS_INCOMPLETE_CHAIN) {
                $items[] = $this->once($seen, 'fix_incomplete_certificate_chain', $this->item(
                    'fix_incomplete_certificate_chain',
                    'Fix incomplete certificate chain',
                    'The certificate chain for ' . $endpointLabel . ' is incomplete.',
                    'high',
                    ScanReportStatusMapper::FAIL,
                ));
            } elseif ($trustStatus === SystemCertificateTrustStore::STATUS_UNTRUSTED_ISSUER
                || (($endpoint['trusted'] ?? true) === false && ($endpoint['fingerprint_sha256'] ?? null) !== null)) {
                $items[] = $this->once($seen, 'fix_untrusted_certificate_chain', $this->item(
                    'fix_untrusted_certificate_chain',
                    'Fix untrusted certificate chain',
                    'The certificate for ' . $endpointLabel . ' is not trusted by the system CA store.',
                    'high',
                    ScanReportStatusMapper::FAIL,
                ));
            }

            if (is_int($days) && $days >= 0) {
                $severity = match (true) {
                    $days <= (int) config('email-security.certificates.expiry_urgent_days', 7) => 'high',
                    $days <= (int) config('email-security.certificates.expiry_critical_days', 14) => 'medium',
                    $days <= (int) config('email-security.certificates.expiry_warning_days', 30) => 'low',
                    default => null,
                };

                if ($severity !== null) {
                    $items[] = $this->once($seen, 'renew_expiring_certificate', $this->item(
                        'renew_expiring_certificate',
                        'Renew expiring certificate',
                        'The certificate for ' . $endpointLabel . ' expires in ' . $days . ' days.',
                        $severity,
                        ScanReportStatusMapper::WARNING,
                    ));
                }
            }

            if (($endpoint['key_strength_classification'] ?? '') === CertificateKeyInspector::CLASSIFICATION_WEAK) {
                $items[] = $this->once($seen, 'upgrade_weak_certificate_key', $this->item(
                    'upgrade_weak_certificate_key',
                    'Upgrade weak certificate key',
                    'The certificate for ' . $endpointLabel . ' uses a weak public key.',
                    'medium',
                    ScanReportStatusMapper::WARNING,
                ));
            }

            $signatureClassification = (string) ($endpoint['signature_classification'] ?? '');
            if (in_array($signatureClassification, [
                CertificateSignatureInspector::CLASSIFICATION_WEAK,
                CertificateSignatureInspector::CLASSIFICATION_OBSOLETE,
            ], true)) {
                $items[] = $this->once($seen, 'replace_weak_certificate_signature', $this->item(
                    'replace_weak_certificate_signature',
                    'Replace weak certificate signature',
                    'The certificate for ' . $endpointLabel . ' uses an obsolete signature algorithm.',
                    'medium',
                    ScanReportStatusMapper::WARNING,
                ));
            }

            if ($failureCategory === 'starttls_not_advertised'
                || in_array('STARTTLS_NOT_ADVERTISED', array_column($endpoint['warnings'] ?? [], 'code'), true)) {
                $items[] = $this->once($seen, 'enable_starttls_for_mx', $this->item(
                    'enable_starttls_for_mx',
                    'Enable STARTTLS on MX host',
                    'MX host ' . $hostname . ' did not advertise STARTTLS.',
                    'medium',
                    ScanReportStatusMapper::WARNING,
                ));
            }

            if ($certificateStatus === CertificateEndpointEvaluation::CERTIFICATE_UNAVAILABLE
                && in_array($failureCategory, [
                    'connection_timeout',
                    'connection_refused',
                    'tls_handshake_failure',
                    'dns_failure',
                    'unsupported_endpoint',
                ], true)) {
                $items[] = $this->once($seen, 'investigate_certificate_probe_failure', $this->item(
                    'investigate_certificate_probe_failure',
                    'Investigate certificate probe failure',
                    'MXScan could not complete certificate evaluation for ' . $endpointLabel . '.',
                    'low',
                    ScanReportStatusMapper::UNKNOWN,
                ));
            }
        }

        if ($cardState === CertificateStates::WARNING
            && !isset($seen['review_certificate_renewal_automation'])
            && (int) ($analysis['counts']['expiring_soon'] ?? 0) > 0) {
            $items[] = $this->once($seen, 'review_certificate_renewal_automation', $this->item(
                'review_certificate_renewal_automation',
                'Review certificate renewal automation',
                'One or more certificates are approaching expiry. Review automated renewal coverage for ' . strtolower(rtrim(trim($domain), '.')) . '.',
                'low',
                ScanReportStatusMapper::WARNING,
            ));
        }

        return $items;
    }

    /**
     * @param array<string, mixed> $endpoint
     */
    private function isEvaluatedEndpoint(array $endpoint): bool
    {
        return in_array($endpoint['protocol_status'] ?? '', [
            CertificateEndpointEvaluation::PROTOCOL_EVALUATED,
            CertificateEndpointEvaluation::PROTOCOL_PARTIALLY_EVALUATED,
        ], true)
            && ($endpoint['certificate_status'] ?? '') !== CertificateEndpointEvaluation::CERTIFICATE_UNAVAILABLE;
    }

    /**
     * @param array<string, mixed> $endpoint
     */
    private function hostnameMismatchBody(array $endpoint): string
    {
        $hostname = (string) ($endpoint['hostname'] ?? 'unknown');
        $presented = (string) ($endpoint['matched_identity']
            ?? $endpoint['subject']
            ?? $endpoint['common_name']
            ?? '');
        $sans = is_array($endpoint['san_dns'] ?? null) ? $endpoint['san_dns'] : [];
        $sanList = $sans !== [] ? implode(', ', $sans) : null;

        if ($presented === '' && $sanList !== null) {
            $presented = $sanList;
        }

        if ($presented === '') {
            return 'The certificate presented for ' . $hostname . ' does not include a matching hostname identity.';
        }

        return 'The certificate for ' . $hostname . ' presents identity "' . $presented . '" which does not match the requested hostname.';
    }

    /**
     * @param array<string, mixed> $endpoint
     */
    private function endpointLabel(array $endpoint): string
    {
        $type = (string) ($endpoint['endpoint_type'] ?? 'endpoint');
        $hostname = (string) ($endpoint['hostname'] ?? 'unknown');

        return match ($type) {
            CertificateEndpoint::KIND_PRIMARY_HTTPS => 'primary HTTPS (' . $hostname . ')',
            CertificateEndpoint::KIND_MTA_STS_HTTPS => 'MTA-STS HTTPS (' . $hostname . ')',
            CertificateEndpoint::KIND_SMTP_MX => 'SMTP MX (' . $hostname . ')',
            default => $hostname,
        };
    }

    /**
     * @param array<string, true> $seen
     * @return array{semantic_key: string, legacy_key: string, severity: string, title: string, body: string, suggested: ?string, card_state: string}
     */
    private function once(array &$seen, string $semanticKey, array $item): array
    {
        $seen[$semanticKey] = true;

        return $item;
    }

    /**
     * @return array{semantic_key: string, legacy_key: string, severity: string, title: string, body: string, suggested: ?string, card_state: string}
     */
    private function item(
        string $semanticKey,
        string $title,
        string $body,
        string $severity,
        string $cardState,
        ?string $suggested = null,
    ): array {
        return [
            'semantic_key' => $semanticKey,
            'legacy_key' => 'certificates',
            'severity' => $severity,
            'title' => $title,
            'body' => $body,
            'suggested' => $suggested,
            'card_state' => $cardState,
        ];
    }
}
